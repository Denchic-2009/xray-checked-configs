#!/usr/bin/env python3
import re
import sys
import asyncio
import logging
import socket
from pathlib import Path
from typing import Set, Tuple, Optional

import aiohttp
import geoip2.database

# --- Конфигурация ---
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/RU.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://wlrus.lol/confs/selected.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
]

# Файлы для сохранения (как ожидается в ваших логах GitHub Actions)
OUTPUT_ALL = Path("config.txt")
OUTPUT_RU = Path("config_ru.txt")
OUTPUT_OTHER = Path("config_other.txt")

# Путь к локальной базе GeoIP (нужно положить этот файл в репозиторий)
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

PROTO_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss|ssr|hysteria2)://\S+")
TCP_TIMEOUT = 3
MAX_CONCURRENT_CHECKS = 200 # Увеличили, так как теперь все работает быстрее

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def get_host_port(uri: str) -> Optional[Tuple[str, int]]:
    """Извлекает хост и порт из конфигурации."""
    try:
        if "@" not in uri: return None
        address_part = uri.rsplit("@", 1)[1].split("?")[0].split("#")[0]

        if "]" in address_part: # IPv6
            host = address_part.split("]")[0] + "]"
            port_str = address_part.split("]")[-1].lstrip(":")
            return host, (int(port_str) if port_str else 443)
        
        if ":" in address_part: # IPv4 или домен
            host, port = address_part.rsplit(":", 1)
            return host, int(port)
        
        return address_part, 443
    except Exception:
        return None

async def resolve_ip(host: str) -> Optional[str]:
    """Асинхронно резолвит домен в IP (нужно для GeoIP)."""
    # Очищаем IPv6 от скобок для резолва
    clean_host = host.strip("[]")
    
    # Проверяем, может это уже IP-адрес
    try:
        socket.inet_aton(clean_host)
        return clean_host
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, clean_host)
        return clean_host
    except socket.error:
        pass

    # Если домен, резолвим
    loop = asyncio.get_running_loop()
    try:
        info = await loop.getaddrinfo(clean_host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        return info[0][4][0] # Берем первый найденный IP
    except Exception:
        return None

async def check_node(link: str, semaphore: asyncio.Semaphore, geo_reader) -> dict:
    """Проверяет TCP доступность и определяет страну."""
    hp = get_host_port(link)
    if not hp:
        return {"link": link, "alive": False, "country": None}

    host, port = hp
    alive = False
    
    # Проверка TCP-соединения
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            alive = True
        except Exception:
            pass # Соединение не удалось

    country_code = None
    # Если узел жив и база GeoIP загружена, проверяем страну
    if alive and geo_reader:
        ip = await resolve_ip(host)
        if ip:
            try:
                response = geo_reader.country(ip)
                country_code = response.country.iso_code
            except Exception:
                pass # IP не найден в базе

    return {"link": link, "alive": alive, "country": country_code}

async def fetch_url(session: aiohttp.ClientSession, url: str) -> Set[str]:
    """Асинхронное скачивание файла по URL."""
    try:
        async with session.get(url, timeout=15) as resp:
            resp.raise_for_status()
            text = await resp.text()
            links = PROTO_PATTERN.findall(text)
            logger.info(f"Fetched {len(links)} links from {url}")
            return set(links)
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return set()

async def main():
    logger.info("Starting async fetch of raw configs...")
    raw_links: Set[str] = set()
    
    # Асинхронно скачиваем все URL
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in URLS]
        results = await asyncio.gather(*tasks)
        for links in results:
            raw_links.update(links)

    if not raw_links:
        logger.error("No configs found!")
        return

    logger.info(f"Deduplicated to {len(raw_links)} unique links. Checking connectivity & GeoIP...")
    
    # Инициализация базы GeoIP
    geo_reader = None
    if Path(GEOIP_DB_PATH).exists():
        geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info(f"GeoIP database loaded successfully.")
    else:
        logger.warning(f"GeoIP DB '{GEOIP_DB_PATH}' not found! All configs will be saved as 'other'.")

    # Параллельная проверка всех ссылок
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    check_tasks = [check_node(link, semaphore, geo_reader) for link in raw_links]
    
    results = await asyncio.gather(*check_tasks)

    # Закрываем базу, если она была открыта
    if geo_reader:
        geo_reader.close()

    # Сортировка результатов
    alive_all = []
    alive_ru = []
    alive_other = []

    for res in results:
        if res["alive"]:
            alive_all.append(res["link"])
            if res["country"] == "RU":
                alive_ru.append(res["link"])
            else:
                alive_other.append(res["link"])

    # Сохранение файлов
    if alive_all:
        OUTPUT_ALL.write_text("\n".join(sorted(alive_all)), encoding="utf-8")
        OUTPUT_RU.write_text("\n".join(sorted(alive_ru)), encoding="utf-8")
        OUTPUT_OTHER.write_text("\n".join(sorted(alive_other)), encoding="utf-8")
        
        logger.info(f"Successfully saved:")
        logger.info(f"  - {len(alive_all)} total alive -> {OUTPUT_ALL}")
        logger.info(f"  - {len(alive_ru)} RU configs -> {OUTPUT_RU}")
        logger.info(f"  - {len(alive_other)} OTHER configs -> {OUTPUT_OTHER}")
    else:
        logger.error("No alive configs found after TCP check.")

if __name__ == "__main__":
    # Устанавливаем политику событий для Windows, если скрипт будет запускаться локально
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(0)
