#!/usr/bin/env python3
import re
import sys
import asyncio
import socket
import logging
import requests
from pathlib import Path
from typing import Set, Tuple, Optional

from ip2geotools.databases.noncommercial import DbIpCity

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

OUTPUT_ALL = Path("config.txt")
OUTPUT_RU = Path("config_ru.txt")
OUTPUT_OTHER = Path("config_other.txt")

PROTO_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss|ssr|hysteria2)://\S+")
TCP_TIMEOUT = 3
MAX_CONCURRENT_CHECKS = 100

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def get_host_port(uri: str) -> Optional[Tuple[str, int]]:
    """Извлекает хост и порт из ссылки."""
    try:
        if "@" not in uri:
            return None
        address_part = uri.rsplit("@", 1)[1].split("?")[0].split("#")[0]
        if "]" in address_part:  # IPv6
            host = address_part.split("]")[0] + "]"
            port_str = address_part.split("]")[-1].lstrip(":")
            return host, (int(port_str) if port_str else 443)
        if ":" in address_part:
            host, port = address_part.rsplit(":", 1)
            return host, int(port)
        return address_part, 443
    except Exception:
        return None

async def check_tcp(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    """Асинхронная проверка TCP-соединения."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

def get_country_sync(host: str) -> Optional[str]:
    """Синхронно определяет код страны по хосту."""
    try:
        ip = socket.gethostbyname(host)
        # Используем бесплатную базу IP2Location LITE
        response = DbIpCity.get(ip, api_key="free")
        return response.country
    except Exception as e:
        logger.warning(f"Не удалось определить страну для {host}: {e}")
        return None

async def get_country(host: str) -> Optional[str]:
    """Асинхронная обёртка для get_country_sync."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_country_sync, host)

async def fetch_and_filter():
    """Основная логика сборщика."""
    logger.info("Загрузка конфигов из источников...")
    raw_links: Set[str] = set()

    for url in URLS:
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            links = PROTO_PATTERN.findall(resp.text)
            raw_links.update(links)
            logger.info(f"Загружено {len(links)} из {url}")
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")

    if not raw_links:
        logger.error("Конфиги не найдены!")
        return

    logger.info(f"После дедупликации: {len(raw_links)} уникальных ссылок. Проверка TCP...")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    tasks_map = []

    for link in raw_links:
        hp = get_host_port(link)
        if hp:
            task = asyncio.create_task(check_tcp(hp[0], hp[1], semaphore))
            tasks_map.append((link, task))

    if not tasks_map:
        logger.error("Нет ссылок для проверки.")
        return

    await asyncio.gather(*(task for _, task in tasks_map))

    alive_links = [link for link, task in tasks_map if task.result()]
    logger.info(f"Живых после TCP: {len(alive_links)}")

    if not alive_links:
        logger.error("Нет живых конфигов.")
        return

    # Сохраняем полный список
    OUTPUT_ALL.write_text("\n".join(sorted(alive_links)), encoding="utf-8")
    logger.info(f"Сохранён полный список в {OUTPUT_ALL}")

    # Определяем страны и разделяем
    ru_links = []
    other_links = []
    host_cache = {}  # кэш резолвинга страны по хосту

    for link in alive_links:
        hp = get_host_port(link)
        if not hp:
            other_links.append(link)  # не смогли извлечь хост – в "другие"
            continue
        host = hp[0]

        if host not in host_cache:
            country = await get_country(host)
            host_cache[host] = country
        else:
            country = host_cache[host]

        if country == "RU":
            ru_links.append(link)
        else:
            other_links.append(link)

    OUTPUT_RU.write_text("\n".join(sorted(ru_links)), encoding="utf-8")
    OUTPUT_OTHER.write_text("\n".join(sorted(other_links)), encoding="utf-8")
    logger.info(f"Российских: {len(ru_links)}, остальных: {len(other_links)}. Файлы сохранены.")

if __name__ == "__main__":
    try:
        asyncio.run(fetch_and_filter())
    except KeyboardInterrupt:
        sys.exit(0)
