#!/usr/bin/env python3
import re
import sys
import asyncio
import logging
import requests
from pathlib import Path
from typing import Set, Tuple, Optional

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

OUTPUT_FILE = Path("config.txt")
# Используем (?:...) чтобы findall возвращал всю ссылку целиком
PROTO_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss|ssr|hysteria2)://\S+")
TCP_TIMEOUT = 3
MAX_CONCURRENT_CHECKS = 100 

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def get_host_port(uri: str) -> Optional[Tuple[str, int]]:
    [span_1](start_span)"""Извлекает хост и порт для проверки доступности [cite: 2-4]."""
    try:
        if "@" not in uri: return None
        # [cite_start]Берем часть после @ и убираем параметры/фрагменты[span_1](end_span)
        address_part = uri.rsplit("@", 1)[1].split("?")[0].split("#")[0]

        [span_2](start_span)if "]" in address_part: # Поддержка IPv6[span_2](end_span)
            host = address_part.split("]")[0] + "]"
            port_str = address_part.split("]")[-1].lstrip(":")
            return host, (int(port_str) if port_str else 443)
        
        [span_3](start_span)if ":" in address_part: # IPv4:порт[span_3](end_span)
            host, port = address_part.rsplit(":", 1)
            return host, int(port)
        
        return address_part, 443
    except Exception:
        return None

async def check_tcp(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    [span_4](start_span)"""Асинхронная проверка TCP-соединения [cite: 6-7]."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

async def fetch_and_filter():
    [cite_start]"""Основная логика сборщика [cite: 9-11]."""
    logger.info("Fetching raw configs from sources...")
    raw_links: Set[str] = set()
    
    for url in URLS:
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            links = PROTO_PATTERN.findall(resp.text)
            raw_links.update(links)
            logger.info(f"Fetched {len(links)} from {url}")
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")

    if not raw_links:
        logger.error("No configs found!")
        return

    logger.info(f"Deduplicated to {len(raw_links)} unique links. Checking connectivity...")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    link_map = [] 

    for link in raw_links:
        hp = get_host_port(link)
        if hp:
            task = asyncio.create_task(check_tcp(hp[0], hp[1], semaphore))
            link_map.append((link, task))

    if not link_map:
        return

    # [cite_start]Ждем завершения всех проверок[span_4](end_span)
    await asyncio.gather(*(task for _, task in link_map))
    
    alive = [link for link, task in link_map if task.result()]
    
    if alive:
        OUTPUT_FILE.write_text("\n".join(sorted(alive)), encoding="utf-8")
        logger.info(f"Successfully saved {len(alive)} alive configs to {OUTPUT_FILE}")
    else:
        logger.error("No alive configs found after TCP check.")

if __name__ == "__main__":
    try:
        asyncio.run(fetch_and_filter())
    except KeyboardInterrupt:
        sys.exit(0)
