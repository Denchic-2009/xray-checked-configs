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
[span_3](start_span)PROTO_PATTERN = re.compile(r"(vless|vmess|trojan|ss|ssr|hysteria2)://\S+")[span_3](end_span)
[span_4](start_span)TCP_TIMEOUT = 3[span_4](end_span)
MAX_CONCURRENT_CHECKS = 100 # Лимит одновременных соединений

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def get_host_port(uri: str) -> Optional[Tuple[str, int]]:
    [span_5](start_span)"""Извлекает хост и порт, учитывая IPv6 и параметры запроса[span_5](end_span)."""
    try:
        # [span_6](start_span)Отсекаем часть с протоколом и userinfo (до символа @)[span_6](end_span)
        if "@" not in uri: return None
        address_part = uri.rsplit("@", 1)[1].split("?")[0].split("#")[0]

        # Обработка IPv6: [2001:db8::1]:443
        if "]" in address_part:
            host = address_part.split("]")[0] + "]"
            port_str = address_part.split("]")[-1].lstrip(":")
            return host, (int(port_str) if port_str else 443)
        
        # Обработка IPv4: host:port
        if ":" in address_part:
            host, port = address_part.rsplit(":", 1)
            return host, int(port)
        
        [span_7](start_span)return address_part, 443[span_7](end_span)
    except Exception:
        return None

async def check_tcp(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    [span_8](start_span)"""Проверяет доступность порта по TCP[span_8](end_span)."""
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
    [span_9](start_span)"""Основной цикл: загрузка, дедупликация и проверка[span_9](end_span)."""
    logger.info("Fetching raw configs from sources...")
    raw_links: Set[str] = set()
    
    for url in URLS:
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            [span_10](start_span)found = PROTO_PATTERN.findall(resp.text)[span_10](end_span)
            # findall вернет список кортежей из-за групп в regex, берем полные ссылки
            links = re.findall(r"(?:vless|vmess|trojan|ss|ssr|hysteria2)://\S+", resp.text)
            raw_links.update(links)
            [span_11](start_span)logger.info(f"Fetched {len(links)} from {url}")[span_11](end_span)
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")

    if not raw_links:
        [span_12](start_span)logger.error("No configs found!")[span_12](end_span)
        return

    logger.info(f"Deduplicated to {len(raw_links)} unique links. Checking connectivity...")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    tasks = []
    link_map = [] # Список пар (ссылка, задача)

    for link in raw_links:
        [span_13](start_span)hp = get_host_port(link)[span_13](end_span)
        if hp:
            task = asyncio.create_task(check_tcp(hp[0], hp[1], semaphore))
            tasks.append(task)
            link_map.append((link, task))

    # Ждем завершения всех проверок
    await asyncio.gather(*tasks)
    
    alive = [link for link, task in link_map if task.result()]
    
    if alive:
        [span_14](start_span)OUTPUT_FILE.write_text("\n".join(sorted(alive)), encoding="utf-8")[span_14](end_span)
        logger.info(f"Successfully saved {len(alive)} alive configs to {OUTPUT_FILE}")
    else:
        logger.error("No alive configs found after TCP check.")

if __name__ == "__main__":
    try:
        asyncio.run(fetch_and_filter())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(0)
