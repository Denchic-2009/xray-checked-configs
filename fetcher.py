#!/usr/bin/env python3
"""
Xray VPN Config Aggregator & Health Checker
Fetches VLESS configs from multiple GitHub sources, deduplicates,
verifies TCP connectivity, and exports to config.txt.
"""

import re
import sys
import time
import signal
import logging
import asyncio
from urllib.parse import urlparse
from pathlib import Path
from typing import Set, Tuple, Optional

import requests
import schedule

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/RU.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://wlrus.lol/confs/selected.txt",  # Might be unreachable from some regions
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
]

OUTPUT_FILE = Path("config.txt")
REQUEST_TIMEOUT = 15  # seconds for fetching source lists
TCP_TIMEOUT = 3       # seconds for connectivity check
MAX_CONCURRENT_CHECKS = 50

# Protocols we are interested in
PROTO_PATTERN = re.compile(r"(vless|vmess|trojan|ss|ssr|hysteria2)://\S+")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# Helper: extract host and port from a URL
# ------------------------------------------------------------
def get_host_port(uri: str) -> Optional[Tuple[str, int]]:
    """Return (host, port) or None if parsing fails."""
    try:
        # VLESS links may contain '@' for userinfo, handle that
        if "@" in uri:
            # Split off the userinfo part
            _, rest = uri.split("@", 1)
            # In case there is a fragment after '#'
            if "#" in rest:
                rest = rest.split("#", 1)[0]
            host_port = rest.split("?")[0]  # remove query params
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                return host, int(port_str)
            else:
                return host_port, 443  # default TLS port
    except Exception:
        pass
    return None

# ------------------------------------------------------------
# Fetch raw text from a URL
# ------------------------------------------------------------
def fetch_configs(url: str) -> Set[str]:
    """Download text, extract all protocol links, return a set of URLs."""
    configs: Set[str] = set()
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        # Find all protocol URLs in the whole text
        found = PROTO_PATTERN.findall(resp.text)
        configs.update(found)
        logger.info("Fetched %d configs from %s", len(found), url)
    except requests.RequestException as e:
        logger.warning("Failed to fetch %s: %s", url, e)
    return configs

# ------------------------------------------------------------
# Asynchronous TCP connectivity check
# ------------------------------------------------------------
async def check_tcp(host: str, port: int) -> bool:
    """Try to open a TCP connection to host:port."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_TIMEOUT,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def filter_alive(configs: Set[str]) -> Set[str]:
    """Return only configs whose host:port is reachable via TCP."""
    alive: Set[str] = set()
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    async def check_one(cfg: str):
        hp = get_host_port(cfg)
        if not hp:
            return
        async with sem:
            if await check_tcp(*hp):
                alive.add(cfg)

    tasks = [asyncio.create_task(check_one(c)) for c in configs]
    await asyncio.gather(*tasks)
    logger.info("Alive configs after TCP check: %d/%d", len(alive), len(configs))
    return alive

# ------------------------------------------------------------
# Main update logic
# ------------------------------------------------------------
def update_configs():
    """Download, deduplicate, check, and write configs."""
    logger.info("Starting config update...")

    all_configs: Set[str] = set()
    for url in URLS:
        all_configs.update(fetch_configs(url))

    if not all_configs:
        logger.error("No configs fetched from any source. Keeping previous file.")
        return

    # TCP check (run async)
    alive = asyncio.run(filter_alive(all_configs))

    # Write to file
    OUTPUT_FILE.write_text("\n".join(sorted(alive)), encoding="utf-8")
    logger.info("Written %d alive configs to %s", len(alive), OUTPUT_FILE)

# ------------------------------------------------------------
# Graceful shutdown
# ------------------------------------------------------------
def signal_handler(sig, frame):
    logger.info("Shutdown signal received, exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Xray Config Aggregator started")

    # Run immediately on start
    update_configs()

    # Schedule: check every hour, full update every 2 hours
    schedule.every(2).hours.do(update_configs)

    while True:
        schedule.run_pending()
        time.sleep(1)
