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
from pathlib import Path
from typing import Set, Tuple, Optional

import requests
import schedule

# ... (URLS и константы остаются прежними)

def get_host_port(uri: str) -> Optional[Tuple[str, int]]:
    """Исправлено: улучшена обработка IPv6 и разбор параметров."""
    try:
        if "@" in uri:
            # Извлекаем часть после последнего '@' (на случай, если пароль содержит @)
            rest = uri.rsplit("@", 1)[1]
            # Убираем фрагменты и параметры запроса
            rest = rest.split("#")[0].split("?")[0]
            
            # Обработка IPv6 в скобках [2001:db8::1]:443
            if "]" in rest:
                host = rest.split("]")[0] + "]"
                port_part = rest.split("]")[-1]
                port = int(port_part.split(":")[1]) if ":" in port_part else 443
                return host, port
            
            if ":" in rest:
                host, port_str = rest.rsplit(":", 1)
                return host, int(port_str)
            return rest, 443
    except Exception as e:
        logger.debug(f"Parsing error for {uri}: {e}")
    return None

# В функции update_configs добавим очистку дубликатов перед проверкой
def update_configs():
    logger.info("Starting config update...")
    all_configs: Set[str] = set()
    for url in URLS:
        fetched = fetch_configs(url)
        all_configs.update(fetched)

    if not all_configs:
        logger.error("No configs fetched. Keeping previous file.")
        return

    # Запуск асинхронной фильтрации
    alive = asyncio.run(filter_alive(all_configs))

    if alive:
        OUTPUT_FILE.write_text("\n".join(sorted(alive)), encoding="utf-8")
        logger.info("Written %d alive configs to %s", len(alive), OUTPUT_FILE)
    else:
        logger.warning("No alive configs found. File not updated.")

# Исправленный блок запуска (Entry point)
if __name__ == "__main__":
    logger.info("Xray Config Aggregator started")
    update_configs()

    # Исправлено: добавлены обе задачи согласно комментариям
    schedule.every(1).hours.do(update_configs) # Проверка/обновление каждый час

    while True:
        schedule.run_pending()
        time.sleep(1)
