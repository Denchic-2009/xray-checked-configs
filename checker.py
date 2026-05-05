#!/usr/bin/env python3
import json
import sys
import time
import logging
import subprocess
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs

# --- Конфигурация ---
CONFIG_INPUT = Path("config.txt")
OUTPUT_FILE = Path("conf_ck.txt")
XRAY_BIN = "xray"  # Убедитесь, что xray установлен в системе
BASE_SOCKS_PORT = 10800
CHECK_URL = "https://www.gstatic.com/generate_204"
TIMEOUT = 10
MAX_WORKERS = 40 

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def parse_link(link: str) -> dict:
    """Парсит ссылку в формат outbound для Xray."""
    try:
        if link.startswith("vmess://"):
            import base64
            # Добавляем padding для корректного декодирования base64
            payload = link[8:].strip()
            data = json.loads(base64.b64decode(payload + "==").decode())
            return {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": data['add'], "port": int(data['port']), 
                             "users": [{"id": data['id'], "security": "auto"}]}]},
                "streamSettings": {"network": data.get("net", "tcp"), 
                                   "security": "tls" if data.get("tls") == "tls" else "none"}
            }
        
        p = urlparse(link)
        params = parse_qs(p.query)
        net = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]

        outbound = {
            "protocol": p.scheme,
            "settings": {},
            "streamSettings": {"network": net, "security": security}
        }

        if p.scheme == "vless":
            outbound["settings"] = {"vnext": [{"address": p.hostname, "port": p.port or 443, 
                                    "users": [{"id": p.username, "encryption": "none"}]}]}
        elif p.scheme == "trojan":
            outbound["settings"] = {"servers": [{"address": p.hostname, "port": p.port or 443, "password": p.username}]}
        else:
            return None

        # Обработка TLS и Reality
        if security in ["tls", "reality"]:
            key = f"{security}Settings"
            outbound["streamSettings"][key] = {"serverName": params.get("sni", [p.hostname])[0]}
            if security == "reality":
                outbound["streamSettings"][key].update({
                    "publicKey": params.get("pbk", [""])[0], 
                    "shortId": params.get("sid", [""])[0]
                })
        
        return outbound
    except Exception:
        return None

def test_config(link: str, port: int) -> str:
    """Запускает Xray и проверяет соединение через прокси."""
    outbound = parse_link(link)
    if not outbound:
        return None

    config_path = Path(f"tmp_{port}.json")
    xray_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "protocol": "socks", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }
    
    config_path.write_text(json.dumps(xray_config))
    
    process = None
    try:
        # Запуск Xray
        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1.5) # Ждем инициализации порта

        proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
        r = requests.get(CHECK_URL, proxies=proxies, timeout=TIMEOUT)
        
        if r.status_code == 204:
            logger.info(f"OK: {link[:50]}...")
            return link
    except Exception:
        pass
    finally:
        if process:
            process.terminate()
            process.wait()
        if config_path.exists():
            config_path.unlink()
    return None

def main():
    if not CONFIG_INPUT.exists():
        logger.error(f"Input file {CONFIG_INPUT} not found.")
        return

    links = [line.strip() for line in CONFIG_INPUT.read_text().splitlines() if line.strip()]
    logger.info(f"Starting check for {len(links)} configs...")

    working_links = []
    # Параллельное выполнение тестов
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Чтобы не занимать одинаковые порты, передаем разные значения порта
        futures = [executor.submit(test_config, link, BASE_SOCKS_PORT + i) for i, link in enumerate(links)]
        for f in futures:
            result = f.result()
            if result:
                working_links.append(result)

    OUTPUT_FILE.write_text("\n".join(working_links))
    logger.info(f"Done. Found {len(working_links)} working configs. Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
