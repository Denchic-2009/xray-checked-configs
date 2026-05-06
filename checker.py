#!/usr/bin/env python3
import json
import sys
import time
import logging
import subprocess
import requests
import base64
import socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs

# --- Конфигурация ---
CONFIG_INPUT = Path("config.txt")
OUTPUT_FILE = Path("conf_ck.txt")
XRAY_BIN = "xray" 
BASE_SOCKS_PORT = 10800
CHECK_URL = "https://www.gstatic.com/generate_204"
TIMEOUT = 10
MAX_WORKERS = 30 # Уменьшили для стабильности на слабых раннерах

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def wait_for_port(port: int, timeout: float = 3.0) -> bool:
    """Ожидает, пока порт откроется."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                return True
        time.sleep(0.2)
    return False

def parse_link(link: str) -> dict:
    """Парсит ссылки vmess/vless/trojan в формат Xray."""
    try:
        if link.startswith("vmess://"):
            payload = link[8:].strip()
            # Исправляем padding для base64
            missing_padding = len(payload) % 4
            if missing_padding:
                payload += '=' * (4 - missing_padding)
            
            data = json.loads(base64.b64decode(payload).decode())
            return {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": data.get('add'), "port": int(data.get('port', 443)), 
                             "users": [{"id": data.get('id'), "security": "auto"}]}]},
                "streamSettings": {
                    "network": data.get("net", "tcp"), 
                    "security": "tls" if data.get("tls") == "tls" else "none",
                    "tlsSettings": {"serverName": data.get("sni", data.get("host", ""))}
                }
            }
        
        p = urlparse(link)
        params = parse_qs(p.query)
        net = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        sni = params.get("sni", [p.hostname])[0]

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

        if security in ["tls", "reality"]:
            key = f"{security}Settings"
            outbound["streamSettings"][key] = {"serverName": sni}
            if security == "reality":
                outbound["streamSettings"][key].update({
                    "publicKey": params.get("pbk", [""])[0], 
                    "shortId": params.get("sid", [""])[0]
                })
        
        return outbound
    except Exception as e:
        return None

def test_config(link: str, port: int) -> str:
    """Проверка работоспособности конфига."""
    outbound = parse_link(link)
    if not outbound:
        return None

    config_path = Path(f"tmp_{port}.json")
    xray_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }
    
    config_path.write_text(json.dumps(xray_config))
    
    process = None
    try:
        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        # Ждем реального открытия порта вместо фиксированного sleep
        if wait_for_port(port):
            # Используем socks5h для удаленного DNS-резолвинга
            proxies = {
                "http": f"socks5h://127.0.0.1:{port}",
                "https": f"socks5h://127.0.0.1:{port}"
            }
            r = requests.get(CHECK_URL, proxies=proxies, timeout=TIMEOUT)
            if r.status_code == 204 or r.status_code == 200:
                logger.info(f"✅ OK: {link[:40]}...")
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
        logger.error(f"❌ Файл {CONFIG_INPUT} не найден!")
        return

    links = list(set(line.strip() for line in CONFIG_INPUT.read_text().splitlines() if line.strip()))
    logger.info(f"🔍 Начинаю проверку {len(links)} конфигов...")

    working_links = []
    # Используем ThreadPool для параллельной проверки
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_config, link, BASE_SOCKS_PORT + i) for i, link in enumerate(links)]
        for f in futures:
            res = f.result()
            if res:
                working_links.append(res)

    OUTPUT_FILE.write_text("\n".join(working_links))
    logger.info(f"🎉 Готово! Найдено рабочих: {len(working_links)}. Результат в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
 
