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
[span_4](start_span)CONFIG_INPUT = Path("config.txt")[span_4](end_span)
[span_5](start_span)OUTPUT_FILE = Path("conf_ck.txt")[span_5](end_span)
[span_6](start_span)XRAY_BIN = "xray"[span_6](end_span)
[span_7](start_span)BASE_SOCKS_PORT = 10800[span_7](end_span)
[span_8](start_span)CHECK_URL = "https://www.gstatic.com/generate_204"[span_8](end_span)
[span_9](start_span)TIMEOUT = 10[span_9](end_span)
[span_10](start_span)MAX_WORKERS = 40  # Теперь действительно работает параллельно[span_10](end_span)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def parse_link(link: str) -> dict:
    [span_11](start_span)[span_12](start_span)[span_13](start_span)"""Универсальный парсер для создания outbound конфига Xray [cite: 15-38]."""
    try:
        if link.startswith("vmess://"):
            import base64
            data = json.loads(base64.b64decode(link[8:] + "==").decode())
            return {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": data['add'], "port": int(data['port']), 
                             "users": [{"id": data['id'], "security": "auto"}]}]},
                "streamSettings": {"network": data.get("net", "tcp"), 
                                   "security": "tls" if data.get("tls") == "tls" else "none"}
            }
        
        # [cite_start]Парсинг VLESS, Trojan, SS (через urlparse)[span_11](end_span)[span_12](end_span)[span_13](end_span)
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

        # [span_14](start_span)Добавляем специфичные настройки TLS/Reality[span_14](end_span)
        if security in ["tls", "reality"]:
            key = f"{security}Settings"
            outbound["streamSettings"][key] = {"serverName": params.get("sni", [p.hostname])[0]}
            if security == "reality":
                outbound["streamSettings"][key].update({"publicKey": params.get("pbk", [""])[0], "shortId": params.get("sid", [""])[0]})
        
        return outbound
    except Exception:
        return None

def test_config(link: str, port: int) -> str:
    [span_15](start_span)"""Запускает Xray, проверяет соединение и возвращает ссылку, если она работает [cite: 42-48]."""
    outbound = parse_link(link)
    if not outbound: return None

    # [cite_start]Генерируем минимальный конфиг во временный файл[span_15](end_span)
    tmp_config = Path(f"/tmp/xray_{port}.json")
    conf_data = {
        "inbounds": [{"port": port, "protocol": "socks", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }
    tmp_config.write_text(json.dumps(conf_data))

    proc = None
    try:
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", str(tmp_config)], 
                                [span_16](start_span)stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)[span_16](end_span)
        [span_17](start_span)time.sleep(1.5) # Даем время на запуск[span_17](end_span)

        proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
        [span_18](start_span)resp = requests.get(CHECK_URL, proxies=proxies, timeout=TIMEOUT)[span_18](end_span)
        
        [span_19](start_span)if resp.status_code == 204:[span_19](end_span)
            logger.info(f"✓ Work: {link[:50]}...")
            return link
    except Exception:
        pass
    finally:
        [span_20](start_span)if proc: proc.terminate()[span_20](end_span)
        if tmp_config.exists(): tmp_config.unlink()
    return None

def run():
    if not CONFIG_INPUT.exists(): return
    links = CONFIG_INPUT.read_text().splitlines()
    
    logger.info(f"Starting check of {len(links)} configs...")
    working = []

    # [span_21](start_span)Используем пул потоков для параллельной проверки[span_21](end_span)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_config, link, BASE_SOCKS_PORT + i) for i, link in enumerate(links)]
        for f in futures:
            res = f.result()
            if res: working.append(res)

    [span_22](start_span)OUTPUT_FILE.write_text("\n".join(working))[span_22](end_span)
    logger.info(f"Done! Saved {len(working)} working configs.")

if __name__ == "__main__":
    run()
