#!/usr/bin/env python3
"""
Xray Config Liveness Checker via https://www.gstatic.com/generate_204
Reads configs from config.txt, tests each one through a temporary Xray SOCKS5 proxy,
saves working configs to conf_ck.txt. Runs every hour.
"""

import json
import os
import signal
import subprocess
import sys
import time
import logging
import random
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import List, Optional, Dict

import requests
import schedule

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
CONFIG_INPUT = Path("config.txt")
OUTPUT_FILE = Path("conf_ck.txt")
XRAY_BIN = "xray"                     # or full path like "/usr/local/bin/xray"
BASE_SOCKS_PORT = 10800               # starting port for temporary SOCKS proxies
CHECK_URL = "https://www.gstatic.com/generate_204"
REQUEST_TIMEOUT = 10                  # seconds for the HTTP request
XRAY_STARTUP_DELAY = 1.5              # seconds to wait for Xray to start listening
MAX_WORKERS = 1                       # parallel checks (set 1 to avoid overload)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------
# Parser: convert a protocol link to Xray outbound config
# ------------------------------------------------------------
def parse_vless(uri: str) -> Optional[Dict]:
    """vless://uuid@host:port?params#remark"""
    try:
        parsed = urlparse(uri)
        uuid = parsed.username  # VLESS puts UUID in username part
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        remark = parsed.fragment or ""

        # Default settings
        ob = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": params.get("encryption", ["none"])[0]}]
                }]
            },
            "streamSettings": {},
            "tag": f"proxy-{remark}" if remark else "proxy"
        }

        # Security / TLS
        security = params.get("security", [None])[0]
        if security == "tls":
            ob["streamSettings"]["security"] = "tls"
            tls_settings = {"serverName": params.get("sni", [host])[0]}
            if "alpn" in params:
                tls_settings["alpn"] = params["alpn"]
            ob["streamSettings"]["tlsSettings"] = tls_settings
        elif security == "reality":
            # reality not fully supported in this simple parser
            pass

        # Transport
        transport = params.get("type", ["tcp"])[0]
        if transport != "tcp":
            ob["streamSettings"]["network"] = transport
            if transport == "ws":
                ws_settings = {}
                if "path" in params:
                    ws_settings["path"] = params["path"][0]
                if "host" in params:
                    ws_settings["headers"] = {"Host": params["host"][0]}
                ob["streamSettings"]["wsSettings"] = ws_settings
            elif transport == "grpc":
                if "serviceName" in params:
                    ob["streamSettings"]["grpcSettings"] = {"serviceName": params["serviceName"][0]}
            # add other transports as needed

        return ob
    except Exception as e:
        logger.debug(f"Failed to parse vless link: {e}")
        return None

def parse_vmess(uri: str) -> Optional[Dict]:
    """vmess://base64-json"""
    try:
        # vmess links are base64 encoded JSON
        import base64
        b64 = uri.replace("vmess://", "")
        # Add padding if necessary
        missing_padding = len(b64) % 4
        if missing_padding:
            b64 += '=' * (4 - missing_padding)
        conf = json.loads(base64.b64decode(b64).decode())
        host = conf.get("add", conf.get("host", ""))
        port = int(conf.get("port", 443))
        uid = conf.get("id", "")
        ob = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uid, "security": conf.get("scy", "auto")}]
                }]
            },
            "streamSettings": {},
            "tag": f"proxy-{conf.get('ps', '')}"
        }
        net = conf.get("net", "tcp")
        if net != "tcp":
            ob["streamSettings"]["network"] = net
            if net == "ws":
                ws = {}
                if "path" in conf:
                    ws["path"] = conf["path"]
                if "host" in conf:
                    ws["headers"] = {"Host": conf["host"]}
                ob["streamSettings"]["wsSettings"] = ws
        tls = conf.get("tls", "")
        if tls == "tls":
            ob["streamSettings"]["security"] = "tls"
            ob["streamSettings"]["tlsSettings"] = {"serverName": conf.get("sni", host)}
        return ob
    except Exception as e:
        logger.debug(f"Failed to parse vmess link: {e}")
        return None

def parse_trojan(uri: str) -> Optional[Dict]:
    """trojan://password@host:port?params#remark"""
    try:
        parsed = urlparse(uri)
        password = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        remark = parsed.fragment or ""
        ob = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {},
            "tag": f"proxy-{remark}"
        }
        sni = params.get("sni", [host])[0]
        ob["streamSettings"]["security"] = "tls"
        ob["streamSettings"]["tlsSettings"] = {"serverName": sni}
        # optional transport
        transport = params.get("type", ["tcp"])[0]
        if transport != "tcp":
            ob["streamSettings"]["network"] = transport
            if transport == "ws":
                ws = {}
                if "path" in params:
                    ws["path"] = params["path"][0]
                if "host" in params:
                    ws["headers"] = {"Host": params["host"][0]}
                ob["streamSettings"]["wsSettings"] = ws
        return ob
    except Exception as e:
        logger.debug(f"Failed to parse trojan link: {e}")
        return None

def parse_shadowsocks(uri: str) -> Optional[Dict]:
    """ss://base64(method:password)@host:port or ss://method:password@host:port"""
    try:
        if uri.startswith("ss://") and "@" in uri:
            # New format: ss://base64(method:password)@host:port
            userinfo_host = uri[5:]  # remove ss://
            if "#" in userinfo_host:
                userinfo_host = userinfo_host.split("#")[0]
            userinfo, hostport = userinfo_host.rsplit("@", 1)
            host, port_str = hostport.split(":")
            port = int(port_str)
            # userinfo may be base64
            import base64
            try:
                decoded = base64.urlsafe_b64decode(userinfo + "==").decode()
                method, password = decoded.split(":", 1)
            except Exception:
                # maybe plain method:password
                method, password = userinfo.split(":", 1)
            ob = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": password
                    }]
                },
                "tag": "proxy"
            }
            return ob
    except Exception as e:
        logger.debug(f"Failed to parse ss link: {e}")
    return None

def link_to_outbound(link: str) -> Optional[Dict]:
    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("ss://"):
        return parse_shadowsocks(link)
    logger.warning(f"Unsupported protocol, skipped: {link[:50]}...")
    return None

# ------------------------------------------------------------
# Temporary Xray process manager
# ------------------------------------------------------------
def generate_temp_config(socks_port: int, outbound: Dict) -> Dict:
    """Generate a minimal Xray config with an inbound SOCKS and a given outbound."""
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
                "tag": "socks-in"
            }
        ],
        "outbounds": [
            outbound,
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["socks-in"], "outboundTag": outbound.get("tag", "proxy")}
            ]
        }
    }
    return config

class XrayInstance:
    def __init__(self, outbound: Dict, port: int):
        self.port = port
        self.config = generate_temp_config(port, outbound)
        self.process = None

    def start(self):
        """Start xray with temporary config file."""
        config_path = Path(f"/tmp/xray_check_{self.port}.json")
        config_path.write_text(json.dumps(self.config, indent=2))
        try:
            self.process = subprocess.Popen(
                [XRAY_BIN, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(XRAY_STARTUP_DELAY)   # wait for socket to be ready
            return True
        except FileNotFoundError:
            logger.error(f"Xray binary not found at '{XRAY_BIN}'. Make sure Xray is installed and in PATH.")
            return False
        except Exception as e:
            logger.error(f"Failed to start Xray: {e}")
            return False

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

# ------------------------------------------------------------
# Check single config
# ------------------------------------------------------------
def test_config(link: str, port: int) -> bool:
    outbound = link_to_outbound(link)
    if not outbound:
        return False

    xray = XrayInstance(outbound, port)
    if not xray.start():
        return False

    try:
        # Use SOCKS5 proxy to make request
        proxies = {
            "http": f"socks5://127.0.0.1:{port}",
            "https": f"socks5://127.0.0.1:{port}"
        }
        resp = requests.get(CHECK_URL, proxies=proxies, timeout=REQUEST_TIMEOUT)
        # gstatic generate_204 returns 204 with empty body
        success = (resp.status_code == 204 and resp.text == "")
        if success:
            logger.info(f"✓ Working: {link[:80]}...")
        else:
            logger.debug(f"✗ Failed status {resp.status_code}")
        return success
    except Exception as e:
        logger.debug(f"✗ Connection error: {e}")
        return False
    finally:
        xray.stop()

# ------------------------------------------------------------
# Main loop
# ------------------------------------------------------------
def run_checks():
    if not CONFIG_INPUT.exists():
        logger.warning(f"{CONFIG_INPUT} not found, skipping.")
        return

    configs = [line.strip() for line in CONFIG_INPUT.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not configs:
        logger.info("No configs to check.")
        return

    logger.info(f"Testing {len(configs)} configs...")
    working = []
    for i, link in enumerate(configs):
        port = BASE_SOCKS_PORT + (i % 1000)   # avoid colliding with other possible instances
        if test_config(link, port):
            working.append(link)

    OUTPUT_FILE.write_text("\n".join(working), encoding="utf-8")
    logger.info(f"Check finished. {len(working)}/{len(configs)} are alive. Saved to {OUTPUT_FILE}")

def signal_handler(sig, frame):
    logger.info("Stopping checker...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    logger.info("Xray Config Checker started (tests through real tunnels)")

    # First run immediately
    run_checks()

    # Schedule every hour
    schedule.every(1).hours.do(run_checks)

    while True:
        schedule.run_pending()
        time.sleep(1)
