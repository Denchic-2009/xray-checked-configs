import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from urllib.parse import urlparse
import requests

# Настройки
SUBSCRIPTION_URL = "https://raw.githubusercontent.com/FLAT447/v2ray-lists/refs/heads/main/WHITE_FULL.txt"
OUTPUT_FILE = "test.txt"
TIMEOUT = 2.0  # Таймаут TCP пинга в секундах
MAX_WORKERS = 70  # Количество параллельных потоков для проверки


def fetch_subscription(url):
  """Скачивает подписку и декодирует Base64, если это необходимо."""
  try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    content = response.text.strip()

    # Декодирование Base64 (стандартный формат большинства подписок)
    try:
      padding = 4 - (len(content) % 4)
      if padding < 4:
        content += "=" * padding
      decoded_bytes = base64.b64decode(content)
      content = decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
      pass  # Если это не Base64, оставляем как обычный текст с URI

    # Извлекаем строки с прокси
    proxies = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and "://" in line
    ]
    return proxies
  except Exception as e:
    print(f"Ошибка при скачивании подписки: {e}")
    return []


def extract_host_port(uri):
  """Извлекает хост и порт из URI различных прокси-протоколов."""
  try:
    # Обработка старого формата Shadowsocks (base64 внутри)
    if uri.startswith("ss://") and "@" not in uri.split("://")[1]:
      parts = uri.split("://")[1].split("#")[0]
      try:
        decoded_ss = (
            base64.b64decode(parts + "==").decode("utf-8", errors="ignore")
            or parts
        )
        if "@" in decoded_ss:
          host_port = decoded_ss.split("@")[1].split("/")[0]
          host, port = host_port.rsplit(":", 1)
          return host, int(port)
      except Exception:
        pass

    # Стандартный парсинг для vless, trojan, hysteria2, shadowsocks (SIP002)
    parsed = urlparse(uri)
    netloc = parsed.netloc
    if "@" in netloc:
      netloc = netloc.split("@")[1]
    if ":" in netloc:
      host, port_str = netloc.rsplit(":", 1)
      port = int(port_str.split("?")[0].split("/")[0])
      return host.strip("[]"), port
  except Exception:
    pass
  return None, None


def tcp_ping(host, port, timeout=TIMEOUT):
  """Выполняет TCP-соединение и возвращает задержку в миллисекундах."""
  start_time = time.time()
  try:
    with socket.create_connection((host, port), timeout=timeout):
      latency = (time.time() - start_time) * 1000
      return True, round(latency, 2)
  except Exception:
    return False, 0


def check_proxy(uri):
  """Проверяет отдельный прокси."""
  host, port = extract_host_port(uri)
  if not host or not port:
    return None
  success, latency = tcp_ping(host, port)
  if success:
    return (uri, latency)
  return None


def main():
  print("Загрузка подписки...")
  proxies = fetch_subscription(SUBSCRIPTION_URL)
  print(f"Найдено конфигураций: {len(proxies)}")

  if not proxies:
    print("Список прокси пуст или недоступен.")
    return

  working_proxies = []
  print("Запуск проверки TCP пинга...")

  with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(check_proxy, proxy): proxy for proxy in proxies}
    for future in as_completed(futures):
      result = future.result()
      if result:
        uri, latency = result
        working_proxies.append((uri, latency))
        print(f"[OK] {latency}ms | {uri[:60]}...")

  # Сортируем рабочие прокси по возрастанию пинга
  working_proxies.sort(key=lambda x: x[1])

  # Сохраняем в файл test.txt (построчно, поддерживается клиентами в качестве подписки)
  with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for uri, _ in working_proxies:
      f.write(uri + "\n")

  print(f"\nГотово! Прошло проверку: {len(working_proxies)} из {len(proxies)}")
  print(f"Результат сохранен в файл: {OUTPUT_FILE}")


if __name__ == "__main__":
  main()
