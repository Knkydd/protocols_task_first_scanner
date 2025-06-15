import socket
import ssl
import json
import os

LAT_EKB = 56.8389
LON_EKB = 60.6057
CONFIG_FILE = "key.json"

def load_api_key(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Не найден файл конфигурации: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    key = data.get("api_key")
    if not key:
        raise ValueError("В key.json не задан api_key")
    return key

def decode_chunked(body: bytes) -> bytes:
    decoded = b""
    idx = 0

    while True:
        pos = body.find(b"\r\n", idx)
        if pos == -1:
            break
        length_str = body[idx:pos].decode('ascii').strip()
        try:
            length = int(length_str, 16)
        except ValueError:
            break
        if length == 0:
            break

        start = pos + 2
        end = start + length
        decoded += body[start:end]
        idx = end + 2

    return decoded

def get_weather(api_key: str, lat: float, lon: float) -> dict | None:
    host = "api.weather.yandex.ru"
    port = 443

    request_line = f"GET /v2/forecast?lat={lat}&lon={lon}&lang=ru_RU HTTP/1.1\r\n"
    headers = [
        f"Host: {host}",
        "Connection: close",
        f"X-Yandex-API-Key: {api_key}",
    ]

    http_request = request_line + "\r\n".join(headers) + "\r\n\r\n"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(sock, server_hostname=host)
    s.connect((host, port))
    s.sendall(http_request.encode("utf-8"))

    resp = b""

    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk

    s.close()

    sep = b"\r\n\r\n"
    header_end = resp.find(sep)

    if header_end == -1:
        print("Invalid HTTP response")
        return None

    raw_headers = resp[:header_end].decode("utf-8", errors="replace")
    body = resp[header_end + 4:]

    if "Transfer-Encoding: chunked" in raw_headers:
        body = decode_chunked(body)

    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as e:
        print("JSON parse error:", e)
        return None

def main():
    try:
        api_key = load_api_key(CONFIG_FILE)
    except Exception as e:
        print("Ошибка загрузки API-ключа:", e)
        return

    weather = get_weather(api_key, LAT_EKB, LON_EKB)

    if not weather:
        return

    fact = weather.get("fact")

    if not fact:
        print("В ответе нет секции 'fact'")
        return

    print("Погода в Екатеринбурге:")
    print(f"  Температура: {fact.get('temp', '—')} °C")
    print(f"  Состояние: {fact.get('condition', '—')}")
    print(f"  Ветер: {fact.get('wind_speed', '—')} м/с")
    print(f"  Влажность: {fact.get('humidity', '—')}%")
    print(f"  Давление: {fact.get('pressure_mm', '—')} мм рт. ст.")

if __name__ == "__main__":
    main()