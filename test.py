import sys
import re
import requests
import urllib3

MAX_ATTEMPTS = 3
TIMEOUT_SECONDS = 20

# Disable SSL warnings because we intentionally allow self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def safe_print(text: str) -> None:
    """Print one line safely, handling encoding issues."""
    enc = sys.stdout.encoding or "utf-8"
    try:
        print(text.encode(enc, errors="replace").decode(enc))
    except Exception:
        print(text)


def read_ports(filename: str):
    """Read ports.txt into a list of ports."""
    ports = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                ports.append(line)
    return ports


def extract_title(html: str) -> str:
    """Return the contents of the first <title> tag found in HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return match.group(1).strip()


def fetch_target(session: requests.Session, proto: str, ip: str, port: str) -> bool:
    """Fetch the target URL, ensuring redirects settle on a final page before logging."""
    url = f"{proto}://{ip}:{port}/"
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = session.get(
                url,
                timeout=TIMEOUT_SECONDS,
                allow_redirects=True,
                verify=False,
            )

            if response.status_code >= 400:
                raise requests.HTTPError(f"bad status: {response.status_code}")
            if 300 <= response.status_code < 400:
                raise requests.HTTPError("redirect chain did not reach final page")

            title = extract_title(response.text or "")
            final_url = response.url
            safe_print(f"{proto} - {ip}:{port} > {final_url} | {title}")
            return True
        except requests.RequestException:
            if attempt == MAX_ATTEMPTS:
                safe_print(f"{proto} - {ip}:{port} ! FAIL")
            else:
                continue
    return False


def main():
    ip = input("Введите IP для проверки: ").strip()
    if not ip:
        safe_print("IP не указан, завершение работы.")
        return

    ports = read_ports("ports.txt")
    if not ports:
        safe_print("ports.txt пуст или не найден.")
        return

    with requests.Session() as session:
        for port in ports:
            for proto in ("http", "https"):
                fetch_target(session, proto, ip, port)


if __name__ == "__main__":
    main()
