import sys
import time
import threading
import queue
import gc
import re

import requests
import urllib3


GOOD_FILE = "good.txt"
MAX_WORKERS = 200
MAX_ATTEMPTS = 3
CONNECT_TIMEOUT_SECONDS = 20
READ_TIMEOUT_SECONDS = 60
QUEUE_MAXSIZE = 1000

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TASK_QUEUE: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
STOP_SIGNAL = object()

print_lock = threading.Lock()


def safe_print(text: str):
    enc = sys.stdout.encoding or "utf-8"
    with print_lock:
        try:
            print(text.encode(enc, errors="replace").decode(enc))
        except Exception:
            print(text)


def read_ports(filename: str):
    ports = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                ports.append(line)
    return ports


def ip_lines(filename: str):
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                yield ip


def generate_targets(ips_filename: str, ports):
    for ip in ip_lines(ips_filename):
        for port in ports:
            yield ("http", ip, port)
            yield ("https", ip, port)


write_lock = threading.Lock()


def write_good_line(line: str):
    with write_lock:
        with open(GOOD_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def build_session() -> requests.Session:
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS,
        max_retries=0,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def handle_target_with_session(session: requests.Session, proto: str, ip: str, port: str):
    url = f"{proto}://{ip}:{port}/"

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = session.get(
                url,
                timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
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
            write_good_line(f"{final_url} | {title}")
            return

        except requests.RequestException:
            if attempt == MAX_ATTEMPTS:
                safe_print(f"{proto} - {ip}:{port} ! FAIL")
            else:
                time.sleep(1.0)


def worker_loop(worker_id: int):
    session = build_session()
    try:
        while True:
            task = TASK_QUEUE.get()
            try:
                if task is STOP_SIGNAL:
                    return
                proto, ip, port = task
                handle_target_with_session(session, proto, ip, port)
            except Exception:
                safe_print(f"worker {worker_id} encountered an error on {task}")
            finally:
                TASK_QUEUE.task_done()
    finally:
        session.close()
        gc.collect()


def main():
    ports = read_ports("ports.txt")
    open(GOOD_FILE, "w", encoding="utf-8").close()

    threads = []
    for i in range(MAX_WORKERS):
        t = threading.Thread(target=worker_loop, args=(i + 1,), daemon=True)
        t.start()
        threads.append(t)

    # Produce tasks lazily from big ips.txt
    for proto, ip, port in generate_targets("ips.txt", ports):
        TASK_QUEUE.put((proto, ip, port))

    # Send STOP_SIGNAL for each worker
    for _ in range(MAX_WORKERS):
        TASK_QUEUE.put(STOP_SIGNAL)

    TASK_QUEUE.join()

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
