import sys
import time
import threading
import queue
import gc
import re

import requests
import urllib3


GOOD_FILE = "good.txt"
MAX_WORKERS = 500             # number of worker threads
MAX_ATTEMPTS = 3             # attempts per target
CONNECT_TIMEOUT_SECONDS = 20  # connection timeout
READ_TIMEOUT_SECONDS = 60     # allow slower servers to finish sending pages
QUEUE_MAXSIZE = 1000         # limit queued tasks to save memory

# Disable SSL warnings because we intentionally allow self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TASK_QUEUE: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
STOP_SIGNAL = object()      # sentinel object to stop workers


# ---------- THREAD-SAFE PRINTING ----------

print_lock = threading.Lock()


def safe_print(text: str):
    """
    Print one line to console safely (avoid encoding issues and interleaving).
    Console output MUST be only in the required formats.
    """
    enc = sys.stdout.encoding or "utf-8"
    with print_lock:
        try:
            print(text.encode(enc, errors="replace").decode(enc))
        except Exception:
            print(text)


# ---------- FILE UTILITIES ----------

def read_ports(filename: str):
    """
    Read ports as a small list (ports.txt is usually small).
    """
    ports = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                ports.append(line)
    return ports


def ip_lines(filename: str):
    """
    Generator over non-empty IP lines (does NOT load whole file into memory).
    """
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                yield ip


def generate_targets(ips_filename: str, ports):
    """
    Memory-friendly generator of (proto, ip, port).
    Reads ips.txt line-by-line and yields all combinations
    with ports and protocols.
    """
    for ip in ip_lines(ips_filename):
        for port in ports:
            yield ("http", ip, port)
            yield ("https", ip, port)


# ---------- good.txt WRITING (THREAD-SAFE) ----------

write_lock = threading.Lock()


def write_good_line(line: str):
    """
    Append a line to GOOD_FILE in a thread-safe way.
    File is opened/closed on every write so it is always up to date.
    """
    with write_lock:
        with open(GOOD_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


# ---------- HTTP REQUEST HANDLING ----------


def extract_title(html: str) -> str:
    """Return the contents of the first <title> tag found in HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return match.group(1).strip()


def handle_target_with_session(session: requests.Session, proto: str, ip: str, port: str):
    """
    Fetch URL over HTTP/HTTPS, following redirects, and process the final page.

    On success:
        - Console: protocol - IP:Port > FinalURL | Page Title
        - good.txt: FinalURL | Page Title

    On final failure:
        - Console: protocol - IP:Port ! FAIL
    """
    url = f"{proto}://{ip}:{port}/"

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = session.get(
                url,
                timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
                allow_redirects=True,
                verify=False,
            )

            # Ensure we landed on a final (non-redirect) successful page
            if response.status_code >= 400:
                raise requests.HTTPError(f"bad status: {response.status_code}")
            if 300 <= response.status_code < 400:
                raise requests.HTTPError("redirect chain did not reach final page")

            html = response.text or ""
            title = extract_title(html)
            final_url = response.url

            safe_print(f"{proto} - {ip}:{port} > {final_url} | {title}")
            write_good_line(f"{final_url} | {title}")

            return  # success, stop attempts

        except requests.RequestException:
            if attempt == MAX_ATTEMPTS:
                safe_print(f"{proto} - {ip}:{port} ! FAIL")
            else:
                time.sleep(1.0)


# ---------- WORKER THREAD ----------

def worker_loop(worker_id: int):
    """
    Worker thread:
    - creates its own requests session once
    - takes tasks from TASK_QUEUE
    - stops when receives STOP_SIGNAL
    """
    session = requests.Session()
    try:
        while True:
            task = TASK_QUEUE.get()
            try:
                if task is STOP_SIGNAL:
                    TASK_QUEUE.task_done()
                    break

                proto, ip, port = task
                handle_target_with_session(session, proto, ip, port)

                TASK_QUEUE.task_done()
            except Exception:
                TASK_QUEUE.task_done()
    finally:
        session.close()
        del session
        gc.collect()


# ---------- MAIN ----------

def main():
    ports = read_ports("ports.txt")

    # Clear good.txt at the start
    open(GOOD_FILE, "w", encoding="utf-8").close()

    # Start exactly MAX_WORKERS worker threads
    threads = []
    for i in range(MAX_WORKERS):
        t = threading.Thread(
            target=worker_loop,
            args=(i + 1,),
            daemon=True
        )
        t.start()
        threads.append(t)

    # Produce tasks lazily from big ips.txt
    for proto, ip, port in generate_targets("ips.txt", ports):
        # This will block if the queue is full (limits memory)
        TASK_QUEUE.put((proto, ip, port))

    # Send STOP_SIGNAL for each worker
    for _ in range(MAX_WORKERS):
        TASK_QUEUE.put(STOP_SIGNAL)

    # Wait until all tasks are fully processed
    TASK_QUEUE.join()

    # Wait for workers to exit cleanly
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
