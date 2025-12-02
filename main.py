import sys
import time
import threading
import queue
import gc

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


GOOD_FILE = "good.txt"
MAX_WORKERS = 20             # exactly 3 browsers at the same time
MAX_ATTEMPTS = 3            # attempts per target
TIMEOUT_SECONDS = 20        # <-- your 20-second timeout
PAGE_LOAD_TIMEOUT = TIMEOUT_SECONDS
WAIT_BODY_TIMEOUT = TIMEOUT_SECONDS
QUEUE_MAXSIZE = 1000        # limit queued tasks to save memory

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


# ---------- SELENIUM SETUP ----------

# Install chromedriver once and reuse path
CHROME_DRIVER_PATH = ChromeDriverManager().install()


def create_driver():
    """
    Create a headless Chrome driver with basic options.
    Called once per worker thread and reused for many URLs.
    """
    chrome_options = Options()
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--ignore-ssl-errors=yes")
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    service = Service(CHROME_DRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver


# ---------- URL PROCESSING WITH SELENIUM ----------

def handle_target_with_driver(driver, proto: str, ip: str, port: str):
    """
    Open URL with the given Selenium driver and process result.

    On success:
        - Console: protocol - IP:Port > Page Title
        - good.txt: <protocol>://ip:port/ | Page Title

    On final failure:
        - Console: protocol - IP:Port ! FAIL
    """
    url = f"{proto}://{ip}:{port}/"

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            driver.get(url)

            # Try to wait for <body>, but ignore if timeout
            try:
                WebDriverWait(driver, WAIT_BODY_TIMEOUT).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except Exception:
                # Even if body wait fails, we still can read the title
                pass

            title = driver.title or ""

            # SUCCESS line to console:
            # protocol - IP:Port > Page Title
            safe_print(f"{proto} - {ip}:{port} > {title}")

            # Update good.txt immediately
            write_good_line(f"{url} | {title}")

            return  # success, stop attempts

        except Exception:
            if attempt == MAX_ATTEMPTS:
                # Final failure
                safe_print(f"{proto} - {ip}:{port} ! FAIL")
            else:
                time.sleep(1.0)


# ---------- WORKER THREAD ----------

def worker_loop(worker_id: int):
    """
    Worker thread:
    - creates its own Selenium driver once
    - takes tasks from TASK_QUEUE
    - stops when receives STOP_SIGNAL
    """
    driver = create_driver()
    try:
        while True:
            task = TASK_QUEUE.get()
            try:
                if task is STOP_SIGNAL:
                    TASK_QUEUE.task_done()
                    break

                proto, ip, port = task
                handle_target_with_driver(driver, proto, ip, port)

                TASK_QUEUE.task_done()
            except Exception:
                TASK_QUEUE.task_done()
    finally:
        driver.quit()
        del driver
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
