import sys
import time
import threading
import queue
import requests
from concurrent.futures import ThreadPoolExecutor

GOOD_FILE = "good.txt"
MAX_WORKERS = 100  # увеличено количество потоков
MAX_ATTEMPTS = 3   # попытки для каждого URL
TIMEOUT_SECONDS = 20  # таймаут в секундах для запроса
QUEUE_MAXSIZE = 1000  # ограничение на размер очереди

TASK_QUEUE: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
STOP_SIGNAL = object()  # сигнал для остановки рабочих потоков


# ---------- THREAD-SAFE PRINTING ----------

print_lock = threading.Lock()


def safe_print(text: str):
    """Печать текста в консоль с блокировкой для предотвращения проблемы с многозадачностью"""
    enc = sys.stdout.encoding or "utf-8"
    with print_lock:
        try:
            print(text.encode(enc, errors="replace").decode(enc))
        except Exception:
            print(text)


# ---------- FILE UTILITIES ----------

def read_ports(filename: str):
    """Чтение портов из файла"""
    ports = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                ports.append(line)
    return ports


def ip_lines(filename: str):
    """Генератор строк IP-адресов"""
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                yield ip


def generate_targets(ips_filename: str, ports):
    """Генератор для создания всех комбинаций IP, портов и протоколов"""
    for ip in ip_lines(ips_filename):
        for port in ports:
            yield ("http", ip, port)
            yield ("https", ip, port)


# ---------- good.txt WRITING (THREAD-SAFE) ----------

write_lock = threading.Lock()


def write_good_line(line: str):
    """Запись в good.txt с блокировкой"""
    with write_lock:
        with open(GOOD_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


# ---------- URL PROCESSING WITH REQUESTS ----------

def handle_target_with_requests(proto: str, ip: str, port: str):
    """Обработка URL с использованием библиотеки requests"""
    url = f"{proto}://{ip}:{port}/"

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = requests.get(url, timeout=TIMEOUT_SECONDS)

            # Успех: извлекаем заголовок страницы
            title = response.text.split('<title>')[1].split('</title>')[0] if '<title>' in response.text else 'No Title'

            # Вывод в консоль
            safe_print(f"{proto} - {ip}:{port} > {title}")

            # Запись в good.txt
            write_good_line(f"{url} | {title}")

            return  # успех, выходим из цикла

        except Exception as e:
            if attempt == MAX_ATTEMPTS:
                # Финальная ошибка
                safe_print(f"{proto} - {ip}:{port} ! FAIL")
            else:
                time.sleep(1.0)


# ---------- MAIN ----------

def main():
    ports = read_ports("ports.txt")

    # Очистка файла good.txt перед началом работы
    open(GOOD_FILE, "w", encoding="utf-8").close()

    # Создаем пул потоков (работает до MAX_WORKERS потоков)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Генерируем задачи для пула
        for proto, ip, port in generate_targets("ips.txt", ports):
            executor.submit(handle_target_with_requests, proto, ip, port)

    # Ожидаем завершения всех задач
    safe_print("Завершена обработка всех URL")


if __name__ == "__main__":
    main()
