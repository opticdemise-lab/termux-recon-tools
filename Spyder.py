import os
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

NOISE_EXTENSIONS = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".pdf",
)


def print_banner():
    banner = r"""
  ____  ____  __   __ ____   _____  ____  
 / ___||  _ \ \ \ / /|  _ \ | ____||  _ \ 
 \___ \| |_) | \ V / | | | ||  _|  | |_) |
  ___) |  __/   | |  | |_| || |___ |  _ < 
 |____/|_|      |_|  |____/ |_____||_| \_\

      [ Web Crawling & Netrunning ]
    """
    print(banner)


def update_progress(percent, status_text):
    bar_length = 20
    filled_length = int(round(bar_length * percent / 100.0))
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    sys.stdout.write(f"\r{bar} {percent:3d}% | {status_text:<20}")
    sys.stdout.flush()


def run_command_with_progress(cmd_list, start_pct, end_pct, label):
    result_lines = []
    done = threading.Event()

    def worker():
        nonlocal result_lines
        try:
            res = subprocess.run(
                cmd_list, capture_output=True, text=True, check=True
            )
            result_lines = res.stdout.splitlines()
        except FileNotFoundError:
            sys.stdout.write(
                f"\n[!] Error: '{cmd_list}' not found in PATH.\n"
            )
        except subprocess.CalledProcessError as e:
            sys.stdout.write(
                f"\n[!] Error running {cmd_list}: {e.stderr.strip()}\n"
            )
        finally:
            done.set()

    thread = threading.Thread(target=worker)
    thread.start()

    current_pct = start_pct
    while not done.is_set():
        update_progress(current_pct, label)
        if current_pct < end_pct - 1:
            current_pct += 1
        time.sleep(0.3)

    thread.join()
    update_progress(end_pct, f"{label} (Done)")
    return result_lines


def is_noise(url):
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Drop malformed/concatenated URLs or unusually long lines
    if len(url) > 250 or "http://" in path or "https://" in path:
        return True

    _, ext = os.path.splitext(path)
    return ext in NOISE_EXTENSIONS


def collect_and_filter_urls(domain, run_crawl, slow_mode, rate_limit):
    gau_end = 45 if run_crawl else 90
    gau_urls = run_command_with_progress(
        ["gau", domain], 0, gau_end, "Running gau"
    )

    katana_urls = []
    if run_crawl:
        katana_cmd = ["katana", "-u", domain, "-silent", "-ct", "18m", "-timeout", "12"]
        if slow_mode:
            katana_cmd.extend(["-rl", str(rate_limit), "-c", "1", "-d", "2"])
            label = f"Crawling ({rate_limit} req/s)"
        else:
            label = "Running katana"

        katana_urls = run_command_with_progress(katana_cmd, 45, 90, label)

    update_progress(95, "Filtering URLs")
    unique_urls = set(gau_urls + katana_urls)

    clean_urls = []
    seen_signatures = set()
    noise_dropped = 0
    dupes_collapsed = 0

    for url in sorted(unique_urls):
        if is_noise(url):
            noise_dropped += 1
            continue

        parsed = urlparse(url)
        if not parsed.query:
            continue

        # Normalize host (strip :80/:443) and group by path + parameter keys
        host = parsed.hostname or ""
        param_keys = tuple(sorted(parse_qs(parsed.query, keep_blank_values=True).keys()))
        signature = (host, parsed.path, param_keys)

        if signature in seen_signatures:
            dupes_collapsed += 1
            continue

        seen_signatures.add(signature)
        clean_urls.append(url)

    update_progress(100, "Complete!")
    print("\n")
    return clean_urls, len(unique_urls), noise_dropped, dupes_collapsed


def main():
    print_banner()
    target_domain = input("Enter target domain: ").strip()
    if not target_domain:
        print("No domain provided.")
        return

    crawl_choice = (
        input("Run active web crawl with katana? (y/n): ").strip().lower()
    )
    run_crawl = crawl_choice in ("y", "yes")

    slow_mode = False
    rate_limit = 2
    if run_crawl:
        slow_choice = (
            input("Use slow/rate-limited mode? (y/n): ").strip().lower()
        )
        slow_mode = slow_choice in ("y", "yes")
        if slow_mode:
            custom_rl = input(
                "Requests per second (press Enter for default 2): "
            ).strip()
            if custom_rl.isdigit() and int(custom_rl) > 0:
                rate_limit = int(custom_rl)

    print()
    filtered_results, total_unique, noise_dropped, dupes_collapsed = (
        collect_and_filter_urls(target_domain, run_crawl, slow_mode, rate_limit)
    )

    output_file = f"{target_domain}_filtered.txt"
    with open(output_file, "w") as f:
        for url in filtered_results:
            f.write(url + "\n")

    print(f"[+] Total unique URLs discovered: {total_unique}")
    print(f"[+] Noise & malformed URLs dropped: {noise_dropped}")
    print(f"[+] Duplicate parameter patterns collapsed: {dupes_collapsed}")
    print(
        f"[+] Saved {len(filtered_results)} unique endpoints to {output_file}."
    )


if __name__ == "__main__":
    main()
