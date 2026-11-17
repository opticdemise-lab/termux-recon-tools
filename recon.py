import json
import os
import shutil
import socket
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup, Comment

requests.packages.urllib3.disable_warnings()

WORDLIST = os.path.expanduser("~/wordlists/common.txt")
NEUTRAL_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
PORTS = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    1433, 3000, 3306, 3389, 5000, 5432, 6379, 8000,
    8080, 8443, 8888, 9000
)

raw_target = input("Target domain (e.g. scanme.nmap.org): ").strip()
target = urlparse(raw_target if "://" in raw_target else "http://" + raw_target).netloc

report_lines = []
interesting_findings = []

def log(text=""):
    print(text)
    report_lines.append(text)

def run_ffuf(base_url):
    """Runs ffuf with a live terminal progress bar and no research tags."""
    if not shutil.which("ffuf"):
        log("    [-] ffuf not found in PATH.")
        return
    if not os.path.exists(WORDLIST):
        log(f"    [-] Wordlist not found at {WORDLIST}")
        return

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        cmd = [
            "ffuf", "-w", WORDLIST, "-u", f"{base_url}/FUZZ",
            "-H", f"User-Agent: {NEUTRAL_UA}",
            "-ac", "-t", "15", "-rate", "10", "-noninteractive",
            "-o", tmp_path, "-of", "json"
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, timeout=600)
        print()

        if os.path.exists(tmp_path):
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            results = data.get("results", [])
            if results:
                interesting_findings.append(f"{len(results)} directories/files discovered via ffuf")
                log(f"    Found {len(results)} valid paths:")
                for res in results:
                    log(f"    [{res.get('status')}] /{res.get('input', {}).get('FUZZ', '')} (Size: {res.get('length')})")
            else:
                log("    No hidden directories or files matched.")
    except subprocess.TimeoutExpired:
        print()
        log("    [-] ffuf timed out after 10 minutes.")
    except Exception as e:
        print()
        log(f"    [-] ffuf error: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

log(f"=== Recon Report: {target} ===")
log(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

log("[*] PHASE 1: Passive Subdomain Discovery (Subfinder)")
if shutil.which("subfinder"):
    try:
        out = subprocess.check_output(
            ["subfinder", "-d", target, "-r", "1.1.1.1,8.8.8.8", "-max-time", "15", "-silent"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=25
        )
        subs = sorted({line.strip().lower() for line in out.splitlines() if line.strip()})
        if subs:
            interesting_findings.append(f"{len(subs)} subdomains discovered")
            log(f"[+] Subdomains Found ({len(subs)}):")
            for s in subs[:40]:
                log(f"    - {s}")
        else:
            log("    No subdomains found.")
    except Exception as e:
        log(f"[-] Subfinder error: {e}")
else:
    log("[-] subfinder not found in PATH.")

print("    Your current IP will be visible unless routed through a VPN or torsocks.")
proceed = input("Proceed with active scanning? (y/n): ").strip().lower()

if proceed == "y":
    ip = None
    try:
        ip = socket.gethostbyname(target)
        log(f"\n[+] IP Address: {ip}")
    except Exception as e:
        log(f"\n[-] Could not resolve IP: {e}")

    # HTTP Check
    response = None
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{target}", headers={"User-Agent": NEUTRAL_UA}, timeout=6, verify=False)
            log(f"[+] HTTP Status: {response.status_code}")
            log(f"[+] Final URL: {response.url}")
            log("\n[+] Server Headers:")
            for k, v in response.headers.items():
                log(f"    {k}: {v}")
            break
        except Exception:
            continue

    # Concurrent Port Scan
    def check_port(target_ip, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((target_ip, port)) == 0:
                return port
        return None

    open_ports = []
    if ip:
        log(f"\n[+] Scanning {len(PORTS)} Common Ports:")
        with ThreadPoolExecutor(max_workers=25) as executor:
            for port in executor.map(lambda p: check_port(ip, p), PORTS):
                if port:
                    open_ports.append(port)
                    log(f"    [OPEN] Port {port}")

        uncommon_ports = [p for p in open_ports if p not in (80, 443)]
        if uncommon_ports:
            interesting_findings.append(f"Open non-web ports: {uncommon_ports}")

        if open_ports and shutil.which("nmap"):
            port_str = ",".join(str(p) for p in open_ports)
            log(f"\n[+] Nmap Service Detection (-sV -Pn -p {port_str}):")
            try:
                nmap_out = subprocess.check_output(
                    ["nmap", "-sV", "--version-intensity", "2", "-Pn", "-T4", "-p", port_str, ip],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=45
                )
                for line in nmap_out.splitlines():
                    if "/tcp" in line:
                        log(f"    {line.strip()}")
            except Exception:
                log("    [-] Nmap timed out or skipped.")

    # Optional Directory Fuzzing (ffuf)
    if response is not None:
        fuzz_choice = input("\nRun directory fuzzing (ffuf)? (y/n): ").strip().lower()
        if fuzz_choice == "y":
            base_url = response.url.rstrip("/")
            log(f"\n[+] Directory Fuzzing (ffuf -> {base_url}/FUZZ):")
            run_ffuf(base_url)

        # Optional HTML Scraping
        scrape = input("\nPull links and HTML comments? (y/n): ").strip().lower()
        if scrape == "y":
            soup = BeautifulSoup(response.text, "html.parser")
            unique_links = sorted({link["href"] for link in soup.find_all("a", href=True)})
            log(f"\n--- Unique Links Found ({len(unique_links)}) ---")
            for href in unique_links:
                log(f"    [Link] {href}")

            comments = [c.strip() for c in soup.find_all(string=lambda text: isinstance(text, Comment)) if c.strip()]
            if comments:
                interesting_findings.append(f"{len(comments)} HTML comments found")
            log("\n--- HTML Comments ---")
            for comment in comments:
                log(f"    [Comment] {comment}")

if interesting_findings:
    print("\n[★] INTERESTING FINDINGS DETECTED:")
    for item in interesting_findings:
        print(f"    - {item}")
    save_choice = input("\nEncrypt and file this report into ~/recon_vault/? (y/n): ").strip().lower()
else:
    print("\n[*] Nothing unusual flagged during this scan.")
    save_choice = input("Force-encrypt and save anyway? (y/n): ").strip().lower()

if save_choice == "y":
    if not shutil.which("gpg"):
        print("[-] GPG not installed. Run: pkg install gnupg -y")
    else:
        vault_dir = os.path.expanduser("~/recon_vault")
        os.makedirs(vault_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_file = os.path.join(vault_dir, f"recon_{target.replace('.', '_')}_{ts}.txt")
        enc_file = f"{raw_file}.gpg"

        with open(raw_file, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))

        print("[*] Enter a passphrase to encrypt the report:")
        subprocess.run(["gpg", "--symmetric", "--cipher-algo", "AES256", "-o", enc_file, raw_file])
        if os.path.exists(enc_file):
            os.remove(raw_file)
            print(f"[+] Encrypted archive filed safely: {enc_file}")
