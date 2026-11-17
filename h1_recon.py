import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup, Comment

requests.packages.urllib3.disable_warnings()

# --- CONFIGURATION ---
H1_USERNAME = "too_kryll"
WORDLIST = os.path.expanduser("~/wordlists/common.txt")
PORTS = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    1433, 3000, 3306, 3389, 5000, 5432, 6379, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090
)
# ---------------------

raw_target = input("Enter in-scope HackerOne domain: ").strip()
target = urlparse(raw_target if "://" in raw_target else "http://" + raw_target).netloc

headers = {
    "User-Agent": f"Mozilla/5.0 (Linux; Android 14) HackerOne-Research-{H1_USERNAME}",
    "X-HackerOne-Research": H1_USERNAME
}

report_lines = []
def log(text=""):
    print(text)
    report_lines.append(text)

def run_subfinder(domain):
    """Runs subfinder with explicit resolvers for Termux DNS compatibility."""
    if not shutil.which("subfinder"):
        return []
    try:
        out = subprocess.check_output(
            ["subfinder", "-d", domain, "-r", "1.1.1.1,8.8.8.8", "-max-time", "15", "-silent"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60
        )
        return sorted({line.strip().lower() for line in out.splitlines() if line.strip()})
    except Exception:
        return []

def run_ffuf(base_url):
    """Runs ffuf with a live terminal progress bar and logs JSON results."""
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
            "-H", f"X-HackerOne-Research: {H1_USERNAME}",
            "-H", f"User-Agent: {headers['User-Agent']}",
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

def scan_port(target_ip, port):
    """Checks if TCP port is open and probes for HTTP/HTTPS title."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.2)
        if s.connect_ex((target_ip, port)) != 0:
            return None

        details = []
        non_web_ports = {21, 22, 23, 25, 53, 110, 143, 445, 1433, 3306, 3389, 5432, 6379}
        if port not in non_web_ports:
            for scheme in ("https", "http"):
                try:
                    url = f"{scheme}://{target}:{port}"
                    r = requests.get(url, headers=headers, timeout=3, verify=False)
                    soup = BeautifulSoup(r.text, "html.parser")
                    title = soup.title.string.strip() if soup.title and soup.title.string else "No Title"
                    details.append(f"{scheme.upper()} {r.status_code} | Title: {title[:50]}")
                    break
                except Exception:
                    continue
        return port, " | ".join(details)

log(f"=== HackerOne Auto-Audit Report: {target} ===")
log(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# 1. IP RESOLUTION
ip = None
try:
    ip = socket.gethostbyname(target)
    log(f"[+] IP Address: {ip}")
except Exception as e:
    log(f"[-] Could not resolve IP: {e}")

# 2. SUBFINDER ENUMERATION
log("\n[+] Subdomain Discovery (Subfinder):")
subdomains = run_subfinder(target)
if subdomains:
    log(f"    Found {len(subdomains)} unique subdomains (showing up to 30):")
    for sub in subdomains[:30]:
        log(f"    - {sub}")
else:
    log("    No subdomains found or subfinder timed out.")

# 3. PORT SCANNING + AUTOMATIC NMAP SERVICE DETECTION
open_ports = []
if ip:
    log(f"\n[+] Scanning {len(PORTS)} High-Value Ports:")
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in PORTS]
        for future in futures:
            res = future.result()
            if res:
                port, info = res
                open_ports.append(str(port))
                extra = f" -> ({info})" if info else ""
                log(f"    [OPEN] Port {port}{extra}")

    if open_ports and shutil.which("nmap"):
        port_str = ",".join(open_ports)
        log(f"\n[+] Running Targeted Nmap Service Scan (-sV -Pn -p {port_str}):")
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
        except Exception as e:
            log(f"    [-] Nmap scan skipped or timed out: {e}")

# 4. WEB RECON & AUTO-AUDIT
response = None
for scheme in ("https", "http"):
    try:
        response = requests.get(f"{scheme}://{target}", headers=headers, timeout=8, verify=False)
        log(f"\n[+] Main Web HTTP Status: {response.status_code}")
        log(f"[+] Final URL: {response.url}")
        break
    except Exception:
        continue

if response is not None:
    log("\n[+] Server & Security Headers:")
    for key, value in response.headers.items():
        log(f"    {key}: {value}")

    # Security Header Audit
    log("\n[!] Security Header Audit (Missing Protections):")
    required_headers = (
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    )
    existing_lower = {k.lower() for k in response.headers.keys()}
    for h in required_headers:
        if h.lower() not in existing_lower:
            log(f"    [MISSING] {h}")

    # Sensitive Exposure & Recon File Audit (with Soft-200 check)
    log("\n[+] Auditing Recon & Sensitive Exposure Paths:")
    base_url = response.url.rstrip("/")
    home_len = len(response.text)
    audit_paths = (
        "/robots.txt",
        "/.well-known/security.txt",
        "/.env",
        "/.git/config",
        "/swagger.json",
        "/api-docs",
        "/.DS_Store"
    )
    for path in audit_paths:
        try:
            r = requests.get(f"{base_url}{path}", headers=headers, timeout=4, allow_redirects=False, verify=False)
            is_soft_200 = (r.status_code == 200 and abs(len(r.text) - home_len) < 100)
            flag = ""
            if r.status_code == 200 and not is_soft_200 and path not in ("/robots.txt", "/.well-known/security.txt"):
                flag = " <-- CHECK THIS!"
            elif is_soft_200:
                flag = " (Soft-200 / SPA fallback)"
            log(f"    {path} -> Status {r.status_code}{flag}")
            time.sleep(0.2)
        except Exception:
            log(f"    {path} -> Failed")

    # 5. DIRECTORY FUZZING (FFUF)
    log(f"\n[+] Directory Fuzzing (ffuf -> {base_url}/FUZZ):")
    run_ffuf(base_url)

    # Parse HTML content (Deduplicated)
    soup = BeautifulSoup(response.text, "html.parser")

    scripts = sorted({script["src"] for script in soup.find_all("script", src=True)})
    log(f"\n[+] Unique JS Files Found ({len(scripts)}):")
    for src in scripts:
        log(f"    [JS] {src}")

    links = sorted({link["href"] for link in soup.find_all("a", href=True)})
    log(f"\n[+] Unique Links Found ({len(links)}):")
    for href in links:
        log(f"    [Link] {href}")

    log("\n[+] HTML Comments:")
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        if comment.strip():
            log(f"    [Comment] {comment.strip()}")
else:
    log("\n[-] Could not connect via HTTPS or HTTP.")

# --- SAVE & ARCHIVE ---
out_dir = os.path.expanduser("~/bounties/active")
os.makedirs(out_dir, exist_ok=True)
filename = os.path.join(out_dir, f"h1_{target.replace('.', '_')}.txt")

with open(filename, "w", encoding="utf-8") as f:
    f.write("\n".join(report_lines))

print(f"\n[*] Report saved to {filename}")

choice = input("\nArchive and mark this target as completed? (y/n): ").strip().lower()
if choice == "y":
    completed_dir = os.path.expanduser("~/bounties/completed")
    os.makedirs(completed_dir, exist_ok=True)
    dest = os.path.join(completed_dir, os.path.basename(filename))
    shutil.move(filename, dest)
    print(f"[*] Archived to {dest}")
else:
    print("[*] Kept in active/ for further hunting.")
