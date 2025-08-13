import subprocess
import os
import argparse
from datetime import datetime
import random
import time
import requests
from urllib.parse import urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup

# ---------- SETTINGS ----------
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconTool/3.0"
}
REQUEST_DELAY = (1, 3)

def stealth_request(url, allow_redirects=True, **kwargs):
    """Send request with delay to avoid hammering server."""
    time.sleep(random.uniform(*REQUEST_DELAY))
    return requests.get(url, headers=HEADERS, timeout=5, allow_redirects=allow_redirects, **kwargs)

# ---------- KALI TOOL WRAPPER ----------
def run_tool(cmd, outfile):
    print(f"[+] Running: {' '.join(cmd)}")
    with open(outfile, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)

# ---------- PYTHON CHECKS ----------
def check_security_headers(url, report_dir):
    try:
        print("\n[+] Checking security headers...")
        r = stealth_request(url)
        headers = r.headers
        important_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        missing = [h for h in important_headers if h not in headers]
        result = ""
        if missing:
            result = f"Missing headers: {', '.join(missing)}"
        else:
            result = "All important headers present."
        with open(f"{report_dir}/security_headers.txt", "w") as f:
            f.write(result)
    except Exception as e:
        print(f"[!] Error checking headers: {e}")

def check_cors(url, report_dir):
    try:
        print("\n[+] Checking for CORS misconfig...")
        evil_origin = "https://evil.com"
        r = stealth_request(url, headers={**HEADERS, "Origin": evil_origin})
        origin_allowed = r.headers.get("Access-Control-Allow-Origin", "")
        if origin_allowed in ("*", evil_origin):
            with open(f"{report_dir}/cors.txt", "w") as f:
                f.write(f"Possible CORS misconfiguration: {origin_allowed}")
    except Exception as e:
        print(f"[!] CORS check failed: {e}")

def check_csrf(url, report_dir):
    try:
        print("\n[+] Checking for CSRF tokens in forms...")
        token_names = ["csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token"]
        r = stealth_request(url)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        results = []
        for i, form in enumerate(forms, start=1):
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            has_token = any(inp.get("name") in token_names for inp in hidden_inputs)
            if not has_token:
                results.append(f"Form {i} may be missing CSRF token")
        with open(f"{report_dir}/csrf.txt", "w") as f:
            f.write("\n".join(results) if results else "All forms seem to have CSRF tokens.")
    except Exception as e:
        print(f"[!] CSRF check failed: {e}")

def test_open_redirect(url, report_dir):
    try:
        print("\n[+] Testing for Open Redirect...")
        payload = "https://evil.com"
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for key in params:
                params[key] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                r = stealth_request(test_url, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308) and payload in r.headers.get("Location", ""):
                    with open(f"{report_dir}/open_redirect.txt", "a") as f:
                        f.write(f"Open Redirect on '{key}' → {test_url}\n")
    except Exception as e:
        print(f"[!] Open Redirect test failed: {e}")

def test_lfi(url, report_dir):
    try:
        print("\n[+] Testing for Local File Inclusion...")
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../../../windows/win.ini"
        ]
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for payload in lfi_payloads:
                for key in params:
                    params[key] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                    r = stealth_request(test_url)
                    if "root:x:" in r.text or "for 16-bit app support" in r.text:
                        with open(f"{report_dir}/lfi.txt", "a") as f:
                            f.write(f"LFI detected on '{key}' → {test_url}\n")
    except Exception as e:
        print(f"[!] LFI test failed: {e}")

def test_rfi(url, report_dir):
    try:
        print("\n[+] Testing for Remote File Inclusion...")
        payload = "http://test.example.com/rfi.txt"
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for key in params:
                params[key] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
                r = stealth_request(test_url)
                if "rfi_test_marker" in r.text.lower():
                    with open(f"{report_dir}/rfi.txt", "a") as f:
                        f.write(f"RFI detected on '{key}' → {test_url}\n")
    except Exception as e:
        print(f"[!] RFI test failed: {e}")

# ---------- MAIN ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merged Kali Offensive Toolkit + Python Checks")
    parser.add_argument("target", help="Target domain or IP")
    args = parser.parse_args()

    target = args.target
    report_dir = f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(report_dir, exist_ok=True)

    # Kali tools
    run_tool(["nmap", "-sV", "-A", target], f"{report_dir}/nmap.txt")
    run_tool(["sublist3r", "-d", target, "-o", f"{report_dir}/subdomains.txt"], f"{report_dir}/sublist3r.log")
    run_tool(["dnsrecon", "-d", target], f"{report_dir}/dnsrecon.txt")
    run_tool(["sslscan", target], f"{report_dir}/sslscan.txt")
    run_tool(["gobuster", "dir", "-u", f"http://{target}", "-w", "/usr/share/wordlists/dirb/common.txt"], f"{report_dir}/gobuster.txt")
    run_tool(["whois", target], f"{report_dir}/whois.txt")
    run_tool(["sqlmap", "-u", f"http://{target}", "--batch", "--crawl=1"], f"{report_dir}/sqlmap.txt")

    try:
        stealth_request(f"https://{target}")
        full_url = f"https://{target}"
    except Exception:
        full_url = f"http://{target}"

    check_security_headers(full_url, report_dir)
    check_cors(full_url, report_dir)
    check_csrf(full_url, report_dir)
    test_open_redirect(full_url, report_dir)
    test_lfi(full_url, report_dir)
    test_rfi(full_url, report_dir)

    print(f"\n[✓] Full scan completed. Reports saved in {report_dir}")