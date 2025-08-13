# KaliPyReconMate
**Kali Linux + Python hybrid recon and vulnerability scanning toolkit**

KaliPyReconMate is an automation framework that combines popular Kali Linux reconnaissance tools with custom Python vulnerability checks. It streamlines both passive and active scanning into a single workflow and saves results in a timestamped report directory.

> ⚠ **Legal Disclaimer**  
> This tool is for authorized security testing and educational purposes only.  
> Unauthorized use against systems you do not own or have permission to test is illegal.

---

## ✨ Features
- **Kali Tool Integration**
  - Nmap – Service/version detection & OS fingerprinting
  - Sublist3r – Subdomain enumeration
  - Dnsrecon – DNS records mapping
  - SSLScan – SSL/TLS certificate checks
  - Gobuster – Directory brute-forcing
  - WHOIS – Domain registration info
  - SQLMap – Automated SQL injection testing

- **Custom Python Security Checks**
  - Security headers detection
  - CORS misconfiguration checks
  - CSRF token presence detection
  - Open Redirect testing
  - Local File Inclusion (LFI) detection
  - Remote File Inclusion (RFI) detection
  - **Auto-detects HTTPS vs HTTP**

- **Stealth Mode**
  - Randomized delays for Python-based HTTP requests

- **Organized Reporting**
  - All results saved in `scan_<target>_<timestamp>` directory

---

## 🛠 Installation

### Requirements
- Python 3.7+
- Kali Linux (or any system with equivalent tools installed)
- Internet access for external lookups

### Install Dependencies
```bash
# Install Python libraries
pip install requests beautifulsoup4

# Install Kali tools if missing
sudo apt install nmap sublist3r dnsrecon sslscan gobuster whois sqlmap
