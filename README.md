<div align="center">

# 🐍 ViperScan

**A fast, threaded network reconnaissance tool for host discovery, banner grabbing, and report generation.**

![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-None-green?style=flat-square)

</div>

---

## 📌 What is ViperScan?

ViperScan is a command-line network recon tool built in pure Python.  
It scans a target IP, domain, or entire subnet — finds open ports, grabs service banners, detects the OS, assigns risk levels, and generates a full HTML + TXT report. All three phases run automatically in sequence with a single command.

---

## ✨ Features

- 🔍 **Host Discovery** — scans 68 common ports per host using parallel threads
- 🎯 **Banner Grabbing** — connects to each open port and tries 15 protocol probes (HTTP, FTP, SSH, SMTP, IMAP, Redis, and more)
- 🖥 **OS Detection** — identifies Linux/Unix, Windows, Cisco IOS from banner keywords
- ⚠️ **Risk Classification** — automatically flags ports as HIGH / MEDIUM / LOW risk
- 📊 **HTML Report** — full dashboard with stat cards, summary tables, risk badges, and per-host details
- 📄 **TXT Report** — plain-text version for terminals, logs, and archives
- 🌐 **3 Scan Modes** — `single`, `multi`, `subnet`
- 🧮 **Subnet Calculator** — supports /8 /16 /24 /32 CIDR masks
- ⚡ **Threaded** — all IPs scanned in parallel, a /24 scan finishes in under 30 seconds on LAN
- 📈 **Live Progress Bar** — single updating line instead of flooding the terminal
- 🔁 **Report-Only Mode** — regenerate reports from existing JSON without rescanning
- 📦 **Zero Dependencies** — standard library only, no pip install needed

---

## 📁 Project Structure

```
ViperScan/
├── main.py                  ← entry point, run this
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
└── Modules/
    ├── __init__.py
    ├── Host_Discovery.py    ← Phase 1: port scanning
    ├── Banner_Scanner.py    ← Phase 2: banner grabbing & OS detection
    └── Report.py            ← Phase 3: HTML + TXT report generation
```

> `Json/` and `Report/` folders are created automatically when you run the tool.

---

## ⚙️ Installation

**1. Clone the repository**
```bash
git clone https://github.com/khalid609/ViperScan.git
cd ViperScan
```

**2. Check Python version** (3.7+ required)
```bash
python --version
```

**3. No pip install needed** — ViperScan uses only the Python standard library.

**4. Verify everything works**
```bash
python -c "from Modules.Host_Discovery import HostDiscovery; from Modules.Banner_Scanner import BannerScanner; from Modules.Report import Report; print('✅ All imports OK')"
```

---

## 🚀 Usage

### Basic Syntax
```bash
python main.py [--ip IP | --domain DOMAIN] [--mode MODE] [OPTIONS]
```

### All Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ip` | str | `""` | Target IPv4 address |
| `--domain` | str | `""` | Target domain — auto-resolved to IP |
| `--mode` | str | `single` | Scan mode: `single` · `multi` · `subnet` |
| `--start` | int | `0` | Last-octet start for `multi` mode |
| `--end` | int | `255` | Last-octet end for `multi` mode |
| `--subnetmask` | int | `—` | CIDR prefix for `subnet` mode: `8` `16` `24` `32` |
| `--timeout` | int | `5` | Banner grab timeout in seconds |
| `--report-only` | flag | off | Skip scanning, rebuild report from existing JSON |

---

## 📖 Examples

**Scan a single IP**
```bash
python main.py --ip 192.168.1.1
```

**Scan a domain**
```bash
python main.py --domain example.com
```

**Scan entire /24 subnet**
```bash
python main.py --ip 192.168.1.1 --mode subnet --subnetmask 24
```

**Scan a custom range (multi mode)**
```bash
python main.py --ip 192.168.1.1 --mode multi --start 1 --end 50
```

**Faster scan with lower timeout**
```bash
python main.py --ip 192.168.1.1 --timeout 2
```

**Regenerate report without rescanning**
```bash
python main.py --report-only
```

---

## 🔄 How It Works

ViperScan runs in 3 automatic phases:

### Phase 1 — Host Discovery
- Resolves domain to IP (if `--domain` used)
- Builds target IP list based on `--mode`
- Launches one thread per IP — all IPs scanned simultaneously
- Checks 68 common ports per IP using TCP `connect_ex()` with 0.5s timeout
- Shows a live progress bar: `[=============>      ] 68%  |  4,624/6,800 checks  |  3 host(s) found`
- Saves open ports to `Json/result.json`

### Phase 2 — Banner Scanning
- Loads hosts from `Json/result.json`
- One thread per host — all run in parallel
- Tries 15 protocol probes per port (HTTP GET, FTP QUIT, SSH handshake, SMTP HELP, etc.)
- Detects service type and OS from banner keywords
- Prints a result block per host as it finishes
- Overwrites `Json/result.json` with enriched data

### Phase 3 — Report Generation
- Reads enriched `Json/result.json`
- Assigns risk level per port (HIGH / MEDIUM / LOW)
- Generates `Report/report_TIMESTAMP.html` — full visual dashboard
- Generates `Report/report_TIMESTAMP.txt` — plain-text version

---

## ⚠️ Risk Levels

| Level | Ports | Reason |
|-------|-------|--------|
| 🔴 **HIGH** | 21, 23, 445, 2375, 3389, 5900-5902, 6379, 11211, 27017 | Unencrypted or commonly exploited |
| 🟡 **MEDIUM** | 22, 25, 80, 110, 143, 1433, 3306, 5432, 8080, 8443, 9200 | Standard services worth reviewing |
| 🟢 **LOW** | All others | Generally safe |

---

## 🔌 Scanned Ports (68 total)

```
20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139,
143, 161, 389, 443, 445, 465, 554, 587, 636, 993, 995, 1433, 1521,
1935, 2049, 2181, 2375, 2376, 2379, 2380, 3000, 3306, 3389, 5000,
5060, 5061, 5222, 5223, 5432, 5672, 5900, 5901, 5902, 5984, 6379,
6443, 8000, 8080, 8081, 8082, 8086, 8443, 8888, 9000, 9042, 9090,
9092, 9200, 9300, 10250, 11211, 15672, 27017
```

---

## 🧪 Quick Test

```bash
# Test your own machine (safest)
python main.py --ip 127.0.0.1

# Test a public DNS server (always legal)
python main.py --ip 8.8.8.8

# Test imports only
python -c "from Modules.Host_Discovery import HostDiscovery; from Modules.Banner_Scanner import BannerScanner; from Modules.Report import Report; print('All OK')"
```

---

## 🔒 Legal Disclaimer

> **Only scan networks and systems you own or have explicit written permission to test.**  
> Unauthorized port scanning may be illegal under computer crime laws in your country.  
> The author accepts no liability for misuse of this tool.

---

## 👤 Author

**khalid609**  
📧 khalid609abu.kaf@gmail.com  
🐙 https://github.com/khalid609

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
