# 🔎 OSINT Recon Tool

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![Security](https://img.shields.io/badge/Field-Cybersecurity-red)
![Status](https://img.shields.io/badge/Project-Active-success)
![License](https://img.shields.io/badge/License-MIT-yellow)

> A Python tool that gathers all possible **public information about a target**.

## 📌 What is OSINT?

**OSINT (Open Source Intelligence)** refers to the process of collecting and analyzing publicly available information from open sources such as websites, DNS records, public databases, and exposed files.

In cybersecurity, OSINT is a critical phase of reconnaissance, allowing analysts and penetration testers to understand a target **without direct interaction or exploitation**.

---

## 🎯 About This Tool

This project is a **modular OSINT reconnaissance tool** designed to automate the information gathering phase of a security assessment.

It combines multiple techniques into a single workflow to provide a **structured and actionable overview of a target domain**, including:

* Infrastructure analysis
* Subdomain discovery
* Web fingerprinting
* Exposure detection
* Human-related OSINT (emails & phones)
* Breach data correlation

The tool is built with a focus on:

* 🔥 Accuracy (false positive reduction)
* ⚡ Efficiency (optimized requests & filtering)
* 🧠 Real-world applicability (pentesting mindset)

---

## 🚀 Features

### 🌐 Domain & Infrastructure

* WHOIS lookup
* DNS records:

  * A
  * MX
  * NS
* IP geolocation (country, ISP, region)

---

### 🧩 Subdomain Enumeration

* Passive enumeration (crt.sh)
* Active enumeration (wordlist-based)

✔ Supports modes:

* `--passive`
* `--active`
* `--all`

---

### 📡 Web Information

* HTTP status
* Server detection (Apache, Nginx, Cloudflare, etc.)
* Basic technology fingerprinting

---

### 📄 Exposed Files Detection

Searches for sensitive files:

* `/robots.txt`
* `/sitemap.xml`
* `/security.txt`
* `/.env`
* backups
* `.git/config`

✔ Smart filtering:

* avoids false positives (redirects)
* ignores HTML fake responses
* detects protected resources (403)

---

### 👤 Emails Extraction

* Domain-based email discovery
* Works on:

  * main domain
  * subdomains
* Multiple paths:

  * `/contact`
  * `/about`
  * `/legal`

---

### 📞 Phone Numbers Extraction

* Context-aware detection (avoids false positives)
* Supports international formats
* Normalization (e.g. +57 Colombia)

---

### 🔐 Leak Detection

* Integration with Have I Been Pwned
* Detects breached emails
* Optional API key support

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/osint-tool.git
cd osint-tool
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python main.py <domain> [--passive | --active | --all]
```

### Examples

```bash
python main.py example.com
python main.py example.com --passive
python main.py example.com --active
python main.py example.com --all
```

---

## ⚙️ Modes Explained

### 🔵 Passive Mode (`--passive`)

* Uses public sources (crt.sh)
* No direct interaction with target

⚠️ **Note:**

* May return `HTTP 502` errors occasionally
* This is normal (crt.sh instability / rate limiting)
* The tool handles retries automatically

---

### 🔴 Active Mode (`--active`)

* Uses wordlist brute-force
* Requires:

```bash
wordlists/subdomains.txt
```

✔ More aggressive
✔ Finds hidden subdomains

---

### 🟣 All Mode (`--all`)

* Combines passive + active
* Recommended for full reconnaissance

---

## 🖥️ Example Output

```text
[+] Target: example.com

[*] Running passive subdomain enumeration...
[*] Running active subdomain enumeration...

[+] RESULTS

[+] DOMAIN
  domain name: EXAMPLE.COM
  registrar: Example Registrar

[+] DNS
  A: ['1.2.3.4']

[+] WEB_INFO
  url:      http://example.com
  status:   200
  server:   cloudflare
  tech:     React, cloudflare

[!] FILES
  Found: 2
  → https://example.com/robots.txt
    200 | text/plain | 500b

[!] EMAILS
  Found: 1
  → admin@example.com

[!] PHONES
  Found: 1
  → +573001234567

[+] LEAKS
  (none)

[+] SUBDOMAINS
  Found: 2
  → www.example.com
  → api.example.com
```

---

## ⚠️ Notes & Limitations

### Subdomain Enumeration

* Passive sources may fail (`502`)
* Not all subdomains are discoverable

---

### Emails / Phones

* Many modern sites:

  * hide data with JavaScript
  * use forms instead of direct exposure

---

### Files Detection

* Protected files (403) are still valuable findings
* Redirects are ignored to avoid false positives

---

### Leaks

* Requires API key for full functionality
* Without API:

  * limited results
  * possible errors

---

## 🔐 API Key (Optional)

For better leak detection:

1. Create an account in Have I Been Pwned
2. Generate an API key
3. Integrate it into the tool

---

## 📁 Project Structure

```bash
.
├── main.py
├── modules
│   ├── domain.py
│   ├── dns.py
│   ├── ip_info.py
│   ├── web_info.py
│   ├── files.py
│   ├── emails.py
│   ├── phones.py
│   ├── leaks.py
│   └── subdomains/
│       ├── passive.py
│       └── active.py
├── wordlists/
│   └── subdomains.txt
├── output/
├── requirements.txt
└── README.md
```

---

## 🧠 Skills Demonstrated

* OSINT methodology
* Web reconnaissance
* Data extraction & filtering
* False positive handling
* Modular Python architecture
* Real-world pentesting logic

---

## ⚖️ Disclaimer

This tool is intended for:

✔ Educational purposes
✔ Authorized security testing

Do NOT use against systems without permission.

---

## 👨‍💻 Author

Julian Camacho
Cybersecurity & Offensive Security
