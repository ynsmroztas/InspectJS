
<div align="center">


<h1>🔍 inspectJS</h1>
<h3>Advanced JavaScript File Discovery and Analysis Tool</h3>

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)
![Theme](https://img.shields.io/badge/Theme-Dark--Terminal-black.svg)

<img src="InspectJS.jpeg" alt="inspectJS Logo" width="420"/>

</div>

---

## 🧠 Overview

`inspectJS` is a **security auditing tool** designed to automatically discover and analyze JavaScript files in web applications.  
It extracts **endpoints**, **API keys**, **tokens**, and potential **client-side vulnerabilities**.

---

## ⚙️ Installation

```bash
git clone https://github.com/ynsmroztas/InspectJS.git
cd inspectjs
pip install -r requirements.txt
python inspectjs.py -u https://example.com
```

---

## 🖥️ Terminal Preview

```
┌─────────────────────────────────────────────────────────────┐
│                 INSPECTJS SECURITY SCANNER                  │
│─────────────────────────────────────────────────────────────│
│ Target: https://example.com                                 │
│ Threads: 10         SSL: Disabled         Depth: 2          │
├─────────────────────────────────────────────────────────────┤
│ [+] Discovered: 8 JS files                                  │
│ [+] Detected API Keys: 3                                   │
│ [+] Endpoints Found: 5                                     │
│ [+] Risk Level: HIGH ⚠️                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧩 Detection Capabilities

```
[CRITICAL] 🔑 API Keys, Secrets, JWT Tokens
[HIGH] 🌐 API Endpoints, Login Routes, Admin Panels
[MEDIUM] 📧 Email Addresses, IPs, Subdomains
[LOW] 🧱 Comments, Debug Statements, Paths
```

---

## 🛠️ Command Examples

```bash
# Save report
python inspectjs.py -u https://target.com -o report.txt

# Multi-threaded scan
python inspectjs.py -u https://target.com -t 10

# Verify SSL
python inspectjs.py -u https://target.com --verify-ssl

# Set depth
python inspectjs.py -u https://target.com -d 3
```

---

## 📊 Sample Output

```
═══════════════════════════════════════════════════════════
🔗 Target: https://example.com
📅 Date: 2024-01-15 14:30:22
📁 JS Files: 8

[CRITICAL] API Key found → "api_key_123456789"
  ↳ Source: https://example.com/app.js
  ↳ Context: const API_KEY = "api_key_123456789";

[ALERT] Endpoint → POST /api/v1/login
  ↳ Parameters: username, password

═══════════════════════════════════════════════════════════
📈 Findings Summary
───────────────────────────────────────────────────────────
  Critical Secrets ......... 3
  HTTP Requests ............ 5
  High-Risk Endpoints ...... 2
  Overall Risk ............. 🔴 HIGH
═══════════════════════════════════════════════════════════
```

---

## 🧰 Use Cases

- 🛡️ **Penetration Testing** – Identify exposed client-side secrets  
- 🪲 **Bug Bounty Hunting** – Automate discovery of key leaks  
- 🧮 **Code Review** – Check for unsafe hardcoded values  
- 🧰 **CI/CD Integration** – Pre-deployment security validation  

---

## ⚠️ Legal Disclaimer

> **inspectJS** must only be used for **authorized testing** and **educational purposes**.  
> Unauthorized scanning or exploitation of systems without permission is **illegal**.

---

## 👨‍💻 Author

**mitsec**  
- 🐦 Twitter: [@ynsmroztas](https://x.com/ynsmroztas)  
- 💻 GitHub: [github.com/ynsmroztas](https://github.com/ynsmroztas)  
- 🌐 Project: [inspectJS](https://github.com/ynsmroztas/InspectJS)

---

<div align="center">
  <sub>© 2025 mitsec — Licensed under the <a href="LICENSE">MIT License</a></sub>
</div>

