# Cloudflare Malicious IP Auto-Blocker 🚫🌐

> **Automate malicious IP detection and blocking for Cloudflare WAF.**

## Overview
This project scans IP addresses, identifies malicious sources using AbuseIPDB and GraphQL, and automatically updates Cloudflare firewall rules — with logging and email reporting included.

---


## 🔥 Features

- Fetch IPs from Cloudflare WAF using API

- Detect malicious IPs via AbuseIPDB + GraphQL scanning

- Automatically block bad IPs by updating Cloudflare rules

- Email reports to security teams (daily or scheduled)

- Full logging with timestamps and IP history tracking

- Easy scheduling (run via cron or Task Scheduler)
---

## Tech Stack

- Python 3.10+

- Cloudflare API (Firewall Ruleset)

- AbuseIPDB API

- GraphQL API (for IP intelligence)

- SMTP (email reporting)

- dotenv for secret management

- logging module for persistent logs

---

## Setup Instructions
- **Clone this repo**
```
git clone https://github.com/anshahkhan/cloudflare-auto-blocker.git
cd cloudflare-auto-blocker

```
- **Install dependencies**
```
pip install -r requirements.txt

```
- **Add your credentials to .env**
```
CLOUDFLARE_ZONE_ID = yourCloudFlareZoneID
RULESET_ID = RulesetID
RULE_ID = RuleID

ABUSE_API_KEY = AbuseIPDB_API
CLOUDFLARE_API_TOKEN = CF_API_TOKEN

LOOKBACK_HOURS = 24
INPUT_FILE = input.txt
OUTPUT_ALL = ouput.txt
OUTPUT_NOT_BLOCKED = output_non_blocked.txt

SMTP_SERVER = 10.0.0.1
SMTP_PORT = 25
EMAIL_SENDER = youremail@example.com
EMAIL_PASSWORD = password123
EMAIL_IP_FILE = email_ip.txt
```
- **Usage**
```
python main.python
```
---

## Email example
Subject:
```
[Security Alert] 15 IPs Blocked - 2025-08-14

```
Body:
```
Hello,

The following IPs are currently flagged and blocked:

185.225.69.140
195.3.145.99
91.243.113.21

Regards,  
Security Bot 🤖

```
---

## 🧑‍💻 Authors
- Anshah Khan
---

## 📄 License
MIT License. Use freely, modify boldly, and give credit kindly.
---
### “Build tools to empower defenders, not overwhelm them.” — **Anshah Khan**
