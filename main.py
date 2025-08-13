import requests
import json
import csv
import re
from datetime import datetime, timedelta, UTC
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")  


load_dotenv()


# === CONFIGURATION ===
CLOUDFLARE_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
RULESET_ID = os.getenv("RULESET_ID")
RULE_ID = os.getenv("RULE_ID")

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN") #MAKE SURE YOUR API HAS FIREWALL WRITE ACCESS 

LOOKBACK_HOURS = os.getenv("LOOKBACK_HOURS")
INPUT_FILE = os.getenv("INPUT_FILE")
OUTPUT_ALL = os.getenv("OUTPUT_ALL")
OUTPUT_NOT_BLOCKED = os.getenv("OUTPUT_NOT_BLOCKED")

# === EMAIL CONFIG ===
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECIPIENTS = ["example@example.com"]
EMAIL_IP_FILE = os.getenv("EMAIL_IP_FILE")

# === CLOUDFLARE HEADERS ===
cf_url = "https://api.cloudflare.com/client/v4/graphql"
cf_headers = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json"
}

# === TIME RANGE ===
to_timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
from_timestamp = (datetime.now(UTC) - timedelta(hours=LOOKBACK_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")

# === CLOUDFLARE QUERY BUILDER ===         BUILD YOUR OWN QUERY ON api.cloudflare.graphql.com
def build_query(country_filter):
    return f"""
    query TopTrafficIPs($zoneTag: String!) {{
      viewer {{
        zones(filter: {{ zoneTag: $zoneTag }}) {{
          top10TrafficIPs: httpRequestsAdaptiveGroups(
            filter: {{
              datetime_geq: \"{from_timestamp}\",
              datetime_lt: \"{to_timestamp}\",
              AND: [
                {{ clientIP_neq: "0.0.0.0" }} 
                {{ edgeResponseStatus_neq: 403 }}
                {{ userAgent_neq: "#" }}
                {{ userAgent_neq: "#" }}
                {{ xRequestedWith_neq: "#" }}
                {country_filter}
              ]
            }}
            limit: 10
            orderBy: [count_DESC]
          ) {{
            count
            dimensions {{
              clientIP
            }}
          }}
        }}
      }}
    }}
    """

queries = {
    "PK": build_query('{ clientCountryName: "PK" }'),
    "US": build_query('{ clientCountryName: "US" }'),
    "OTHERS": build_query('{ clientCountryName_neq: "US" }, { clientCountryName_neq: "PK" }'),
}

variables = {"zoneTag": CLOUDFLARE_ZONE_ID}

# === STEP 1: FETCH TOP IPs ===
top_ips = set()
print("Fetching top IPs from Cloudflare...")
log_event("Fetching top IPs from Cloudflare...")
for label, query in queries.items():
    print(f"Querying for {label}...")
    cf_response = requests.post(cf_url, headers=cf_headers, json={"query": query, "variables": variables})
    if cf_response.status_code == 200:
        try:
            ip_data = cf_response.json()["data"]["viewer"]["zones"][0]["top10TrafficIPs"]
            for entry in ip_data:
                ip = entry["dimensions"]["clientIP"]
                top_ips.add(ip)
        except Exception as e:
            print(f"⚠️ Error parsing data for {label}: {e}")
            log_event(f"⚠️ Error parsing data for {label}: {e}")
    else:
        print(f"❌ API Error for {label}: {cf_response.status_code}")
        log_event(f"❌ API Error for {label}: {cf_response.status_code}")

with open(INPUT_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    for ip in sorted(top_ips):
        writer.writerow([ip])
print(f"✅ Saved {len(top_ips)} IPs to {INPUT_FILE}")
log_event(f"Saved {len(top_ips)} IPs to {INPUT_FILE}")

# === STEP 2: CHECK IF BLOCKED ===   THIS IS THE SECOND QUERY(YOU CAN ADJUST IT ACCORDING TO YOUR REQUIREMENTS)
graphql_query = """
query CheckBlockedIP($zoneTag: String!, $ip: String!, $from: DateTime!, $to: DateTime!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(             #YOU COULD READ CLOUDFLARE'S API DOCUMENTATION FOR RELATED QUERIES
        limit: 1
        filter: {
          datetime_geq: $from
          datetime_lt: $to
          clientIP: $ip
          action: "block"
        }
      ) {
        action
        clientIP
        datetime
      }
    }
  }
}
"""

def check_ip_blocked(ip):
    variables = {
        "zoneTag": CLOUDFLARE_ZONE_ID,
        "ip": ip,
        "from": from_timestamp,
        "to": to_timestamp
    }
    try:
        response = requests.post(cf_url, headers=cf_headers, json={"query": graphql_query, "variables": variables}, timeout=10)
        data = response.json()
    except Exception as e:
        log_event(f"Request failed: {e}")
        return f"Request failed: {e}"

    if "errors" in data and data["errors"]:
        log_event(f"Error: {data['errors'][0].get('message', 'Unknown error')}")
        return f"Error: {data['errors'][0].get('message', 'Unknown error')}"

    try:
        events = data["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    except (KeyError, TypeError):
        log_event(f"Error: Unexpected data structure")
        return "Error: Unexpected data structure"

    return "Blocked" if events else "Not Blocked"

with open(OUTPUT_ALL, "w", newline="") as all_file, open(OUTPUT_NOT_BLOCKED, "w", newline="") as nb_file:
    writer_all = csv.writer(all_file)
    writer_all.writerow(["IP", "Status"])
    
    for ip in sorted(top_ips):
        status = check_ip_blocked(ip)
        print(f"{ip} -> {status}")
        writer_all.writerow([ip, status])
        if status.lower() == "not blocked":
            nb_file.write(ip + "\n")

print(f"✅ Saved all statuses to {OUTPUT_ALL}")
print(f"✅ Saved not blocked IPs to {OUTPUT_NOT_BLOCKED}")
log_event(f"Saved not blocked IPs to {OUTPUT_NOT_BLOCKED}")

# === STEP 3: CHECK WITH ABUSEIPDB ===
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        country = data["data"]["countryCode"]
        if score >= 40:
            print(f"⚠️ {ip} flagged! Score: {score}, Country: {country}")
            return ip, country, score
        else:
            print(f"✅ {ip} is clean.")
    except Exception as e:
        print(f"❌ Failed to check {ip}: {e}")
        log_event(f"❌ Failed to check {ip}: {e}")
    return None

with open(OUTPUT_NOT_BLOCKED, "r") as f:
    not_blocked_ips = [line.strip() for line in f if line.strip()]

flagged_ips = [res for ip in not_blocked_ips if (res := check_abuseipdb(ip))]

# Save flagged results
flagged_filename = f"{datetime.now().strftime('%Y-%m-%d')}_flagged.csv"
with open(flagged_filename, "w", newline="") as flagged_file:
    writer = csv.writer(flagged_file, delimiter=";")
    writer.writerow(["IP", "Country", "Abuse Confidence Score"])
    for ip, country, score in flagged_ips:
        writer.writerow([ip, country, score])

print(f"Saved flagged IPs to {flagged_filename}")
log_event(f"Saved flagged IPs to {flagged_filename}")

# === STEP 4: BLOCK FLAGGED IPs IN CLOUDFLARE ===   ACCESSING CLOUDFLARE'S SECURITY RULE
def strip_readonly_fields(ruleset):
    readonly_fields = ["last_updated", "phase", "zone_id", "id", "version", "created", "modified_on"]
    for field in readonly_fields:
        ruleset.pop(field, None)
    for rule in ruleset.get("rules", []):
        for key in ["last_updated", "created", "id", "version", "ref"]:
            rule.pop(key, None)
    return ruleset

def extract_existing_ips(expression):
    return set(re.findall(r'ip\.src eq (\d+\.\d+\.\d+\.\d+)', expression))

def block_ip_in_cf_from_file(filename):
    try:
        with open(filename, "r") as f:
            reader = csv.reader(f, delimiter=";")
            next(reader) 
            ips = [row[0] for row in reader if row]
    except Exception as e:
        print(f"❌ Could not read {filename}: {e}")
        log_event(f"❌ Could not read {filename}: {e}")
        return

    if not ips:
        print("No flagged IPs to block.")
        log_event("No flagged IPs to block.")
        return

    ruleset_url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/rulesets/{RULESET_ID}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }

    print("📡 Fetching current ruleset...")
    resp = requests.get(ruleset_url, headers=headers)
    if resp.status_code != 200:
        print(f"❌ Failed to fetch ruleset: {resp.status_code}")
        log_event(f"Failed to fetch ruleset: {resp.status_code}")
        print(resp.text)
        return

    ruleset_data = resp.json()["result"]
    target_rule = None
    for rule in ruleset_data["rules"]:
        if rule.get("id") == RULE_ID:
            target_rule = rule
            break

    if not target_rule:
        print("❌ Could not find the specified rule in ruleset.")
        log_event("Could not find the specified rule in ruleset.")
        return

    existing_ips = extract_existing_ips(target_rule.get("expression", ""))
    combined_ips = sorted(existing_ips.union(ips))
    target_rule["expression"] = " or ".join([f"(ip.src eq {ip})" for ip in combined_ips])

    clean_ruleset = strip_readonly_fields(ruleset_data)

    print("Updating Cloudflare ruleset...")
    log_event(f"Updating Cloudflare ruleset...")
    update_resp = requests.put(ruleset_url, headers=headers, data=json.dumps(clean_ruleset))
    if update_resp.status_code == 200:
        print(f"✅ Successfully appended {len(ips)} new IP(s) to block list (total {len(combined_ips)})")
        log_event(f"Successfully appended {len(ips)} new IP(s) to block list (total {len(combined_ips)})")
    else:
        print(f"❌ Failed to update ruleset: {update_resp.status_code}")
        log_event(f"Failed to update ruleset: {update_resp.status_code}")
        print(update_resp.text)

# Run blocking
block_ip_in_cf_from_file(flagged_filename)

def load_ips_from_file(file_path):
    """Load IP addresses from a file."""
    try:
        with open(file_path, "r") as f:
            ips = [line.strip() for line in f if line.strip()]
        return ips
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        log_event(f"Email File not found: {file_path}")
        return []

def send_blocked_ips_email(blocked_ips, total_count):
    """Send an email listing blocked IPs."""
    if not blocked_ips:
        print("📭 No IPs to email.")
        log_event("No IPs to email.")
        return

    subject = f"[Security Alert] {total_count} IPs Blocked - {datetime.now().strftime('%Y-%m-%d')}"
    body = "To whom it may be concerned,\n\nThe following IPs are currently flagged and blocked:\n\n"
    body += "\n".join(blocked_ips)
    body += "\n\nRegards,\nShahBot 🤖"

    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = ", ".join(EMAIL_RECIPIENTS)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        print("📤 Sending email...")
        log_event("Sending email...")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # server.starttls()  YOU CAN ADD TLS
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENTS, msg.as_string())
        print("✅ Email sent successfully.")
        log_event("Email sent successfully.")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        log_event(f"Failed to send email: {e}")

# Run Email
EMAIL_IP_FILE = f"{datetime.now().strftime('%Y-%m-%d')}_flagged.csv"
ips_to_send = load_ips_from_file(EMAIL_IP_FILE)
send_blocked_ips_email(ips_to_send, len(ips_to_send))