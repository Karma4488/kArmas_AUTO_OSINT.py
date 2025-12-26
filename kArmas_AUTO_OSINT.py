#!/usr/bin/env python3
"""
kArmas AUTO OSINT PLUS
Passive + Active OSINT Automation Framework
Termux 118.3 / Android 16
"""

import os, sys, json, sqlite3, socket, ipaddress, requests, re, ssl
from datetime import datetime
from ipwhois import IPWhois
import dns.resolver
from rich.console import Console
from rich.table import Table

console = Console()
DB = "auto_osint_plus.db"
TIMEOUT = 10

IPINFO = os.getenv("IPINFO_TOKEN")
ABUSE = os.getenv("ABUSEIPDB_KEY")
VT = os.getenv("VT_API_KEY")

# ---------------- DB ----------------
def db_init():
    db = sqlite3.connect(DB)
    db.execute("""CREATE TABLE IF NOT EXISTS results
        (type TEXT, input TEXT, data TEXT, timestamp TEXT)""")
    db.commit()
    return db

def save(db, t, i, d):
    db.execute(
        "INSERT INTO results VALUES (?,?,?,?)",
        (t, i, json.dumps(d), datetime.utcnow().isoformat())
    )
    db.commit()

# ---------------- DETECTION ----------------
def is_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except:
        return False

def is_asn(x):
    return bool(re.match(r"^AS\d+$", x.upper()))

def is_domain(x):
    return "." in x and not is_ip(x)

# ---------------- ACTIVE OSINT ----------------
def dns_lookup(domain):
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(a) for a in answers]
        except:
            records[rtype] = []
    return records

def whois_domain(domain):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT)
        return r.json() if r.ok else {}
    except:
        return {}

def rdap_ip(ip):
    try:
        obj = IPWhois(ip)
        return obj.lookup_rdap(depth=1)
    except:
        return {}

def http_head(domain):
    try:
        r = requests.head(f"https://{domain}", timeout=TIMEOUT, allow_redirects=True)
        return dict(r.headers)
    except:
        return {}

def tls_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=domain
        ) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "issuer": cert.get("issuer"),
                "subject": cert.get("subject"),
                "expires": cert.get("notAfter"),
                "sans": cert.get("subjectAltName")
            }
    except:
        return {}

# ---------------- PASSIVE OSINT ----------------
def vt_domain(domain):
    if not VT: return {}
    r = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VT},
        timeout=TIMEOUT
    )
    return r.json().get("data", {}).get("attributes", {}) if r.ok else {}

def vt_ip_domains(ip):
    if not VT: return []
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
        headers={"x-apikey": VT},
        timeout=TIMEOUT
    )
    if not r.ok: return []
    return list({i["attributes"]["host_name"] for i in r.json().get("data", [])})

def ipinfo(ip):
    if not IPINFO: return {}
    r = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO}", timeout=TIMEOUT)
    return r.json() if r.ok else {}

def abuse(ip):
    if not ABUSE: return {}
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE, "Accept": "application/json"},
        params={"ipAddress": ip},
        timeout=TIMEOUT
    )
    return r.json().get("data", {}) if r.ok else {}

def tor_exit(ip):
    try:
        r = requests.get("https://check.torproject.org/torbulkexitlist", timeout=TIMEOUT)
        return ip in r.text.splitlines()
    except:
        return False

# ---------------- PROCESSORS ----------------
def process_ip(db, ip):
    data = {
        "ip": ip,
        "ipinfo": ipinfo(ip),
        "abuse": abuse(ip),
        "tor": tor_exit(ip),
        "rdap": rdap_ip(ip),
        "domains": vt_ip_domains(ip)
    }
    save(db, "IP", ip, data)
    return data

def process_domain(db, domain):
    data = {
        "domain": domain,
        "dns": dns_lookup(domain),
        "whois": whois_domain(domain),
        "http_headers": http_head(domain),
        "tls_cert": tls_cert(domain),
        "virustotal": vt_domain(domain)
    }
    save(db, "DOMAIN", domain, data)
    return data

# ---------------- OUTPUT ----------------
def render(title, data):
    t = Table(title=title, show_lines=True)
    t.add_column("Key", style="cyan")
    t.add_column("Value", style="white")
    for k, v in data.items():
        t.add_row(k, str(v)[:500])
    console.print(t)

# ---------------- MAIN ----------------
def main():
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python kArmas_AUTO_OSINT_PLUS.py <target|file>")
        sys.exit(1)

    db = db_init()

    targets = []
    if os.path.isfile(sys.argv[1]):
        with open(sys.argv[1]) as f:
            targets = [l.strip() for l in f if l.strip()]
    else:
        targets = [sys.argv[1]]

    for t in targets:
        console.print(f"\n[bold green]▶ AUTO OSINT: {t}[/bold green]")

        if is_ip(t):
            r = process_ip(db, t)
            render("IP OSINT (Passive + Active)", r)

        elif is_domain(t):
            r = process_domain(db, t)
            render("DOMAIN OSINT (Passive + Active)", r)

    with open("auto_osint_plus_export.json", "w") as f:
        json.dump({"targets": targets}, f, indent=2)

    console.print("\n[green]✔ Complete — stored in SQLite + JSON[/green]")

if __name__ == "__main__":
    main()
