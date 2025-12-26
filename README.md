# 🛡️ kArmas AUTO OSINT PLUS
Passive + Active OSINT Automation Framework Termux 118.3 / Android 16.
termux 118.3 is running best from android 9 & up.

📦 Install (once)
Bash
pkg install python -y
pip install requests rich dnspython

🧠 What it does automatically
Automatic actions
IP
IP intel → ASN → domains → TOR → reputation
Domain
Domain intel → resolves IPs → ASN → pivot
ASN
ASN intel → related domains → infra mapping
File
Detects each line type & runs all pivots 🦝

🧠 What This Gives You (Real-World)
🔄 Zero-interaction OSINT
🧠 Smart input detection
🔗 Automatic infra pivoting
🗄️ Long-term investigation DB
📤 Evidence-ready JSON
🔄 Zero-interaction automation
🌐 Passive + Active OSINT
🔗 Infra pivoting (IP ↔ ASN ↔ Domain)
🔐 TLS certificate intelligence
📡 DNS & RDAP enrichment
🗄️ SQLite investigation trail
📱 Mobile-ready on Termux
🛡️ Legally defensible methodology
This is SOC-grade enrichment, not a toy.🚀🔸️🔹️🔹️🔸️
📱 Mobile red-team OSINT from Android

▶️ Run (automatic)
Single target
Bash
python kArmas_AUTO_OSINT.py 8.8.8.8
python kArmas_AUTO_OSINT.py example.com
python kArmas_AUTO_OSINT.py AS15169

🔑 Optional API keys (recommended)
Bash
export IPINFO_TOKEN="..."
export ABUSEIPDB_KEY="..."
export VT_API_KEY="..."

bonus info;
check ip address with curl
curl https ://ipinfo.io/<yourIP>

Made in l0v3 bY kArmasec 🎩🎭🌈
