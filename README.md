# 🛡️ kArmas_AUTO_OSINT.py
Fully Automated Termux OSINT Framework

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

Made in l0v3 bY kArmasec
