# mini_home_soc

A small Home Network "Mini-SOC" that discovers devices on your local LAN, sniffs packets, provides simple traffic statistics, and serves a lightweight web UI.

Features

- ARP-based device discovery
- Visual topology map for easier network visibility
- AI-assisted issue detection using discovery, traffic, service, and port-scan evidence
- Fix-plan guidance for logical/security issues and admin alerts for likely physical issues
- Live packet capture (Scapy) with a browser UI (Flask)
- Simple port-scan alerting and optional email alerts
- Stores recent packets into a local SQLite database

Prerequisites

- Linux (recommended) with Python 3.8+
- Root privileges to run packet sniffing (run with `sudo`)
- `pip` for installing Python dependencies

Quick install

1. Change into the project directory:

```bash
cd /home/code
```

2. Create a virtual environment (recommended) and activate it:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

Run

Run the application (requires root for packet sniffing):

```bash
sudo python3 mini_home_soc.py
```

Open your browser at http://localhost:5000

Notes and configuration

- Edit `mini_home_soc.py` to set `TARGET_SUBNET` to match your LAN.
- Set `MINI_SOC_GATEWAY` if your gateway is not the first usable address in the subnet.
- Set `MINI_SOC_TRAFFIC_ALERT_BYTES` to tune unusual traffic alerts. The default is `50000000`.
- If you want email alerts, set `ALERT_EMAIL = True` and configure `SMTP_USER` and `SMTP_PASS`.
- AI diagnostics reuse the same email alert helper. Critical security findings and likely physical issues alert the admin once per issue.
- The app stores packet logs in `traffic.db`. Add `traffic.db` to `.gitignore` if you don't want to commit it.

AI diagnostics API

- `GET /api/network-map` returns nodes and links for the topology map.
- `GET /api/ai-diagnostics` returns the issue summary, findings, fix guidance, and network map.
- `GET /api/fix-plan/<issue_id>` returns the suggested safe remediation plan for a finding.

Initialize a GitHub repository and push (optional)

If you have the GitHub CLI (`gh`) configured locally you can create and push a public repo with:

```bash
gh repo create <USERNAME>/<REPO> --public --source=. --remote=origin --push
```

Or create a repo on GitHub and push:

```bash
git remote add origin git@github.com:USERNAME/REPO.git
git branch -M main
git push -u origin main
```

Security & permissions

- Packet sniffing and ARP scanning require elevated privileges — run carefully and only on networks you own or have permission to scan.

License

This project is provided under the MIT License. See LICENSE for details.
