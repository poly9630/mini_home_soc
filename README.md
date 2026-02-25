# mini_home_soc

A small Home Network "Mini-SOC" that discovers devices on your local LAN, sniffs packets, provides simple traffic statistics, and serves a lightweight web UI.

Features

- ARP-based device discovery
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
- If you want email alerts, set `ALERT_EMAIL = True` and configure `SMTP_USER` and `SMTP_PASS`.
- The app stores packet logs in `traffic.db`. Add `traffic.db` to `.gitignore` if you don't want to commit it.

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
