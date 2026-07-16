# Mini Home SOC

A home network Security Operations Centre (SOC) dashboard that discovers devices on your LAN, captures live traffic, and presents everything in a dark-theme web UI with real-time charts and AI-driven alerts.

---

## Features

- **ARP device discovery** — scans the local subnet and lists every connected host with hostname, MAC, and open ports
- **Live packet capture** — Scapy-powered sniffer with per-protocol colour coding
- **Bandwidth over time** — line chart showing sent/received bytes per device at 10-second intervals
- **Protocol distribution** — doughnut chart breaking down TCP / UDP / Other traffic in real time
- **GeoIP enrichment** — external IP destinations are resolved to country flag, city, and ISP automatically
- **DNS query log** — captures domain names resolved by every device on the network
- **AI issue detection** — rule-based diagnostics flag port scans, exposed risky services, unusual traffic volumes, and missing gateway
- **Fix-plan guidance** — safe remediation steps for every detected issue, with admin alerts for physical/critical findings
- **SQLite persistence** — packet logs and DNS queries stored locally in `traffic.db`
- **Optional email alerts** — SMTP notifications for critical findings
- **Windows installer** — `install.bat` handles Python, Npcap, dependencies, and a desktop shortcut

---

## Dashboard

The browser UI is served at **http://127.0.0.1:5000** and has five sections:

| Section | What you see |
|---|---|
| **Overview** | Stat tiles, bandwidth chart, protocol chart, latest issues |
| **Devices** | Full device inventory with role, open ports, and traffic totals |
| **Live Traffic** | Real-time packet stream with GeoIP flags, top talkers, stored history |
| **DNS Logs** | Per-device domain resolution log |
| **Alerts** | AI diagnostic report with severity badges and fix guidance |

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.8+ | 3.10+ recommended |
| [Npcap](https://npcap.com/#download) (Windows) | Required for Scapy packet capture; install in WinPcap-compatible mode |
| libpcap / tcpdump (Linux/macOS) | Usually pre-installed |
| Admin / root privileges | Required for raw socket access |

---

## Windows — Quick Install

1. Download or clone this repository.
2. Right-click **`install.bat`** → **Run as administrator**.
3. The installer will:
   - Verify Python is installed (installs via `winget` if missing)
   - Check for Npcap (provides download link if missing)
   - Run `pip install -r requirements.txt`
   - Create **`launch.bat`** and a **Desktop shortcut**
4. Double-click **Mini Home SOC** on the Desktop to launch.

> The app auto-elevates to admin when launched via `launch.bat` — required for Scapy to open raw sockets on Windows.

---

## Linux / macOS — Quick Install

```bash
# Clone
git clone https://github.com/poly9630/mini_home_soc.git
cd mini_home_soc

# Install dependencies
pip3 install -r requirements.txt

# Run (root required for packet sniffing)
sudo python3 mini_home_soc.py
```

Open **http://localhost:5000** in your browser.

---

## Configuration

Edit the constants near the top of `mini_home_soc.py`:

| Variable | Default | Description |
|---|---|---|
| `TARGET_SUBNET` | `192.168.1.0/24` | Your LAN subnet — **change this first** |
| `ALERT_EMAIL` | `False` | Set to `True` to enable email alerts |
| `SMTP_USER` / `SMTP_PASS` | — | Gmail address and App Password for alerts |
| `SERVICE_SCAN_PORTS` | common ports | Ports checked during device discovery |
| `MAX_PACKETS` | `100` | In-memory packet buffer size |

Environment variable overrides (no code edit needed):

| Variable | Description |
|---|---|
| `MINI_SOC_GATEWAY` | Override gateway IP if not the first host in the subnet |
| `MINI_SOC_TRAFFIC_ALERT_BYTES` | Bytes threshold for unusual traffic alert (default `50000000`) |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/devices` | Discovered devices list |
| `POST` | `/api/scan` | Trigger a new ARP scan |
| `GET` | `/api/packets` | Recent packet buffer |
| `GET` | `/api/stats` | Per-IP bandwidth totals |
| `GET` | `/api/logs` | Last 50 packets from SQLite |
| `GET` | `/api/dns-logs` | Recent DNS queries |
| `GET` | `/api/protocol-stats` | TCP / UDP / Other packet counts |
| `GET` | `/api/bandwidth-history` | Time-series bandwidth snapshots (10 s intervals) |
| `GET` | `/api/geoip/<ip>` | GeoIP lookup for an external IP |
| `GET` | `/api/network-map` | Topology nodes and links |
| `GET` | `/api/ai-diagnostics` | Full diagnostic report with issues and network map |
| `GET` | `/api/fix-plan/<issue_id>` | Remediation plan for a specific issue |

---

## Security & Legal

- Only run this tool on networks **you own or have explicit permission to monitor**.
- Packet sniffing and ARP scanning are intrusive by nature — use responsibly.
- GeoIP lookups are sent to [ip-api.com](http://ip-api.com) (free tier, no API key required). External IPs only; private addresses are never sent.
- `traffic.db` contains captured packet metadata — add it to `.gitignore` if you do not want it committed.

---

## License

MIT — see [LICENSE](LICENSE) for details.
