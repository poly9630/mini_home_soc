#!/usr/bin/env python3
import threading
import time
import logging
import sqlite3
import smtplib
import queue
import ipaddress
from email.mime.text import MIMEText
from collections import deque

try:
    from flask import Flask, jsonify, render_template_string, request
    import requests as http_requests
except Exception as e:
    import sys
    print("[ERROR] Failed to import required packages: {}".format(e))
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS
except Exception as e:
    import sys
    print("[ERROR] Failed to import Scapy: {}".format(e))
    print("Ensure Npcap is installed and you are running as Administrator.")
    sys.exit(1)

import socket
from ai_diagnostics import analyze_network, build_network_map

# --- Configuration ---
TARGET_SUBNET = "192.168.1.0/24"
MAX_PACKETS = 100
PACKET_SNIFFER_FILTER = "not port 5000"
SERVICE_SCAN_PORTS = [22, 23, 80, 443, 445, 3389, 5900, 8080]

ALERT_EMAIL = False
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USER = 'your_email@gmail.com'
SMTP_PASS = 'your_app_password'

# --- Global Data ---
detected_devices = []
packet_buffer = []
traffic_stats = {}
is_sniffing = True
recent_ports = {}
last_ai_report = {"summary": "No diagnostics have run yet.", "issues": [], "network_map": {}}
alerted_issue_ids = set()

dns_log = deque(maxlen=500)
bandwidth_history = deque(maxlen=60)  # 60 × 10s = 10 minutes of history
protocol_counts = {'TCP': 0, 'UDP': 0, 'Other': 0}
geoip_cache = {}
geoip_lookup_queue = queue.Queue(maxsize=200)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Database Setup ---
conn = sqlite3.connect('traffic.db', check_same_thread=False)
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS packet_logs (
    time TEXT, src_ip TEXT, dst_ip TEXT,
    protocol TEXT, length INTEGER, service TEXT
)''')

c.execute('''
CREATE TABLE IF NOT EXISTS dns_logs (
    time TEXT, src_ip TEXT, domain TEXT
)''')

conn.commit()

# --- Flask App ---
app = Flask(__name__)


# --- Helpers ---

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def send_alert_email(subject, body):
    if not ALERT_EMAIL:
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = SMTP_USER
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        print("[ERROR] Email failed: {}".format(e))


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def scan_open_ports(ip):
    open_ports = []
    for port in SERVICE_SCAN_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        finally:
            sock.close()
    return open_ports


# --- GeoIP Worker ---

def geoip_worker():
    while True:
        try:
            ip = geoip_lookup_queue.get(timeout=5)
        except queue.Empty:
            continue
        if ip in geoip_cache:
            geoip_lookup_queue.task_done()
            continue
        try:
            resp = http_requests.get(
                'http://ip-api.com/json/{}?fields=status,country,countryCode,city,isp'.format(ip),
                timeout=4
            )
            data = resp.json()
            if data.get('status') == 'success':
                geoip_cache[ip] = {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', '')
                }
            else:
                geoip_cache[ip] = None
        except Exception:
            geoip_cache[ip] = None
        geoip_lookup_queue.task_done()
        time.sleep(1.4)  # stay under ip-api.com 45 req/min free limit


# --- Bandwidth Snapshot Thread ---

def snapshot_bandwidth():
    while True:
        time.sleep(10)
        bandwidth_history.append({
            'timestamp': time.strftime('%H:%M:%S'),
            'stats': {ip: {'sent': s['sent'], 'received': s['received']}
                      for ip, s in traffic_stats.items()}
        })


# --- Device Discovery ---

def scan_network():
    global detected_devices
    print("Scanning network: {}...".format(TARGET_SUBNET))
    arp = ARP(pdst=TARGET_SUBNET)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': get_hostname(received.psrc),
            'open_ports': scan_open_ports(received.psrc)
        })
    detected_devices = devices
    print("Scan complete. Found {} devices.".format(len(devices)))


# --- Packet Capture ---

COMMON_PORTS = {
    80: "HTTP", 443: "HTTPS", 22: "SSH",
    53: "DNS", 3389: "RDP", 8080: "HTTP-alt"
}


def packet_callback(packet):
    global packet_buffer, traffic_stats, recent_ports, protocol_counts

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    length = len(packet)

    if packet.haslayer(TCP):
        protocol_name = "TCP"
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol_name = "UDP"
        dport = packet[UDP].dport
    else:
        protocol_name = "Other"
        dport = "-"

    service = COMMON_PORTS.get(dport, "Unknown:{}".format(dport)) if isinstance(dport, int) else "Other"

    pkt_data = {
        'timestamp': time.strftime('%H:%M:%S'),
        'src': src_ip, 'dst': dst_ip,
        'protocol': protocol_name,
        'length': length, 'service': service
    }

    packet_buffer.insert(0, pkt_data)
    if len(packet_buffer) > MAX_PACKETS:
        packet_buffer.pop()

    # Protocol counts
    if protocol_name in protocol_counts:
        protocol_counts[protocol_name] += 1
    else:
        protocol_counts['Other'] += 1

    # Bandwidth stats
    traffic_stats.setdefault(src_ip, {'sent': 0, 'received': 0})
    traffic_stats.setdefault(dst_ip, {'sent': 0, 'received': 0})
    traffic_stats[src_ip]['sent'] += length
    traffic_stats[dst_ip]['received'] += length

    # GeoIP async lookup for external destinations
    if not is_private_ip(dst_ip) and dst_ip not in geoip_cache:
        try:
            geoip_lookup_queue.put_nowait(dst_ip)
        except queue.Full:
            pass

    # DNS query detection
    if packet.haslayer(DNS):
        try:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and dns_layer.qdcount > 0 and dns_layer.qd:
                qname = dns_layer.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                entry = {'timestamp': time.strftime('%H:%M:%S'), 'src': src_ip, 'domain': qname}
                dns_log.appendleft(entry)
                c.execute("INSERT INTO dns_logs (time, src_ip, domain) VALUES (?, ?, ?)",
                          (entry['timestamp'], src_ip, qname))
                conn.commit()
        except Exception:
            pass

    # Persist packet
    c.execute("INSERT INTO packet_logs (time, src_ip, dst_ip, protocol, length, service) VALUES (?, ?, ?, ?, ?, ?)",
              (pkt_data['timestamp'], src_ip, dst_ip, protocol_name, length, service))
    conn.commit()

    # Port scan detection
    current_time = time.time()
    if src_ip not in recent_ports:
        recent_ports[src_ip] = []
    if isinstance(dport, int):
        recent_ports[src_ip].append((dport, current_time))
        recent_ports[src_ip] = [(p, t) for p, t in recent_ports[src_ip] if (current_time - t) <= 10]
        if len(set(p for p, _ in recent_ports[src_ip])) > 10:
            msg = "[ALERT] Port scan from {}: multiple ports in 10s window.".format(src_ip)
            print(msg)
            send_alert_email("Port Scan Detected", msg)


def start_sniffer():
    print("[INFO] Starting packet sniffer...")
    sniff(prn=packet_callback, filter=PACKET_SNIFFER_FILTER, store=False)


# --- API Routes ---

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/devices')
def get_devices():
    return jsonify(detected_devices)


@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    threading.Thread(target=scan_network, daemon=True).start()
    return jsonify({"status": "Scanning started"})


@app.route('/api/packets')
def get_packets():
    return jsonify(packet_buffer)


@app.route('/api/stats')
def get_stats():
    return jsonify(traffic_stats)


@app.route('/api/logs')
def get_logs():
    c.execute("SELECT * FROM packet_logs ORDER BY rowid DESC LIMIT 50")
    rows = c.fetchall()
    return jsonify([{'time': r[0], 'src': r[1], 'dst': r[2],
                     'protocol': r[3], 'length': r[4], 'service': r[5]} for r in rows])


@app.route('/api/dns-logs')
def get_dns_logs():
    return jsonify(list(dns_log))


@app.route('/api/protocol-stats')
def get_protocol_stats():
    return jsonify(protocol_counts)


@app.route('/api/bandwidth-history')
def get_bandwidth_history():
    snapshots = list(bandwidth_history)
    if len(snapshots) < 2:
        return jsonify({'labels': [], 'series': []})

    labels = [s['timestamp'] for s in snapshots[1:]]
    all_ips = set()
    for s in snapshots:
        all_ips.update(s['stats'].keys())

    series = []
    for ip in all_ips:
        sent_d, recv_d = [], []
        for i in range(1, len(snapshots)):
            prev = snapshots[i-1]['stats'].get(ip, {'sent': 0, 'received': 0})
            curr = snapshots[i]['stats'].get(ip, {'sent': 0, 'received': 0})
            sent_d.append(max(0, curr['sent'] - prev['sent']))
            recv_d.append(max(0, curr['received'] - prev['received']))
        total = sum(sent_d) + sum(recv_d)
        series.append({'ip': ip, 'sent': sent_d, 'received': recv_d, '_total': total})

    series.sort(key=lambda x: x['_total'], reverse=True)
    for s in series:
        del s['_total']

    return jsonify({'labels': labels, 'series': series[:5]})


@app.route('/api/geoip/<ip>')
def get_geoip(ip):
    if ip in geoip_cache:
        return jsonify(geoip_cache[ip] or {})
    if is_private_ip(ip):
        return jsonify({})
    try:
        geoip_lookup_queue.put_nowait(ip)
    except queue.Full:
        pass
    return jsonify({'pending': True})


@app.route('/api/network-map')
def get_network_map():
    return jsonify(build_network_map(detected_devices, TARGET_SUBNET, traffic_stats))


@app.route('/api/ai-diagnostics')
def get_ai_diagnostics():
    global last_ai_report, alerted_issue_ids
    last_ai_report = analyze_network(detected_devices, traffic_stats, recent_ports, TARGET_SUBNET)
    for issue in last_ai_report["issues"]:
        if issue["admin_alert"] and issue["id"] not in alerted_issue_ids:
            send_alert_email(
                subject="Mini Home SOC Alert: {}".format(issue["title"]),
                body="{}\n\nAffected: {}\nEvidence: {}\nRecommendation: {}".format(
                    last_ai_report["summary"],
                    issue["affected_device"] or "Network-wide",
                    "; ".join(issue["evidence"]),
                    issue["recommendation"],
                ),
            )
            alerted_issue_ids.add(issue["id"])
    return jsonify(last_ai_report)


@app.route('/api/fix-plan/<issue_id>')
def get_fix_plan(issue_id):
    report = analyze_network(detected_devices, traffic_stats, recent_ports, TARGET_SUBNET)
    for issue in report["issues"]:
        if issue["id"] == issue_id:
            return jsonify({
                "issue_id": issue_id,
                "can_auto_fix": bool(issue.get("auto_fix")) and issue["category"] != "physical",
                "plan": issue.get("auto_fix") or issue["recommendation"],
                "requires_admin": issue["admin_alert"],
            })
    return jsonify({"error": "Issue not found"}), 404


# --- Dashboard HTML ---

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mini Home SOC</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg: #0d1117; --card: #161b22; --sidebar: #0d1117;
  --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
  --accent: #58a6ff; --green: #3fb950; --yellow: #d29922;
  --red: #f85149; --purple: #a371f7; --sw: 230px;
}
* { box-sizing: border-box; }
body { background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; margin:0; display:flex; min-height:100vh; }
/* Sidebar */
.sidebar { width:var(--sw); background:var(--sidebar); border-right:1px solid var(--border); min-height:100vh; position:fixed; top:0; left:0; z-index:100; display:flex; flex-direction:column; }
.sb-brand { padding:18px 16px; border-bottom:1px solid var(--border); }
.sb-brand .logo { font-size:0.7rem; font-weight:700; letter-spacing:.15em; text-transform:uppercase; color:var(--accent); }
.sb-brand .appname { font-size:1rem; font-weight:700; color:var(--text); margin-top:4px; }
.live-dot { width:7px; height:7px; border-radius:50%; background:var(--green); display:inline-block; margin-right:5px; animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.sb-nav { padding:10px 0; flex:1; }
.nb { display:flex; align-items:center; width:100%; padding:10px 18px; background:none; border:none; color:var(--muted); font-size:.85rem; cursor:pointer; text-align:left; gap:10px; transition:.15s; border-left:3px solid transparent; }
.nb:hover { background:rgba(88,166,255,.07); color:var(--text); }
.nb.active { color:var(--accent); border-left-color:var(--accent); background:rgba(88,166,255,.1); }
.nb i { width:18px; font-size:.95rem; }
.sb-footer { padding:12px 16px; border-top:1px solid var(--border); font-size:.7rem; color:var(--muted); }
/* Main */
.main { margin-left:var(--sw); flex:1; padding:24px; }
.section { display:none; } .section.active { display:block; }
/* Page header */
.ph h4 { font-size:1.05rem; font-weight:700; margin:0 0 3px; }
.ph p { font-size:.78rem; color:var(--muted); margin:0 0 20px; }
/* Cards */
.sc { background:var(--card); border:1px solid var(--border); border-radius:8px; margin-bottom:18px; }
.sc-hd { padding:12px 18px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
.sc-hd h6 { margin:0; font-size:.83rem; font-weight:600; }
.sc-bd { padding:16px 18px; }
.sc-bd.p0 { padding:0; }
/* Stat tiles */
.tile { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:18px 16px; }
.tile .val { font-size:1.8rem; font-weight:700; color:var(--accent); line-height:1.1; }
.tile .lbl { font-size:.68rem; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; margin-top:5px; }
/* Tables */
.tbl { width:100%; font-size:.78rem; border-collapse:collapse; }
.tbl th { color:var(--muted); font-weight:500; text-transform:uppercase; font-size:.67rem; letter-spacing:.08em; padding:8px 10px; border-bottom:1px solid var(--border); text-align:left; position:sticky; top:0; background:var(--card); z-index:1; }
.tbl td { padding:6px 10px; border-bottom:1px solid rgba(48,54,61,.5); font-family:'Consolas','SF Mono',monospace; }
.tbl tr:hover td { background:rgba(88,166,255,.04); }
.sb { max-height:280px; overflow-y:auto; }
.sb::-webkit-scrollbar { width:3px; } .sb::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
/* Pills */
.pill { display:inline-block; padding:2px 8px; border-radius:10px; font-size:.68rem; font-weight:500; }
.p-tcp { background:rgba(63,185,80,.15); color:var(--green); }
.p-udp { background:rgba(88,166,255,.15); color:var(--accent); }
.p-other { background:rgba(139,148,158,.15); color:var(--muted); }
.p-critical,.p-red { background:rgba(248,81,73,.15); color:var(--red); }
.p-warning,.p-yellow { background:rgba(210,153,34,.15); color:var(--yellow); }
.p-info,.p-blue { background:rgba(88,166,255,.15); color:var(--accent); }
.p-security { background:rgba(163,113,247,.15); color:var(--purple); }
.p-physical { background:rgba(248,81,73,.15); color:var(--red); }
.p-logical { background:rgba(88,166,255,.15); color:var(--accent); }
.p-endpoint { background:rgba(63,185,80,.15); color:var(--green); }
.p-gateway { background:rgba(210,153,34,.15); color:var(--yellow); }
/* Issue cards */
.ic { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:12px 14px; margin-bottom:8px; }
.ic.critical { border-left:3px solid var(--red); }
.ic.warning { border-left:3px solid var(--yellow); }
.ic.info { border-left:3px solid var(--accent); }
/* Buttons */
.btn-soc { background:rgba(88,166,255,.1); border:1px solid rgba(88,166,255,.3); color:var(--accent); padding:5px 14px; border-radius:6px; font-size:.78rem; cursor:pointer; transition:.15s; }
.btn-soc:hover { background:rgba(88,166,255,.2); }
.btn-danger-soc { background:rgba(248,81,73,.1); border:1px solid rgba(248,81,73,.3); color:var(--red); padding:5px 14px; border-radius:6px; font-size:.78rem; cursor:pointer; }
/* Input */
.soc-in { background:var(--bg); border:1px solid var(--border); color:var(--text); padding:5px 12px; border-radius:6px; font-size:.78rem; width:180px; }
.soc-in:focus { outline:none; border-color:var(--accent); }
.soc-in::placeholder { color:var(--muted); }
/* Charts */
.chart-box { position:relative; height:210px; }
/* Geo */
.flag { font-size:.9rem; }
.ext { color:var(--yellow); font-size:.65rem; font-weight:600; }
</style>
</head>
<body>
<div class="sidebar">
  <div class="sb-brand">
    <div class="logo"><span class="live-dot"></span>Live Monitor</div>
    <div class="appname">Mini Home SOC</div>
  </div>
  <nav class="sb-nav">
    <button class="nb active" onclick="nav('overview',this)"><i class="bi bi-grid-fill"></i>Overview</button>
    <button class="nb" onclick="nav('devices',this)"><i class="bi bi-hdd-network-fill"></i>Devices</button>
    <button class="nb" onclick="nav('traffic',this)"><i class="bi bi-activity"></i>Live Traffic</button>
    <button class="nb" onclick="nav('dns',this)"><i class="bi bi-diagram-3-fill"></i>DNS Logs</button>
    <button class="nb" onclick="nav('alerts',this)">
      <i class="bi bi-shield-exclamation"></i>Alerts
      <span id="alert-badge" class="pill p-red ms-auto" style="display:none">0</span>
    </button>
  </nav>
  <div class="sb-footer">v2.0 &nbsp;&middot;&nbsp; updated <span id="upd-time">--</span></div>
</div>

<div class="main">

<!-- OVERVIEW -->
<div id="s-overview" class="section active">
  <div class="ph"><h4><i class="bi bi-grid-fill" style="color:var(--accent)"></i> &nbsp;Overview</h4><p>Live summary of your home network security posture</p></div>
  <div class="row g-3 mb-3">
    <div class="col-6 col-md-3"><div class="tile"><div class="val" id="st-devices">0</div><div class="lbl">Devices</div></div></div>
    <div class="col-6 col-md-3"><div class="tile"><div class="val" id="st-packets">0</div><div class="lbl">Packets Seen</div></div></div>
    <div class="col-6 col-md-3"><div class="tile"><div class="val" id="st-alerts" style="color:var(--red)">0</div><div class="lbl">Active Alerts</div></div></div>
    <div class="col-6 col-md-3"><div class="tile"><div class="val" id="st-traffic">0 B</div><div class="lbl">Total Traffic</div></div></div>
  </div>
  <div class="row g-3 mb-3">
    <div class="col-md-8">
      <div class="sc">
        <div class="sc-hd"><h6><i class="bi bi-graph-up" style="color:var(--accent)"></i> &nbsp;Bandwidth Over Time</h6><span style="font-size:.7rem;color:var(--muted)">10 s intervals &middot; top 5 IPs</span></div>
        <div class="sc-bd"><div class="chart-box"><canvas id="chart-bw"></canvas></div></div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="sc">
        <div class="sc-hd"><h6><i class="bi bi-pie-chart-fill" style="color:var(--accent)"></i> &nbsp;Protocol Mix</h6></div>
        <div class="sc-bd"><div class="chart-box"><canvas id="chart-proto"></canvas></div></div>
      </div>
    </div>
  </div>
  <div class="sc">
    <div class="sc-hd"><h6><i class="bi bi-exclamation-triangle-fill" style="color:var(--yellow)"></i> &nbsp;Latest Issues</h6><button class="btn-soc" onclick="runDiag()"><i class="bi bi-arrow-clockwise"></i> Run Diagnostics</button></div>
    <div class="sc-bd" id="ov-issues"><span style="color:var(--muted);font-size:.83rem">Click "Run Diagnostics" to analyse the network.</span></div>
  </div>
</div>

<!-- DEVICES -->
<div id="s-devices" class="section">
  <div class="ph"><h4><i class="bi bi-hdd-network-fill" style="color:var(--accent)"></i> &nbsp;Connected Devices</h4><p>Hosts discovered via ARP scan on the local subnet</p></div>
  <div class="sc">
    <div class="sc-hd"><h6>Device Inventory</h6><button class="btn-soc" onclick="triggerScan()"><i class="bi bi-radar"></i> ARP Scan</button></div>
    <div class="sc-bd p0"><div class="sb" style="max-height:520px">
      <table class="tbl">
        <thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Role</th><th>Open Ports</th><th>Traffic</th></tr></thead>
        <tbody id="device-table"><tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">Click ARP Scan to discover devices.</td></tr></tbody>
      </table>
    </div></div>
  </div>
</div>

<!-- TRAFFIC -->
<div id="s-traffic" class="section">
  <div class="ph"><h4><i class="bi bi-activity" style="color:var(--accent)"></i> &nbsp;Live Traffic</h4><p>Real-time packet capture with GeoIP enrichment</p></div>
  <div class="row g-3 mb-3">
    <div class="col-md-8">
      <div class="sc">
        <div class="sc-hd"><h6>Packet Stream</h6><input type="text" id="filterInput" class="soc-in" placeholder="Filter by IP..."></div>
        <div class="sc-bd p0"><div class="sb">
          <table class="tbl">
            <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Service</th><th>Bytes</th><th>Geo</th></tr></thead>
            <tbody id="packet-table"></tbody>
          </table>
        </div></div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="sc">
        <div class="sc-hd"><h6>Top Talkers</h6></div>
        <div class="sc-bd p0"><div class="sb" style="max-height:280px">
          <table class="tbl">
            <thead><tr><th>IP</th><th>Sent</th><th>Recv</th></tr></thead>
            <tbody id="traffic-table"></tbody>
          </table>
        </div></div>
      </div>
    </div>
  </div>
  <div class="sc">
    <div class="sc-hd"><h6><i class="bi bi-database-fill" style="color:var(--accent)"></i> &nbsp;Stored Packet History</h6><span style="font-size:.7rem;color:var(--muted)">Last 50 from SQLite</span></div>
    <div class="sc-bd p0"><div class="sb">
      <table class="tbl">
        <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Service</th><th>Bytes</th></tr></thead>
        <tbody id="log-table"></tbody>
      </table>
    </div></div>
  </div>
</div>

<!-- DNS LOGS -->
<div id="s-dns" class="section">
  <div class="ph"><h4><i class="bi bi-diagram-3-fill" style="color:var(--accent)"></i> &nbsp;DNS Query Log</h4><p>Domain names resolved by devices on your network</p></div>
  <div class="sc">
    <div class="sc-hd"><h6>Recent Queries</h6><span style="font-size:.7rem;color:var(--muted)" id="dns-count">0 entries</span></div>
    <div class="sc-bd p0"><div class="sb" style="max-height:600px">
      <table class="tbl">
        <thead><tr><th>Time</th><th>Source IP</th><th>Domain</th></tr></thead>
        <tbody id="dns-table"><tr><td colspan="3" style="text-align:center;color:var(--muted);padding:24px">Waiting for DNS traffic...</td></tr></tbody>
      </table>
    </div></div>
  </div>
</div>

<!-- ALERTS -->
<div id="s-alerts" class="section">
  <div class="ph"><h4><i class="bi bi-shield-fill-exclamation" style="color:var(--red)"></i> &nbsp;Security Alerts</h4><p>AI-driven issue detection and remediation guidance</p></div>
  <div class="sc">
    <div class="sc-hd"><h6>Diagnostic Report</h6><button class="btn-soc" onclick="runDiag()"><i class="bi bi-arrow-clockwise"></i> Run Diagnostics</button></div>
    <div class="sc-bd">
      <p id="ai-summary" style="color:var(--muted);font-size:.83rem;margin-bottom:14px">Diagnostics have not run yet.</p>
      <div id="ai-issues"></div>
    </div>
  </div>
</div>

</div><!-- .main -->

<script>
// ---- Nav ----
function nav(name, btn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b => b.classList.remove('active'));
  document.getElementById('s-' + name).classList.add('active');
  btn.classList.add('active');
}

// ---- Utils ----
function fmtBytes(b) {
  b = b || 0;
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}
function pill(txt, cls) { return '<span class="pill ' + cls + '">' + txt + '</span>'; }
function isPrivate(ip) { return /^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)/.test(ip); }
function flag(code) {
  if (!code || code.length !== 2) return '';
  try { return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E0 + c.charCodeAt(0) - 65)); }
  catch(e) { return ''; }
}

// ---- Charts ----
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
const COLORS = ['#58a6ff','#3fb950','#d29922','#f85149','#a371f7','#79c0ff'];

const bwChart = new Chart(document.getElementById('chart-bw').getContext('2d'), {
  type: 'line',
  data: { labels: [], datasets: [] },
  options: {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { legend: { position: 'top', labels: { boxWidth: 8, font: { size: 9 } } } },
    scales: {
      x: { grid: { color: '#21262d' }, ticks: { font: { size: 9 }, maxTicksLimit: 8 } },
      y: { grid: { color: '#21262d' }, ticks: { font: { size: 9 }, callback: v => fmtBytes(v) } }
    }
  }
});

const protoChart = new Chart(document.getElementById('chart-proto').getContext('2d'), {
  type: 'doughnut',
  data: { labels: ['TCP','UDP','Other'], datasets: [{ data: [0,0,0], backgroundColor: ['#3fb950','#58a6ff','#8b949e'], borderWidth: 0, hoverOffset: 4 }] },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, font: { size: 10 } } } } }
});

function updateBwChart(data) {
  if (!data.labels || !data.labels.length) return;
  const series = (data.series || []).slice(0, 3);
  bwChart.data.labels = data.labels;
  bwChart.data.datasets = series.flatMap((s, i) => [
    { label: s.ip + ' ↑', data: s.sent, borderColor: COLORS[i*2 % COLORS.length], backgroundColor: 'transparent', borderWidth: 1.5, pointRadius: 0, tension: .3 },
    { label: s.ip + ' ↓', data: s.received, borderColor: COLORS[(i*2+1) % COLORS.length], backgroundColor: 'transparent', borderWidth: 1.5, pointRadius: 0, tension: .3, borderDash: [5,3] }
  ]);
  bwChart.update();
}

// ---- Data fetching ----
let statsData = {};
let geoCache = {};

function triggerScan() {
  fetch('/api/scan', { method: 'POST' });
}

function fetchDevices() {
  fetch('/api/devices').then(r => r.json()).then(data => {
    document.getElementById('st-devices').textContent = data.length;
    const tb = document.getElementById('device-table');
    if (!data.length) { tb.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">No devices found. Click ARP Scan.</td></tr>'; return; }
    tb.innerHTML = data.map(d => {
      const traffic = statsData[d.ip] ? (statsData[d.ip].sent + statsData[d.ip].received) : 0;
      const role = d.role || 'endpoint';
      return '<tr><td>' + d.ip + '</td><td style="color:var(--muted)">' + d.mac + '</td>' +
        '<td>' + (d.hostname !== 'Unknown' ? d.hostname : '<span style="color:var(--muted)">—</span>') + '</td>' +
        '<td>' + pill(role, 'p-' + role) + '</td>' +
        '<td>' + ((d.open_ports || []).map(p => pill(p, 'p-yellow')).join(' ') || '<span style="color:var(--muted)">none</span>') + '</td>' +
        '<td style="color:var(--muted)">' + fmtBytes(traffic) + '</td></tr>';
    }).join('');
  });
}

function fetchStats() {
  fetch('/api/stats').then(r => r.json()).then(data => {
    statsData = data;
    const entries = Object.entries(data).sort((a,b) => (b[1].sent+b[1].received) - (a[1].sent+a[1].received));
    const total = entries.reduce((s,[,v]) => s + v.sent + v.received, 0);
    document.getElementById('st-traffic').textContent = fmtBytes(total);
    document.getElementById('traffic-table').innerHTML = entries.slice(0,10).map(([ip,s]) =>
      '<tr><td>' + ip + '</td><td style="color:var(--green)">' + fmtBytes(s.sent) + '</td><td style="color:var(--accent)">' + fmtBytes(s.received) + '</td></tr>'
    ).join('');
  });
}

function fetchPackets() {
  fetch('/api/packets').then(r => r.json()).then(data => {
    document.getElementById('st-packets').textContent = data.length;
    const filter = document.getElementById('filterInput').value;
    const rows = filter ? data.filter(p => p.src.includes(filter) || p.dst.includes(filter)) : data;
    const extIPs = [...new Set(rows.map(p => p.dst).filter(ip => ip && !isPrivate(ip) && !geoCache[ip]))].slice(0, 8);
    extIPs.forEach(ip => fetch('/api/geoip/' + ip).then(r => r.json()).then(d => { if (d && d.country) geoCache[ip] = d; }));
    document.getElementById('packet-table').innerHTML = rows.map(p => {
      const proto = p.protocol === 'TCP' ? 'p-tcp' : p.protocol === 'UDP' ? 'p-udp' : 'p-other';
      const geo = geoCache[p.dst];
      const geoHtml = geo ? '<span class="flag" title="' + geo.city + ', ' + geo.country + '">' + flag(geo.country_code) + '</span>' :
                    (p.dst && !isPrivate(p.dst) ? '<span class="ext">EXT</span>' : '');
      return '<tr><td style="color:var(--muted)">' + p.timestamp + '</td><td>' + p.src + '</td><td>' + p.dst + '</td>' +
        '<td>' + pill(p.protocol, proto) + '</td><td style="color:var(--muted)">' + p.service + '</td><td style="color:var(--muted)">' + p.length + '</td>' +
        '<td>' + geoHtml + '</td></tr>';
    }).join('');
  });
}

function fetchLogs() {
  fetch('/api/logs').then(r => r.json()).then(data => {
    document.getElementById('log-table').innerHTML = data.map(l =>
      '<tr><td style="color:var(--muted)">' + l.time + '</td><td>' + l.src + '</td><td>' + l.dst + '</td>' +
      '<td>' + pill(l.protocol, l.protocol === 'TCP' ? 'p-tcp' : 'p-udp') + '</td>' +
      '<td style="color:var(--muted)">' + l.service + '</td><td style="color:var(--muted)">' + l.length + '</td></tr>'
    ).join('');
  });
}

function fetchDNS() {
  fetch('/api/dns-logs').then(r => r.json()).then(data => {
    document.getElementById('dns-count').textContent = data.length + ' entries';
    const tb = document.getElementById('dns-table');
    if (!data.length) { tb.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:24px">No DNS queries captured yet.</td></tr>'; return; }
    tb.innerHTML = data.map(e =>
      '<tr><td style="color:var(--muted)">' + e.timestamp + '</td><td>' + e.src + '</td><td style="color:var(--accent)">' + e.domain + '</td></tr>'
    ).join('');
  });
}

function fetchBandwidth() {
  fetch('/api/bandwidth-history').then(r => r.json()).then(d => updateBwChart(d));
}

function fetchProtocol() {
  fetch('/api/protocol-stats').then(r => r.json()).then(d => {
    protoChart.data.datasets[0].data = [d.TCP || 0, d.UDP || 0, d.Other || 0];
    protoChart.update();
  });
}

function renderIssues(issues, id) {
  const el = document.getElementById(id);
  if (!issues.length) { el.innerHTML = '<div style="color:var(--green);font-size:.83rem"><i class="bi bi-shield-check"></i> No active issues detected.</div>'; return; }
  el.innerHTML = issues.map(issue =>
    '<div class="ic ' + issue.severity + '">' +
    '<div class="d-flex justify-content-between align-items-start gap-2 mb-1">' +
    '<strong style="font-size:.83rem">' + issue.title + '</strong>' +
    '<div class="d-flex gap-1 flex-shrink-0">' + pill(issue.severity, 'p-' + issue.severity) + pill(issue.category, 'p-' + issue.category) + '</div></div>' +
    (issue.affected_device ? '<div style="font-size:.72rem;color:var(--muted);font-family:monospace;margin-bottom:4px">' + issue.affected_device + '</div>' : '') +
    '<p style="font-size:.78rem;margin:4px 0">' + issue.recommendation + '</p>' +
    '<div class="d-flex gap-2">' + (issue.admin_alert ? pill('admin alert','p-red') : '') + (issue.auto_fix ? pill('fix available','p-blue') : '') + '</div>' +
    '</div>'
  ).join('');
}

function renderIssuesSummary(issues) {
  const el = document.getElementById('ov-issues');
  if (!issues.length) { el.innerHTML = '<span style="color:var(--green);font-size:.83rem"><i class="bi bi-shield-check"></i> No active issues.</span>'; return; }
  el.innerHTML = issues.slice(0,3).map(issue =>
    '<div class="ic ' + issue.severity + '" style="padding:8px 12px;margin-bottom:6px">' +
    '<div class="d-flex justify-content-between">' +
    '<span style="font-size:.8rem"><strong>' + issue.title + '</strong></span>' + pill(issue.severity, 'p-' + issue.severity) + '</div>' +
    '<div style="font-size:.73rem;color:var(--muted);margin-top:3px">' + issue.recommendation.substring(0,90) + (issue.recommendation.length > 90 ? '…' : '') + '</div>' +
    '</div>'
  ).join('') + (issues.length > 3 ? '<div style="font-size:.72rem;color:var(--muted);text-align:center;margin-top:6px">+' + (issues.length-3) + ' more in Alerts tab</div>' : '');
}

function runDiag() {
  fetch('/api/ai-diagnostics').then(r => r.json()).then(data => {
    const issues = data.issues || [];
    const critCount = issues.filter(i => i.severity === 'critical').length;
    document.getElementById('st-alerts').textContent = issues.length;
    const badge = document.getElementById('alert-badge');
    if (critCount > 0) { badge.style.display = ''; badge.textContent = critCount; }
    else { badge.style.display = 'none'; }
    document.getElementById('ai-summary').textContent = data.summary;
    renderIssues(issues, 'ai-issues');
    renderIssuesSummary(issues);
    document.getElementById('upd-time').textContent = new Date().toLocaleTimeString();
  });
}

// ---- Polling ----
triggerScan();
runDiag();
fetchDevices(); fetchStats(); fetchPackets(); fetchLogs(); fetchDNS(); fetchBandwidth(); fetchProtocol();

setInterval(fetchDevices, 5000);
setInterval(fetchPackets, 1000);
setInterval(fetchStats, 2000);
setInterval(fetchLogs, 10000);
setInterval(fetchDNS, 3000);
setInterval(fetchBandwidth, 10000);
setInterval(fetchProtocol, 5000);
setInterval(runDiag, 30000);
</script>
</body>
</html>"""


# --- Main ---

if __name__ == '__main__':
    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=geoip_worker, daemon=True).start()
    threading.Thread(target=snapshot_bandwidth, daemon=True).start()

    print("=" * 50)
    print("  Mini Home SOC v2.0")
    print("  Dashboard -> http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=False, host='0.0.0.0', port=5000)
