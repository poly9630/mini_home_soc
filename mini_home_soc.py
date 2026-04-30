#!/usr/bin/env python3
import threading
import time
import logging
import sqlite3
import smtplib
from email.mime.text import MIMEText
try:
    from flask import Flask, jsonify, render_template_string, request
except Exception as e:
    import sys, pkgutil
    print("[ERROR] Failed to import Flask: {}".format(e))
    print("Python executable:", sys.executable)
    print("Python version:", sys.version.splitlines()[0])
    print("sys.path:")
    for p in sys.path:
        print("  ", p)
    print("Flask importable via pkgutil:", pkgutil.find_loader('flask') is not None)
    print("If Flask is installed for a different interpreter, run the script with that interpreter:\n    /usr/bin/python3 {}".format(__file__))
    sys.exit(1)
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP
import socket
from ai_diagnostics import analyze_network, build_network_map

# --- Configuration ---
TARGET_SUBNET = "192.168.1.0/24"  # CHANGE THIS to reflect your local network
MAX_PACKETS = 100            # Max packets to keep in memory for UI
PACKET_SNIFFER_FILTER = "not port 5000"  # Avoid capturing our web server traffic.
SERVICE_SCAN_PORTS = [22, 23, 80, 443, 445, 3389, 5900, 8080]

# Alerting Email Configuration (Optional: Edit if you want email alerts)
ALERT_EMAIL = False  # Set to True if you want email alerts
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USER = 'your_email@gmail.com'  # Change this to your Gmail
SMTP_PASS = 'your_app_password'     # Gmail App Password (not normal password for security)

# --- Global Data ---
detected_devices = []         # List of discovered devices
packet_buffer = []            # Recent packets for UI
traffic_stats = {}            # Bandwidth stats per device
is_sniffing = True            # Sniffer running flag
recent_ports = {}             # To detect port scans
last_ai_report = {"summary": "No diagnostics have run yet.", "issues": [], "network_map": {}}
alerted_issue_ids = set()     # Avoid repeated AI admin alerts for same finding

# Disable verbose scapy logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Database Setup ---
# SQLite for logging traffic data
conn = sqlite3.connect('traffic.db', check_same_thread=False)
c = conn.cursor()

# Create packet_logs table if it doesn't exist
c.execute('''
CREATE TABLE IF NOT EXISTS packet_logs (
    time TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    length INTEGER,
    service TEXT
)
''')
conn.commit()

# --- Flask Web App Setup ---
app = Flask(__name__)

# --- Email Alert Helper Function ---
def send_alert_email(subject, body):
    if not ALERT_EMAIL:
        return

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = SMTP_USER  # Send alert emails to yourself

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print("[ALERT] Email sent.")
    except Exception as e:
        print("[ERROR] Failed to send alert email: {}".format(e))

# --- Device Discovery Functions ---

def get_hostname(ip):
    """Attempt to resolve hostname from IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_open_ports(ip):
    """Lightweight TCP connect scan for common admin/service ports."""
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

def scan_network():
    """Sends ARP requests to discover devices on the local subnet."""
    global detected_devices
    print("Scanning network: {}...".format(TARGET_SUBNET))
    
    # Create ARP request
    arp = ARP(pdst=TARGET_SUBNET)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send and receive ARP request to discover devices
    result = srp(packet, timeout=3, verbose=0)[0]

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

# --- Packet Capture (Sniffer) ---

# Common ports for easy detection (you can expand this dictionary as needed)
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    53: "DNS",
    3389: "RDP"
}

def packet_callback(packet):
    """Callback function for Scapy packet sniffer."""
    global packet_buffer, traffic_stats, recent_ports

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        # Determine protocol and ports if relevant
        if packet.haslayer(TCP):
            protocol_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            protocol_name = "Other"
            sport = "-"
            dport = "-"

        # Determine service name based on destination port (if known)
        service = COMMON_PORTS.get(dport, "Unknown:{}".format(dport))
        
        # Create packet data dictionary
        pkt_data = {
            'timestamp': time.strftime('%H:%M:%S'),
            'src': src_ip,
            'dst': dst_ip,
            'protocol': protocol_name,
            'length': length,
            'service': service
        }

        # Add to memory buffer for the UI
        packet_buffer.insert(0, pkt_data)
        if len(packet_buffer) > MAX_PACKETS:
            packet_buffer.pop()

        # --- Bandwidth Statistics ---
        if src_ip not in traffic_stats:
            traffic_stats[src_ip] = {'sent': 0, 'received': 0}

        if dst_ip not in traffic_stats:
            traffic_stats[dst_ip] = {'sent': 0, 'received': 0}

        # Increment traffic stats
        traffic_stats[src_ip]['sent'] += length
        traffic_stats[dst_ip]['received'] += length

        # --- Save Packet to Database ---
        c.execute("INSERT INTO packet_logs (time, src_ip, dst_ip, protocol, length, service) VALUES (?, ?, ?, ?, ?, ?)",
                 (pkt_data['timestamp'], src_ip, dst_ip, protocol_name, length, service))
        conn.commit()

        # --- Port Scan Detection (Simple Rule) ---
        current_time = time.time()
        window = 10  # 10 seconds window

        if src_ip not in recent_ports:
            recent_ports[src_ip] = []

        # Store (dest_port, timestamp)
        recent_ports[src_ip].append((dport, current_time))
  
        # Remove ports older than 'window' seconds from history
        recent_ports[src_ip] = [(port, ts) for (port, ts) in recent_ports[src_ip] if (current_time - ts) <= window]

        # --- Simple Port Scan Alert ---
        if len(set(port for port, ts in recent_ports[src_ip])) > 10:
            alert_message = "[ALERT] Potential Port Scan from {}: Targeting multiple ports in a short period.".format(src_ip)
            print(alert_message)
            send_alert_email(subject="Port Scan Detected", body=alert_message)

def start_sniffer():
    """Starts the traffic packet sniffer in a background thread."""
    print("[INFO] Starting packet sniffer...")
    sniff(prn=packet_callback, filter=PACKET_SNIFFER_FILTER, store=False)

# --- Flask API Routes for UI ---

@app.route('/')
def index():
    """Return the main HTML page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/devices')
def get_devices():
    """Return a JSON list of discovered devices."""
    return jsonify(detected_devices)

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """Trigger a new ARP scan to discover devices."""
    threading.Thread(target=scan_network).start()
    return jsonify({"status": "Scanning started"})

@app.route('/api/packets')
def get_packets():
    """Return the most recent captured packets."""
    return jsonify(packet_buffer)

@app.route('/api/stats')
def get_stats():
    """Return traffic statistics by IP."""
    return jsonify(traffic_stats)

@app.route('/api/logs')
def get_logs():
    """Return the latest packet history from the database."""
    c.execute("SELECT * FROM packet_logs ORDER BY time DESC LIMIT 50")
    rows = c.fetchall()
    logs = [{'time': row[0], 'src': row[1], 'dst': row[2], 'protocol': row[3], 'length': row[4], 'service': row[5]} for row in rows]
    return jsonify(logs)

@app.route('/api/network-map')
def get_network_map():
    """Return topology data for the dashboard map."""
    return jsonify(build_network_map(detected_devices, TARGET_SUBNET, traffic_stats))

@app.route('/api/ai-diagnostics')
def get_ai_diagnostics():
    """Return AI-assisted findings based on current SOC evidence."""
    global last_ai_report, alerted_issue_ids
    last_ai_report = analyze_network(detected_devices, traffic_stats, recent_ports, TARGET_SUBNET)
    for issue in last_ai_report["issues"]:
        if issue["admin_alert"] and issue["id"] not in alerted_issue_ids:
            send_alert_email(
                subject="Mini Home SOC admin alert: {}".format(issue["title"]),
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
    """Return safe remediation guidance for a detected issue."""
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


# --- Frontend UI Template ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home Network SOC</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f6f7; padding: 20px; }
        .card { margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .scroll-box { max-height: 200px; overflow-y: scroll; }
        .table-sm th, .table-sm td { font-size: 0.85rem; }
        .sticky-top { position: sticky; top: 0; background: #333; color: #fff; }
        #network-map { width: 100%; min-height: 360px; border: 1px solid #d8dee4; border-radius: 6px; background: #fff; }
        .issue-critical { border-left: 5px solid #dc3545; }
        .issue-warning { border-left: 5px solid #ffc107; }
        .issue-info { border-left: 5px solid #0dcaf0; }
        .badge-physical { background: #dc3545; }
        .badge-logical { background: #0d6efd; }
        .badge-security { background: #6f42c1; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-4 text-primary">Home Network Mini-SOC</h1>

        <!-- AI Diagnostics Section -->
        <div class="row">
            <div class="col-lg-7">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Network Map</h5>
                        <button onclick="updateAIDiagnostics()" class="btn btn-sm btn-outline-primary">Run AI Diagnostics</button>
                    </div>
                    <div class="card-body">
                        <canvas id="network-map" width="760" height="360"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-lg-5">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">AI Issue Detection</h5>
                    </div>
                    <div class="card-body">
                        <p id="ai-summary" class="text-muted">Diagnostics have not run yet.</p>
                        <div id="ai-issues" class="list-group"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Devices Section -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Connected Devices</h5>
                <button onclick="triggerScan()" class="btn btn-sm btn-primary">ARP Scan Devices</button>
            </div>
            <div class="card-body">
                <div class="scroll-box">
                    <table class="table table-striped table-hover table-sm">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Hostname</th>
                            </tr>
                        </thead>
                        <tbody id="device-table">
                            <tr><td colspan="3">Click above to scan devices.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Traffic Monitor Section -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Live Traffic Monitor</h5>
            </div>
            <div class="card-body">
                <div class="input-group mb-3">
                    <span class="input-group-text">Filter IP</span>
                    <input type="text" id="filterInput" class="form-control" placeholder="e.g., 192.168.1.1">
                </div>
                <div class="scroll-box">
                    <table class="table table-sm">
                        <thead class="table-dark sticky-top">
                            <tr>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Protocol</th>
                                <th>Service</th>
                                <th>Size (Bytes)</th>
                            </tr>
                        </thead>
                        <tbody id="packet-table">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Traffic Stats Section -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Top Devices by Traffic</h5>
            </div>
            <div class="card-body">
                <div class="scroll-box">
                    <table class="table table-sm">
                        <thead class="table-dark sticky-top">
                            <tr>
                                <th>IP</th>
                                <th>Sent (Bytes)</th>
                                <th>Received (Bytes)</th>
                            </tr>
                        </thead>
                        <tbody id="traffic-table">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Logged Packets Section -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Stored Packet History (Last 50)</h5>
            </div>
            <div class="card-body">
                <div class="scroll-box">
                    <table class="table table-sm">
                        <thead class="table-dark sticky-top">
                            <tr>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Protocol</th>
                                <th>Service</th>
                                <th>Size</th>
                            </tr>
                        </thead>
                        <tbody id="log-table">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div>

    <script>
        function triggerScan() {
            fetch('/api/scan', { method: 'POST' });
            alert("ARP Scan started. Devices will update shortly.");
        }

        function updateDevices() {
            fetch('/api/devices')
                .then(response => response.json())
                .then(data => {
                    const table = document.getElementById('device-table');
                    if(data.length === 0) {
                        table.innerHTML = '<tr><td colspan="3">No devices found. Scan might be in progress.</td></tr>';
                        return;
                    }
                    
                    let html = '';
                    data.forEach(d => {
                        html += `<tr>
                            <td>${d.ip}</td>
                            <td>${d.mac}</td>
                            <td>${d.hostname}</td>
                        </tr>`;
                    });
                    table.innerHTML = html;
                });
        }

        function updatePackets() {
            fetch('/api/packets')
                .then(response => response.json())
                .then(data => {
                    const table = document.getElementById('packet-table');
                    const filter = document.getElementById('filterInput').value;
                    
                    let html = '';
                    data.forEach(p => {
                        // Simple Client-side filtering by IP
                        if (filter && !p.src.includes(filter) && !p.dst.includes(filter)) {
                            return;
                        }

                        let colorClass = '';
                        if(p.protocol === 'TCP') colorClass = 'table-success';
                        else if(p.protocol === 'UDP') colorClass = 'table-info';
                        
                        html += `<tr class="${colorClass}">
                            <td>${p.timestamp}</td>
                            <td>${p.src}</td>
                            <td>${p.dst}</td>
                            <td>${p.protocol}</td>
                            <td>${p.service}</td>
                            <td>${p.length}</td>
                        </tr>`;
                    });
                    table.innerHTML = html;
                });
        }

        function updateTrafficStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    const table = document.getElementById('traffic-table');
                    let html = '';
                    Object.keys(data).forEach(ip => {
                        html += `<tr>
                            <td>${ip}</td>
                            <td>${data[ip].sent}</td>
                            <td>${data[ip].received}</td>
                        </tr>`;
                    });
                    table.innerHTML = html;
                });
        }

        function updateLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const table = document.getElementById('log-table');
                    let html = '';
                    data.forEach(log => {
                        html += `<tr>
                            <td>${log.time}</td>
                            <td>${log.src}</td>
                            <td>${log.dst}</td>
                            <td>${log.protocol}</td>
                            <td>${log.service}</td>
                            <td>${log.length}</td>
                        </tr>`;
                    });
                    table.innerHTML = html;
                });
        }

        function updateAIDiagnostics() {
            fetch('/api/ai-diagnostics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('ai-summary').textContent = data.summary;
                    renderIssues(data.issues || []);
                    renderNetworkMap(data.network_map || { nodes: [], links: [] });
                });
        }

        function renderIssues(issues) {
            const list = document.getElementById('ai-issues');
            if (!issues.length) {
                list.innerHTML = '<div class="list-group-item">No active issues detected.</div>';
                return;
            }
            list.innerHTML = '';
            issues.forEach(issue => {
                const severityClass = issue.severity === 'critical' ? 'issue-critical' : issue.severity === 'warning' ? 'issue-warning' : 'issue-info';
                const item = document.createElement('div');
                item.className = `list-group-item ${severityClass}`;
                item.innerHTML = `
                    <div class="d-flex justify-content-between gap-2">
                        <strong>${issue.title}</strong>
                        <span class="badge badge-${issue.category}">${issue.category}</span>
                    </div>
                    <div class="small text-muted">${issue.affected_device || 'Network-wide'}</div>
                    <p class="mb-1">${issue.recommendation}</p>
                    ${issue.admin_alert ? '<span class="badge bg-danger">admin alert</span>' : ''}
                    ${issue.auto_fix ? '<span class="badge bg-success">fix plan available</span>' : ''}
                `;
                list.appendChild(item);
            });
        }

        function renderNetworkMap(map) {
            const canvas = document.getElementById('network-map');
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;
            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = '#fff';
            ctx.fillRect(0, 0, width, height);

            const nodes = map.nodes || [];
            if (!nodes.length) {
                ctx.fillStyle = '#6c757d';
                ctx.font = '16px system-ui';
                ctx.fillText('Run a scan to build the topology map.', 28, 42);
                return;
            }

            const gateway = nodes.find(n => n.role === 'gateway') || nodes[0];
            const endpoints = nodes.filter(n => n.id !== gateway.id);
            const center = { x: width / 2, y: height / 2 };
            const radius = Math.min(width, height) * 0.34;
            const placed = {};
            placed[gateway.id] = { ...gateway, x: center.x, y: center.y };
            endpoints.forEach((node, index) => {
                const angle = ((Math.PI * 2) / Math.max(1, endpoints.length)) * index - Math.PI / 2;
                placed[node.id] = {
                    ...node,
                    x: center.x + Math.cos(angle) * radius,
                    y: center.y + Math.sin(angle) * radius
                };
            });

            (map.links || []).forEach(link => {
                const source = placed[link.source];
                const target = placed[link.target];
                if (!source || !target) return;
                ctx.beginPath();
                ctx.moveTo(source.x, source.y);
                ctx.lineTo(target.x, target.y);
                ctx.strokeStyle = '#b6c2cf';
                ctx.lineWidth = 2;
                ctx.stroke();
            });

            Object.values(placed).forEach(node => drawMapNode(ctx, node));
        }

        function drawMapNode(ctx, node) {
            const color = node.role === 'gateway' ? '#0d6efd' : node.role.includes('iot') ? '#fd7e14' : '#198754';
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.role === 'gateway' ? 24 : 18, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 4;
            ctx.stroke();
            ctx.fillStyle = '#212529';
            ctx.font = '12px system-ui';
            ctx.textAlign = 'center';
            ctx.fillText(node.label || node.id, node.x, node.y + 38);
            ctx.fillStyle = '#6c757d';
            ctx.fillText(node.role, node.x, node.y + 53);
        }

        // Poll for updates at intervals
        setInterval(updateDevices, 5000);   // Update devices every 5 seconds
        setInterval(updatePackets, 1000);   // Update packets every 1 second
        setInterval(updateTrafficStats, 2000);  // Update bandwidth stats every 2 seconds
        setInterval(updateLogs, 10000);     // Update logs every 10 seconds
        setInterval(updateAIDiagnostics, 5000); // Refresh AI diagnostics every 5 seconds

        // Load everything initially
        triggerScan();
        updateAIDiagnostics();
    </script>
</body>
</html>
"""

# --- Main Entrypoint ---

if __name__ == '__main__':
    # Start the Sniffer Thread
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    
    # Start the Web Server
    print("Starting Web Server on http://127.0.0.1:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
