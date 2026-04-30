"""AI-style network diagnostics for Mini Home SOC.

The engine is intentionally local-first: it uses the devices, traffic counters,
and port-scan evidence already collected by the app, then turns them into
operator-friendly findings, topology data, and safe remediation guidance.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import time
from dataclasses import dataclass, field


PHYSICAL_KEYWORDS = ("gateway", "cable", "power", "unreachable", "uplink", "access point")
RISKY_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "HTTP admin"}


@dataclass
class DiagnosticIssue:
    title: str
    severity: str
    category: str
    affected_device: str | None
    evidence: list[str]
    recommendation: str
    admin_alert: bool = False
    auto_fix: str | None = None
    issue_id: str = field(init=False)

    def __post_init__(self) -> None:
        raw = "|".join([self.title, self.affected_device or "network", *self.evidence])
        self.issue_id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "id": self.issue_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "affected_device": self.affected_device,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "admin_alert": self.admin_alert,
            "auto_fix": self.auto_fix,
        }


def build_network_map(devices: list[dict], target_subnet: str, traffic_stats: dict) -> dict:
    gateway_ip = detect_gateway(target_subnet)
    nodes = []
    links = []

    nodes.append(
        {
            "id": gateway_ip or "gateway",
            "label": gateway_ip or "Gateway",
            "role": "gateway",
            "status": "online" if _device_exists(devices, gateway_ip) else "unknown",
            "traffic_bytes": _traffic_total(traffic_stats, gateway_ip),
        }
    )

    for device in devices:
        ip = device.get("ip")
        role = infer_role(device)
        nodes.append(
            {
                "id": ip,
                "label": device.get("hostname") if device.get("hostname") != "Unknown" else ip,
                "ip": ip,
                "mac": device.get("mac"),
                "role": role,
                "status": "online",
                "traffic_bytes": _traffic_total(traffic_stats, ip),
            }
        )
        if ip != gateway_ip:
            links.append({"source": gateway_ip or "gateway", "target": ip, "type": role})

    return {
        "gateway": gateway_ip,
        "subnet": target_subnet,
        "nodes": nodes,
        "links": links,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def analyze_network(devices: list[dict], traffic_stats: dict, recent_ports: dict, target_subnet: str) -> dict:
    issues = []
    gateway_ip = detect_gateway(target_subnet)

    if not devices:
        issues.append(
            DiagnosticIssue(
                title="No devices discovered",
                severity="critical",
                category="physical",
                affected_device=None,
                evidence=[f"ARP scan returned zero devices for {target_subnet}."],
                recommendation="Confirm the scanner is on the correct LAN, then check router power, switch uplink, cabling, VLAN, or AP isolation.",
                admin_alert=True,
            )
        )

    if gateway_ip and devices and not _device_exists(devices, gateway_ip):
        issues.append(
            DiagnosticIssue(
                title="Gateway not visible",
                severity="critical",
                category="physical",
                affected_device=gateway_ip,
                evidence=[f"Expected gateway {gateway_ip} was not present in ARP discovery."],
                recommendation="Check router power, gateway address, switch uplink, or wireless isolation before trying software fixes.",
                admin_alert=True,
            )
        )

    for ip, stats in traffic_stats.items():
        total = stats.get("sent", 0) + stats.get("received", 0)
        if total > _traffic_threshold():
            issues.append(
                DiagnosticIssue(
                    title="Unusual traffic volume",
                    severity="warning",
                    category="logical",
                    affected_device=ip,
                    evidence=[f"{ip} has moved {total:,} bytes since the app started."],
                    recommendation="Review recent packet logs for backups, streaming, malware beacons, or repeated retries.",
                    auto_fix="Throttle or isolate the device on the router if this traffic is unexpected.",
                )
            )

    for ip, port_history in recent_ports.items():
        unique_ports = sorted({port for port, _ in port_history if isinstance(port, int)})
        if len(unique_ports) > 10:
            issues.append(
                DiagnosticIssue(
                    title="Port scan behavior",
                    severity="critical",
                    category="security",
                    affected_device=ip,
                    evidence=[f"{ip} touched {len(unique_ports)} unique ports in the detection window."],
                    recommendation="Isolate the source device, inspect it for scanning tools or malware, and rotate credentials on exposed services.",
                    admin_alert=True,
                    auto_fix="Block the source IP on the router or firewall until reviewed.",
                )
            )

    for device in devices:
        open_services = [RISKY_PORTS[p] for p in device.get("open_ports", []) if p in RISKY_PORTS]
        if open_services:
            issues.append(
                DiagnosticIssue(
                    title="Risky management service exposed",
                    severity="warning",
                    category="security",
                    affected_device=device.get("ip"),
                    evidence=[f"Detected exposed service(s): {', '.join(open_services)}."],
                    recommendation="Disable unused admin services or restrict them to trusted admin hosts.",
                    auto_fix="Apply a router/firewall rule limiting access to the service.",
                )
            )

    issue_dicts = [issue.to_dict() for issue in issues]
    return {
        "summary": _summarize(issue_dicts),
        "issues": issue_dicts,
        "network_map": build_network_map(devices, target_subnet, traffic_stats),
    }


def detect_gateway(target_subnet: str) -> str | None:
    env_gateway = os.getenv("MINI_SOC_GATEWAY")
    if env_gateway:
        return env_gateway

    try:
        network = ipaddress.ip_network(target_subnet, strict=False)
        return str(next(network.hosts()))
    except (ValueError, StopIteration):
        return None


def infer_role(device: dict) -> str:
    hostname = (device.get("hostname") or "").lower()
    ip = device.get("ip")
    if ip == detect_gateway(os.getenv("TARGET_SUBNET", "192.168.1.0/24")):
        return "gateway"
    if "camera" in hostname or "cam" in hostname:
        return "camera/iot"
    if "printer" in hostname:
        return "printer"
    if "router" in hostname or "gateway" in hostname:
        return "gateway"
    return "endpoint"


def enrich_device_services(device: dict, ports: list[int]) -> dict:
    enriched = dict(device)
    enriched["open_ports"] = ports
    enriched["role"] = infer_role(enriched)
    return enriched


def _summarize(issues: list[dict]) -> str:
    if not issues:
        return "No active issues detected from current discovery, traffic, and scan evidence."
    physical = sum(1 for issue in issues if issue["category"] == "physical")
    critical = sum(1 for issue in issues if issue["severity"] == "critical")
    if physical:
        return f"{len(issues)} issue(s) found; {physical} look physical and should alert an admin."
    if critical:
        return f"{len(issues)} issue(s) found; {critical} critical security/logical issue(s) need action."
    return f"{len(issues)} issue(s) found; most appear fixable through configuration."


def _device_exists(devices: list[dict], ip: str | None) -> bool:
    return bool(ip) and any(device.get("ip") == ip for device in devices)


def _traffic_total(traffic_stats: dict, ip: str | None) -> int:
    if not ip or ip not in traffic_stats:
        return 0
    stats = traffic_stats[ip]
    return int(stats.get("sent", 0)) + int(stats.get("received", 0))


def _traffic_threshold() -> int:
    return int(os.getenv("MINI_SOC_TRAFFIC_ALERT_BYTES", "50000000"))


def can_resolve_dns() -> bool:
    try:
        socket.gethostbyname("example.com")
        return True
    except OSError:
        return False
