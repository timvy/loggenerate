"""
Palo Alto Networks PAN-OS syslog log generator.

Supported log types: traffic, threat, system, config
Reference: PAN-OS 10.x Syslog Field Descriptions
  https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring
"""

import random
from typing import Optional

from loggenerate.apps.base import BaseAppGenerator
from loggenerate.models import SyslogMessage
from loggenerate.utils import (
    now_utc, rand_private_ip, rand_public_ip,
    rand_ephemeral_port, rand_well_known_port,
    rand_country, rand_application, rand_user,
    rand_bytes_pair, rand_packets_pair, pan_timestamp,
)

_SERIALS = ["012345678901", "123456789012", "PA1234567890", "987654321098", "010108002034"]
_HOSTNAMES = ["PA-FW1", "PA-FW2", "PA-3260", "PA-VM50", "PA-EDGE-01"]
_DEVICE_NAMES = [
    "PNG-PFW-001", "PNG-PFW-005", "PA-FW1", "PA-FW2",
    "PA-EDGE-01", "PA-DC-FW01", "PA-FW-CORE-01",
]
_RULES = [
    "allow-trusted-outbound", "deny-inbound-default",
    "allow-dmz-web", "vpn-split-tunnel", "block-known-bad",
    "allow-guest-internet", "allow-internal-east-west",
    "interzone-default",
]
_INTERFACES = [
    "ethernet1/1", "ethernet1/2", "ethernet1/3",
    "ae1.100", "ae1.200", "ae3.3295", "ae3.3296", "tunnel.1",
]
_ZONES = [
    "trust", "untrust", "dmz", "vpn", "guest", "mgmt",
    "L3-Trust", "L3-Untrust", "L3-dmz", "L3-dmz-secaas",
    "L3-guest-wifi", "external", "internal",
]
_VSYS = ["vsys1", "vsys2", "vsys3", "vsys4", "vsys12"]
_LOG_ACTIONS = ["Syslog-Forward", "Panorama", "log-forward"]
_PROTOCOLS = ["tcp", "udp", "icmp"]
_ACTIONS = ["allow", "deny", "drop", "reset-client", "reset-server"]
_SESSION_END_REASONS = [
    "aged-out", "policy-deny", "tcp-fin",
    "tcp-rst-from-client", "tcp-rst-from-server",
    "resources-unavailable",
]
_URL_CATEGORIES = [
    "shopping", "news", "social-networking",
    "business-and-economy", "computer-and-internet-info",
    "search-engines", "malware", "phishing",
]
_THREAT_NAMES = [
    "SQL Injection", "Cross-site Scripting", "Remote Code Execution",
    "Directory Traversal", "Shellshock", "Heartbleed", "EternalBlue",
    "WannaCry Ransomware", "Log4Shell", "ProxyLogon",
]
_THREAT_SUBTYPES = [
    "vulnerability", "virus", "wildfire-virus", "spyware", "url",
]
_THREAT_ACTIONS = ["alert", "block-ip", "reset-both", "drop-packet", "allow"]
_THREAT_SEVERITIES = ["informational", "low", "medium", "high", "critical"]
_SYSTEM_EVENTS = [
    ("general", "general", "info",     "Configuration committed successfully by admin"),
    ("general", "ha-state-change", "info",  "HA state changed to active"),
    ("auth",    "authd-login-success", "info",   "Admin login succeeded: admin from 10.0.0.1"),
    ("auth",    "authd-login-fail",    "warning", "Admin login failed: unknown from 203.0.113.5"),
    ("dhcp",    "dhcp-lease",  "info",  "DHCP lease assigned 10.1.1.100 to client"),
    ("routing", "route-update","info",  "Route 0.0.0.0/0 via 192.168.1.1 added to routing table"),
    ("general", "link-change", "notice","Interface ethernet1/2 link state changed to up"),
    ("system",  "ntp-sync",    "info",  "NTP time synchronized with 216.239.35.0"),
]


def _traffic_log(dt, serial, src_ip, dst_ip, src_port, dst_port) -> tuple:
    """Returns (severity, message_body, app_name)."""
    in_iface = random.choice(_INTERFACES)
    out_iface = random.choice(_INTERFACES)
    rule = random.choice(_RULES)
    src_zone = random.choice(["trust", "internal", "dmz", "vpn", "L3-Trust", "L3-dmz-secaas"])
    dst_zone = random.choice(["untrust", "external", "dmz", "L3-Untrust", "L3-dmz"])
    proto = random.choice(_PROTOCOLS)
    action = random.choice(_ACTIONS)

    # Dropped/denied traffic often has no identified application
    if action in ("drop", "deny") and random.random() < 0.4:
        app = "not-applicable"
        category = "any"
    else:
        app = rand_application()
        category = random.choice(_URL_CATEGORIES)

    sent, recv = rand_bytes_pair()
    sent_pkts, recv_pkts = rand_packets_pair()
    elapsed = random.randint(1, 600)
    session_id = random.randint(10_000, 9_999_999)
    seq = random.randint(1_000_000_000, 9_999_999_999)

    hires_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+00:00"
    extended = (
        ["", "", "", "", ""]        # DGH hierarchy levels 1-4 + vsys name
        + [random.choice(_DEVICE_NAMES)]  # Device Name (PAN-OS field 53)
        + [""] * 50                 # PAN-OS fields 54-103
        + [hires_ts]                # high-res receive time (PAN-OS field 104)
        + [""] * 14                 # trailing fields 105-118
    )

    fields = [
        "1",                                    # FUTURE_USE
        pan_timestamp(dt),                       # Receive Time
        serial,                                  # Serial Number
        "TRAFFIC",                               # Type
        random.choice(["end", "start", "drop"]), # Subtype
        "2048",                                  # Config Version
        pan_timestamp(dt),                       # Generate Time
        src_ip,                                  # Source Address
        dst_ip,                                  # Destination Address
        "0.0.0.0",                              # NAT Source IP
        "0.0.0.0",                              # NAT Destination IP
        rule,                                    # Rule Name
        rand_user("corp"),                       # Source User
        "",                                      # Destination User
        app,                                     # Application
        random.choice(_VSYS),                    # Virtual System
        src_zone,                                # Source Zone
        dst_zone,                                # Destination Zone
        in_iface,                                # Inbound Interface
        out_iface,                               # Outbound Interface
        random.choice(_LOG_ACTIONS),             # Log Action
        "",                                      # FUTURE_USE
        str(session_id),                         # Session ID
        "1",                                     # Repeat Count
        str(src_port),                           # Source Port
        str(dst_port),                           # Destination Port
        "0",                                     # NAT Source Port
        "0",                                     # NAT Destination Port
        "0x401a",                                # Flags
        proto,                                   # IP Protocol
        action,                                  # Action
        str(sent + recv),                        # Bytes
        str(sent),                               # Bytes Sent
        str(recv),                               # Bytes Received
        str(sent_pkts + recv_pkts),             # Packets
        pan_timestamp(dt),                       # Start Time
        str(elapsed),                            # Elapsed Time
        category,                                # Category
        "0",                                     # FUTURE_USE
        str(seq),                                # Sequence Number
        "0x0",                                   # Action Flags
        "Reserved",                              # Source Country (private IP)
        rand_country(),                          # Destination Country
        "0",                                     # FUTURE_USE
        str(sent_pkts),                          # Packets Sent
        str(recv_pkts),                          # Packets Received
        random.choice(_SESSION_END_REASONS),     # Session End Reason
    ] + extended
    return 6, ",".join(fields), app


def _threat_log(dt, serial, src_ip, dst_ip, src_port, dst_port) -> tuple:
    """Returns (severity, message_body, app_name)."""
    in_iface = random.choice(_INTERFACES[:4])
    out_iface = random.choice(_INTERFACES[:4])
    rule = random.choice(_RULES)
    src_zone = random.choice(["trust", "internal", "vpn"])
    dst_zone = random.choice(["untrust", "external", "dmz"])
    app = rand_application()
    proto = random.choice(_PROTOCOLS[:2])  # tcp or udp only
    threat_name = random.choice(_THREAT_NAMES)
    threat_sev = random.choice(_THREAT_SEVERITIES)
    session_id = random.randint(10_000, 9_999_999)
    seq = random.randint(1_000_000_000, 9_999_999_999)
    uri = random.choice(["/login", "/admin", "/api/v1/exec", "/cgi-bin/test.cgi", "/wp-login.php"])

    fields = [
        "1",
        pan_timestamp(dt),
        serial,
        "THREAT",
        random.choice(_THREAT_SUBTYPES),
        "2048",
        pan_timestamp(dt),
        src_ip,
        dst_ip,
        "0.0.0.0",
        "0.0.0.0",
        rule,
        rand_user("corp"),
        "",
        app,
        random.choice(_VSYS),
        src_zone,
        dst_zone,
        in_iface,
        out_iface,
        random.choice(_LOG_ACTIONS),
        "",
        str(session_id),
        "1",
        str(src_port),
        str(dst_port),
        "0",
        "0",
        "0x401a",
        proto,
        random.choice(_THREAT_ACTIONS),
        f"http://{dst_ip}{uri}",   # URL/Filename
        threat_name,               # Threat/Content Name
        random.choice(_URL_CATEGORIES),
        threat_sev,
        random.choice(["client-to-server", "server-to-client"]),
        str(seq),
        "0x0",
        "Reserved",
        rand_country(),
        "text/html",               # Content Type
        "0",                       # PCAP_ID
        "",                        # File Digest
        "internet",                # Cloud
        "1",                       # URL Index
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "text/html",               # File Type
        "",                        # X-Forwarded-For
        "",                        # Referer
    ]
    sev = 4 if threat_sev in ("high", "critical") else 5
    return sev, ",".join(fields), app


def _system_log(dt, serial) -> tuple:
    """Returns (severity, message_body)."""
    ev_obj, ev_id, ev_sev, desc = random.choice(_SYSTEM_EVENTS)
    sev_map = {"info": 6, "notice": 5, "warning": 4, "error": 3}
    sev = sev_map.get(ev_sev, 6)
    seq = random.randint(1_000_000_000, 9_999_999_999)

    fields = [
        "1",
        pan_timestamp(dt),
        serial,
        "SYSTEM",
        "general",
        "2048",
        pan_timestamp(dt),
        "",            # Virtual System
        ev_obj,        # Object
        ev_id,         # Event ID
        ev_sev,        # Module
        ev_sev,        # Severity
        str(seq),
        "0x0",
        desc,
    ]
    return sev, ",".join(fields)


def _config_log(dt, serial) -> tuple:
    """Returns (severity, message_body)."""
    admins = ["admin", "operator", "netops", "secops"]
    changes = [
        "set deviceconfig system hostname PA-FW1-NEW",
        "set rulebase security rules 'new-rule' action allow",
        "delete address-group 'old-group'",
        "set network interface ethernet ethernet1/3 layer3 ip 10.0.3.1/24",
        "set shared log-settings syslog 'syslog-server' server 192.168.1.100 transport UDP",
        "commit",
    ]
    seq = random.randint(1_000_000_000, 9_999_999_999)
    admin = random.choice(admins)
    change = random.choice(changes)

    fields = [
        "1",
        pan_timestamp(dt),
        serial,
        "CONFIG",
        "0",
        "2048",
        pan_timestamp(dt),
        rand_private_ip(),  # client IP
        "",
        "Succeeded",
        admin,
        change,
        str(seq),
        "0x0",
    ]
    return 5, ",".join(fields)


class PaloAltoGenerator(BaseAppGenerator):
    LOG_TYPES = ["traffic", "threat", "system", "config"]

    def generate(
        self,
        hostname: Optional[str] = None,
        facility: Optional[int] = None,
        severity: Optional[int] = None,
        log_type: Optional[str] = None,
    ) -> SyslogMessage:
        dt = now_utc()
        serial = random.choice(_SERIALS)
        host = hostname or random.choice(_HOSTNAMES)
        fac = facility if facility is not None else 16  # local0
        log_type = log_type or random.choice(self.LOG_TYPES)

        src_ip = rand_private_ip()
        dst_ip = rand_public_ip()
        src_port = rand_ephemeral_port()
        dst_port = rand_well_known_port()

        generators = {
            "traffic": lambda: _traffic_log(dt, serial, src_ip, dst_ip, src_port, dst_port),
            "threat":  lambda: _threat_log(dt, serial, src_ip, dst_ip, src_port, dst_port),
            "system":  lambda: _system_log(dt, serial),
            "config":  lambda: _config_log(dt, serial),
        }
        if log_type not in generators:
            raise ValueError(
                f"Unknown PAN-OS log type '{log_type}'. Choices: {', '.join(self.LOG_TYPES)}"
            )

        result = generators[log_type]()
        if log_type in ("traffic", "threat"):
            default_sev, body, body_app = result
        else:
            default_sev, body = result
            body_app = None
        sev = severity if severity is not None else default_sev

        # Structured data mirrors the most useful CSV fields for RFC 5424 consumers
        sd = {}
        if log_type in ("traffic", "threat"):
            sd = {
                "pan@2773": {
                    "type": log_type.upper(),
                    "src": src_ip,
                    "dst": dst_ip,
                    "app": body_app,
                }
            }

        return SyslogMessage(
            facility=fac,
            severity=sev,
            timestamp=dt,
            hostname=host,
            app_name="PAN-OS",
            proc_id="-",
            msg_id=log_type.upper(),
            structured_data=sd,
            message=body,
        )
