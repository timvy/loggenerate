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
# (app_category, app_subcategory, risk_1_to_5)
_APP_CATEGORY = {
    "ssl":             ("networking",        "encrypted-tunnel",   2),
    "http":            ("general-internet",  "web-browsing",       3),
    "dns":             ("networking",        "infrastructure",     2),
    "smtp":            ("collaboration",     "email",              3),
    "ssh":             ("networking",        "remote-access",      2),
    "ftp":             ("general-internet",  "file-sharing",       4),
    "rdp":             ("business-systems",  "remote-access",      4),
    "office365":       ("business-systems",  "office-programs",    2),
    "msrpc":           ("business-systems",  "general",            3),
    "netbios-ns":      ("networking",        "infrastructure",     3),
    "dropbox":         ("general-internet",  "file-sharing",       3),
    "youtube":         ("media",             "streaming-media",    2),
    "facebook":        ("social-networking", "social-networking",  3),
    "instagram":       ("social-networking", "photo-video",        3),
    "linkedin":        ("social-networking", "social-networking",  2),
    "sharepoint":      ("business-systems",  "content-delivery",   2),
    "teams":           ("collaboration",     "video-conferencing", 2),
    "zoom":            ("collaboration",     "video-conferencing", 2),
    "webex":           ("collaboration",     "video-conferencing", 2),
    "slack":           ("collaboration",     "instant-messaging",  2),
    "ntp":             ("networking",        "infrastructure",     1),
    "snmp":            ("networking",        "infrastructure",     3),
    "ldap":            ("business-systems",  "auth-service",       3),
    "kerberos":        ("business-systems",  "auth-service",       2),
    "quic":            ("networking",        "encrypted-tunnel",   2),
    "splunk":          ("business-systems",  "data-analytics",     2),
    "syslog":          ("networking",        "infrastructure",     2),
    "sap":             ("business-systems",  "erp",                3),
    "oracle-database": ("business-systems",  "database",           3),
    "not-applicable":  ("unknown",           "unknown",            2),
}
_APP_CATEGORY_DEFAULT = ("unknown", "unknown", 2)

_PANORAMA_SERIALS = ["001234567890", "001234567891", "PA-PAN-SRV-01"]
_LOG_PROFILES = ["default", "prod-logs", "sec-ops-logs", "Panorama"]

_GP_PORTALS = ["corp-portal", "remote-portal", "vpn-portal", "staff-portal"]
_GP_GATEWAYS = [
    "us-west-gw", "us-east-gw", "eu-central-gw", "apac-gw",
    "corp-gateway", "dc-gateway-01",
]
_GP_AUTH_METHODS = ["LDAP", "SAML 2.0", "Kerberos", "certificate"]
_GP_TUNNEL_TYPES = ["IPSec", "SSL"]
_GP_OS_TYPES = [
    ("Windows", "Windows 11 22H2"),
    ("Windows", "Windows 10 21H2"),
    ("macOS", "macOS 14.1"),
    ("iOS", "iOS 17.1"),
    ("Android", "Android 13"),
]
_GP_CLIENT_VERSIONS = ["5.2.9", "5.3.0", "6.0.1", "6.1.2"]
_GP_ENDPOINTS = [
    "CORP-WS-1001", "CORP-WS-1002", "CORP-WS-1003", "CORP-WS-1004",
    "CORP-NB-0042", "CORP-NB-0043", "CORP-NB-0044",
    "LAPTOP-AB1234", "LAPTOP-CD5678", "LAPTOP-EF9012",
    "MAC-ALICE", "MAC-BOB", "MAC-CHARLIE",
]
_GP_CONN_ERRORS = [
    "Authentication failed: Invalid username or password",
    "Pre-login authentication failed",
    "Gateway certificate validation failed",
    "Client certificate authentication failed",
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


def _sls_traffic_log(dt, serial, hostname, src_ip, dst_ip, src_port, dst_port) -> tuple:
    """Returns (severity, cef_extension_string, sub_type).

    Generates a TRAFFIC event in Strata Logging Service CEF extension format.
    Reference: https://docs.paloaltonetworks.com/strata-logging-service/log-reference/
               network-logs/network-traffic-log/network-traffic-cef-fields
    """
    subtype = random.choice(["end", "end", "start", "drop", "deny"])
    action = subtype if subtype in ("drop", "deny") else "allow"
    sev = 4 if action != "allow" else 6

    if subtype in ("drop", "deny") and random.random() < 0.4:
        app = "not-applicable"
        url_cat = "any"
    else:
        app = rand_application()
        url_cat = random.choice(_URL_CATEGORIES)
    app_cat, app_subcat, app_risk = _APP_CATEGORY.get(app, _APP_CATEGORY_DEFAULT)

    rule = random.choice(_RULES)
    src_zone = random.choice(["trust", "internal", "L3-Trust", "L3-dmz-secaas", "vpn"])
    dst_zone = random.choice(["untrust", "external", "L3-Untrust"])
    in_iface = random.choice(_INTERFACES)
    out_iface = random.choice(_INTERFACES)
    proto = random.choice(_PROTOCOLS)
    vsys = random.choice(_VSYS)

    if subtype in ("drop", "deny"):
        sent, recv = 0, 0
        sent_pkts, recv_pkts = 1, 0
        elapsed = 0
        session_end_reason = "policy-deny"
    else:
        sent, recv = rand_bytes_pair()
        sent_pkts, recv_pkts = rand_packets_pair()
        elapsed = random.randint(1, 600)
        session_end_reason = (
            random.choice(["aged-out", "tcp-fin", "tcp-rst-from-client", "tcp-rst-from-server"])
            if subtype == "end" else ""
        )

    session_id = random.randint(10_000, 9_999_999)
    seq = random.randint(1_000_000_000, 9_999_999_999)

    is_nat = random.random() < 0.3
    nat_src = rand_private_ip() if is_nat else "0.0.0.0"
    nat_sport = str(random.randint(1024, 65535)) if is_nat else "0"

    user = rand_user("corp")
    user_domain, user_name = user.split("\\", 1) if "\\" in user else ("", user)

    tenant_id = "".join(random.choices("0123456789abcdef", k=16))
    rule_uuid = (
        f"{random.randint(0, 0xffffffff):08x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffffffffffff):012x}"
    )
    profile_token = "".join(random.choices(
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=24,
    ))
    hires_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+00:00"
    cef_ts = dt.strftime("%b %d %Y %H:%M:%S")

    def p(k, v):
        esc = str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")
        return f"{k}={esc}"

    fields = [
        p("ProfileToken", profile_token),
        "dtz=UTC",
        p("rt", cef_ts),
        p("deviceExternalId", serial),
        p("PanOSDGHierarchyLevel1", random.randint(100, 9999)),
        "PanOSDGHierarchyLevel2=0",
        "PanOSDGHierarchyLevel3=0",
        "PanOSDGHierarchyLevel4=0",
        p("dvchost", hostname),
        p("cs3", vsys),
        "cs3Label=Virtual System",
        p("PanOSVirtualSystemName", vsys),
        p("cs1", rule),
        "cs1Label=Rule Name",
        p("cs4", src_zone),
        "cs4Label=Source Zone",
        p("cs5", dst_zone),
        "cs5Label=Destination Zone",
        p("cs6", random.choice(_LOG_PROFILES)),
        "cs6Label=Log Profile",
        p("start", cef_ts),
        p("PanOSTimeGeneratedHighResolution", hires_ts),
        p("src", src_ip),
        p("dst", dst_ip),
        p("spt", src_port),
        p("dpt", dst_port),
        p("suser", user),
        p("sntdom", user_domain),
        p("susername", user_name),
        p("proto", proto),
        p("app", app),
        p("act", action),
        "FlowType=flow",
        p("Name", subtype),
        p("reason", session_end_reason),
        p("in", recv),
        p("out", sent),
        p("PanOSBytes", sent + recv),
        p("cn1", session_id),
        "cn1Label=Session ID",
        p("cn2", sent_pkts + recv_pkts),
        "cn2Label=Total Packets",
        p("PanOSPacketsSent", sent_pkts),
        p("PanOSPacketsReceived", recv_pkts),
        p("cn3", elapsed),
        "cn3Label=Elapsed Time in Seconds",
        p("externalId", seq),
        p("deviceInboundInterface", in_iface),
        p("deviceOutboundInterface", out_iface),
        "PanOSSourceLocation=Reserved",
        p("PanOSDestinationLocation", rand_country()),
        p("cs2", url_cat),
        "cs2Label=URL Category",
        p("PanOSApplicationCategory", app_cat),
        p("PanOSApplicationSubcategory", app_subcat),
        p("PanOSApplicationRisk", app_risk),
        p("sourceTranslatedAddress", nat_src),
        "destinationTranslatedAddress=0.0.0.0",
        p("sourceTranslatedPort", nat_sport),
        "destinationTranslatedPort=0",
        p("PanOSNAT", "true" if is_nat else "false"),
        p("PanOSCortexDataLakeTenantID", tenant_id),
        p("PanOSPanoramaSN", random.choice(_PANORAMA_SERIALS)),
        p("PanOSRuleUUID", rule_uuid),
        "PanOSLogSource=firewall",
    ]
    return sev, " ".join(fields), subtype


def _gp_log(dt, serial, hostname) -> tuple:
    """Returns (severity, cef_extension_string).

    Generates a GlobalProtect event in Strata Logging Service CEF extension format.
    Reference: https://docs.paloaltonetworks.com/strata-logging-service/log-reference/
               network-logs/network-globalprotect-log/network-globalprotect-cef-fields
    """
    stage = random.choice(["connected", "disconnected", "login", "auth-error"])
    is_success = stage != "auth-error"
    outcome = "success" if is_success else "failure"
    sev = 6 if is_success else 4  # info / warning

    user = rand_user("corp")
    user_domain, user_name = user.split("\\", 1) if "\\" in user else ("", user)
    public_ip = rand_public_ip()
    vsys = random.choice(_VSYS)
    endpoint = random.choice(_GP_ENDPOINTS)
    os_type, os_version = random.choice(_GP_OS_TYPES)
    portal = random.choice(_GP_PORTALS)
    gateway = random.choice(_GP_GATEWAYS)
    auth_method = random.choice(_GP_AUTH_METHODS)
    country = rand_country()
    seq = random.randint(1_000_000_000, 9_999_999_999)
    profile_token = "".join(random.choices(
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=24,
    ))
    tenant_id = "".join(random.choices("0123456789abcdef", k=16))
    host_id = (
        f"{random.randint(0, 0xffffffff):08x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffff):04x}-"
        f"{random.randint(0, 0xffffffffffff):012x}"
    )
    hires_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+00:00"
    cef_ts = dt.strftime("%b %d %Y %H:%M:%S")

    def p(k, v):
        esc = str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")
        return f"{k}={esc}"

    fields = [
        p("ProfileToken", profile_token),
        "dtz=UTC",
        p("rt", cef_ts),
        p("deviceExternalID", serial),
        p("PanOSDGHierarchyLevel1", random.randint(100, 9999)),
        "PanOSDGHierarchyLevel2=0",
        "PanOSDGHierarchyLevel3=0",
        "PanOSDGHierarchyLevel4=0",
        p("dvchost", hostname),
        "sourceServiceName=globalprotect",
        p("PanOSVirtualSystem", vsys),
        p("cs3", vsys),
        "cs3Label=vsys_name",
        p("start", cef_ts),
        p("PanOSTimeGeneratedHighResolution", hires_ts),
        p("shost", endpoint),
        p("suser", user),
        p("sntdom", user_domain),
        p("susername", user_name),
        "PanOSLogSubtype=globalprotect",
        p("Name", stage),
        p("PanOSStage", stage),
        p("outcome", outcome),
        p("src", public_ip),
        p("PanOSSourceRegion", country),
        p("PanOSPortal", portal),
        p("PanOSAuthMethod", auth_method),
        p("PanOSGlobalProtectClientVersion", random.choice(_GP_CLIENT_VERSIONS)),
        p("PanOSEndpointOSType", os_type),
        p("PanOSEndpointOSVersion", os_version),
        p("PanOSHostID", host_id),
        p("PanOSSequenceNo", seq),
        p("PanOSTenantID", tenant_id),
    ]

    if stage in ("connected", "disconnected"):
        fields += [
            p("PanOSTunnelType", random.choice(_GP_TUNNEL_TYPES)),
            p("PanOSGateway", gateway),
            p("PanOSPrivateIPv4", rand_private_ip()),
            p("PanOSGatewayPriority", random.randint(1, 3)),
            p("PanOSGatewaySelectionType", random.choice(["automatic", "manual"])),
        ]

    if stage == "disconnected":
        fields.append(p("PanOSLoginDuration", random.randint(60, 86400)))

    if stage == "auth-error":
        fields += [
            p("PanOSConnectionError", random.choice(_GP_CONN_ERRORS)),
            p("PanOSConnectionErrorID", random.randint(1, 20)),
        ]

    return sev, " ".join(fields)


class PaloAltoGenerator(BaseAppGenerator):
    LOG_TYPES = ["traffic", "threat", "system", "config", "globalprotect", "sls-traffic"]

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
            "traffic":       lambda: _traffic_log(dt, serial, src_ip, dst_ip, src_port, dst_port),
            "threat":        lambda: _threat_log(dt, serial, src_ip, dst_ip, src_port, dst_port),
            "system":        lambda: _system_log(dt, serial),
            "config":        lambda: _config_log(dt, serial),
            "globalprotect": lambda: _gp_log(dt, serial, host),
            "sls-traffic":   lambda: _sls_traffic_log(dt, serial, host, src_ip, dst_ip, src_port, dst_port),
        }
        if log_type not in generators:
            raise ValueError(
                f"Unknown PAN-OS log type '{log_type}'. Choices: {', '.join(self.LOG_TYPES)}"
            )

        result = generators[log_type]()
        body_app = None
        sd = {}

        if log_type in ("traffic", "threat"):
            default_sev, body, body_app = result
            sd = {
                "pan@2773": {
                    "type": log_type.upper(),
                    "src": src_ip,
                    "dst": dst_ip,
                    "app": body_app,
                }
            }
        elif log_type == "sls-traffic":
            default_sev, body, subtype = result
            sd = {"_cef": {"name": subtype}}
        else:
            default_sev, body = result

        sev = severity if severity is not None else default_sev

        # SLS log types originate from Strata Logging Service, not PAN-OS directly
        app_name_val = "LF" if log_type in ("globalprotect", "sls-traffic") else "PAN-OS"
        msg_id_val = "TRAFFIC" if log_type == "sls-traffic" else log_type.upper()

        return SyslogMessage(
            facility=fac,
            severity=sev,
            timestamp=dt,
            hostname=host,
            app_name=app_name_val,
            proc_id="-",
            msg_id=msg_id_val,
            structured_data=sd,
            message=body,
        )
