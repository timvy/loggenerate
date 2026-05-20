"""
Fortinet FortiGate syslog log generator.

Supported log types: traffic, utm, event

FortiGate uses a key=value pair format for all log types.
The PRI header uses facility local7 (23) and the level keyword
appears both in the PRI severity and as level="..." in the KV body.

Reference: FortiOS 7.x Log Reference
  https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference
"""

import random
import uuid
from typing import Optional

from loggenerate.apps.base import BaseAppGenerator
from loggenerate.models import SyslogMessage
from loggenerate.utils import (
    now_utc, rand_private_ip, rand_public_ip,
    rand_ephemeral_port, rand_well_known_port,
    rand_country, rand_application, rand_user,
    rand_bytes_pair, rand_packets_pair,
    fortinet_date, fortinet_time,
)

_HOSTNAMES = ["FGT60F", "FGT100E", "FGT200F", "FGT-EDGE-01", "FGT-DC-01"]
_MODELS = {
    "FGT60F":     "FG60F",
    "FGT100E":    "FG100E",
    "FGT200F":    "FG200F",
    "FGT-EDGE-01":"FG200F",
    "FGT-DC-01":  "FG400E",
}
_INTERFACES = ["port1", "port2", "port3", "port4", "wan1", "wan2", "internal", "dmz"]
_IFACE_ROLES = {"port1": "lan", "port2": "lan", "wan1": "wan", "wan2": "wan",
                "internal": "lan", "dmz": "dmz", "port3": "undefined", "port4": "undefined"}
_ACTIONS = ["accept", "deny", "close", "timeout"]
_SERVICES = ["HTTPS", "HTTP", "DNS", "SMTP", "SSH", "FTP", "RDP", "LDAP"]
_VD = ["root", "vdom1", "vdom2"]
_LEVEL_MAP = {6: "information", 5: "notice", 4: "warning", 3: "error", 2: "critical"}

# UTM sub-types and their typical fields
_UTM_IPS_ATTACKS = [
    ("1:30583", "MS.Windows.SMB.Server.Trans2.Request.Handling.Buffer.Overflow", "critical", "block"),
    ("1:57832", "HTTP.GET.Parameter.SQL.Injection", "high",     "block"),
    ("1:28730", "ET MALWARE Possible WannaCry Check-in",         "critical", "block"),
    ("1:44641", "Log4Shell Remote Code Execution",               "critical", "block"),
    ("1:10013", "PHP.CGI.Remote.File.Include",                   "medium",   "pass"),
    ("1:33516", "MS.IIS.Remote.Code.Execution",                  "high",     "block"),
]
_WEBFILTER_CATS = [
    ("malicious-websites", "malware",  "block"),
    ("phishing",           "phishing", "block"),
    ("social-networking",  "social",   "warning"),
    ("pornography",        "adult",    "block"),
    ("gambling",           "gambling", "block"),
    ("online-gaming",      "games",    "warning"),
]
_SYSTEM_EVENTS = [
    ("0100044546", "system", "Configuration changed by admin"),
    ("0100044034", "system", "Admin admin login successful from {ip}"),
    ("0100044038", "system", "Admin admin login failed from {ip}"),
    ("0100032002", "ha",     "HA state changed to master"),
    ("0100032102", "ha",     "HA cluster synchronized"),
    ("0102043039", "update", "IPS definitions updated to version 22.613"),
    ("0100022923", "system", "Interface wan1 link is up"),
    ("0100022924", "system", "Interface wan1 link is down"),
]
_VPN_EVENTS = [
    ("0101037127", "SSL VPN tunnel up for user {user} from {ip}"),
    ("0101037129", "SSL VPN tunnel down for user {user} from {ip}"),
    ("0101039424", "IPsec tunnel VPN-to-HQ is up"),
    ("0101039426", "IPsec tunnel VPN-to-HQ went down: peer is unreachable"),
    ("0101039946", "IPsec IKE phase 1 SA established: {ip} <-> {peer}"),
]


def _kv(pairs: list) -> str:
    """Render a list of (key, value) tuples into FortiGate key=value format."""
    parts = []
    for k, v in pairs:
        if isinstance(v, str) and (" " in v or not v.isdigit()):
            parts.append(f'{k}="{v}"')
        else:
            parts.append(f"{k}={v}")
    return " ".join(parts)


def _traffic_log(dt, devname, devid) -> tuple:
    src_ip = rand_private_ip()
    dst_ip = rand_public_ip()
    src_port = rand_ephemeral_port()
    dst_port = rand_well_known_port()
    sent, recv = rand_bytes_pair()
    sent_pkts, recv_pkts = rand_packets_pair()
    src_iface = random.choice(["port1", "port2", "internal"])
    dst_iface = random.choice(["wan1", "wan2"])
    action = random.choice(_ACTIONS)
    service = random.choice(_SERVICES)
    sev = 6 if action == "accept" else 4
    level = _LEVEL_MAP[sev]
    logid = "0000000013"
    poluuid = str(uuid.uuid4())

    pairs = [
        ("date",        fortinet_date(dt)),
        ("time",        fortinet_time(dt)),
        ("devname",     devname),
        ("devid",       devid),
        ("eventtime",   int(dt.timestamp() * 1_000_000_000)),
        ("tz",          "+0000"),
        ("logid",       logid),
        ("type",        "traffic"),
        ("subtype",     "forward"),
        ("level",       level),
        ("vd",          random.choice(_VD)),
        ("srcip",       src_ip),
        ("srcport",     src_port),
        ("srcintf",     src_iface),
        ("srcintfrole", _IFACE_ROLES.get(src_iface, "undefined")),
        ("dstip",       dst_ip),
        ("dstport",     dst_port),
        ("dstintf",     dst_iface),
        ("dstintfrole", _IFACE_ROLES.get(dst_iface, "wan")),
        ("poluuid",     poluuid),
        ("sessionid",   random.randint(10_000, 9_999_999)),
        ("proto",       6 if dst_port in (80, 443, 8080, 8443) else 17),
        ("action",      action),
        ("policyid",    random.randint(1, 50)),
        ("policytype",  "policy"),
        ("service",     service),
        ("dstcountry",  rand_country()),
        ("srccountry",  "Reserved"),
        ("trandisp",    "snat"),
        ("transip",     rand_public_ip()),
        ("transport",   rand_ephemeral_port()),
        ("duration",    random.randint(1, 600)),
        ("sentbyte",    sent),
        ("rcvdbyte",    recv),
        ("sentpkt",     sent_pkts),
        ("rcvdpkt",     recv_pkts),
        ("appcat",      "unscanned"),
    ]
    return sev, _kv(pairs)


def _utm_ips_log(dt, devname, devid) -> tuple:
    src_ip = rand_private_ip()
    dst_ip = rand_public_ip()
    src_port = rand_ephemeral_port()
    dst_port = rand_well_known_port()
    sigid, attack, sev_str, action = random.choice(_UTM_IPS_ATTACKS)
    sev = 2 if sev_str == "critical" else (3 if sev_str == "high" else 4)

    pairs = [
        ("date",      fortinet_date(dt)),
        ("time",      fortinet_time(dt)),
        ("devname",   devname),
        ("devid",     devid),
        ("eventtime", int(dt.timestamp() * 1_000_000_000)),
        ("tz",        "+0000"),
        ("logid",     "0419016384"),
        ("type",      "utm"),
        ("subtype",   "ips"),
        ("level",     _LEVEL_MAP.get(sev, "warning")),
        ("vd",        random.choice(_VD)),
        ("severity",  sev_str),
        ("srcip",     src_ip),
        ("srccountry","Reserved"),
        ("dstip",     dst_ip),
        ("dstcountry",rand_country()),
        ("srcintf",   random.choice(["port1", "internal"])),
        ("dstintf",   random.choice(["wan1", "wan2"])),
        ("sessionid", random.randint(10_000, 9_999_999)),
        ("action",    action),
        ("proto",     6),
        ("service",   "HTTP"),
        ("policyid",  random.randint(1, 50)),
        ("attack",    attack),
        ("srcport",   src_port),
        ("dstport",   dst_port),
        ("attackid",  sigid),
        ("sensor",    "default"),
        ("ref",       f"http://www.fortinet.com/ids/VID{sigid.split(':')[1]}"),
        ("msg",       f"ips: {attack}"),
    ]
    return sev, _kv(pairs)


def _utm_webfilter_log(dt, devname, devid) -> tuple:
    src_ip = rand_private_ip()
    dst_ip = rand_public_ip()
    cat_name, cat_id, action = random.choice(_WEBFILTER_CATS)
    url = f"http://{dst_ip}/{'badpage' if action == 'block' else 'page'}"
    sev = 4 if action == "block" else 6

    pairs = [
        ("date",      fortinet_date(dt)),
        ("time",      fortinet_time(dt)),
        ("devname",   devname),
        ("devid",     devid),
        ("eventtime", int(dt.timestamp() * 1_000_000_000)),
        ("tz",        "+0000"),
        ("logid",     "0316013056"),
        ("type",      "utm"),
        ("subtype",   "webfilter"),
        ("level",     _LEVEL_MAP.get(sev, "warning")),
        ("vd",        random.choice(_VD)),
        ("srcip",     src_ip),
        ("srcport",   rand_ephemeral_port()),
        ("srcintf",   "port1"),
        ("dstip",     dst_ip),
        ("dstport",   80),
        ("dstintf",   "wan1"),
        ("proto",     6),
        ("service",   "HTTP"),
        ("hostname",  dst_ip),
        ("profile",   "default"),
        ("action",    action),
        ("reqtype",   "direct"),
        ("url",       url),
        ("sentbyte",  random.randint(200, 2000)),
        ("rcvdbyte",  random.randint(200, 50000)),
        ("direction", "outgoing"),
        ("urlsource", "Local URLfilter Block"),
        ("cat",       random.randint(1, 90)),
        ("catdesc",   cat_name),
        ("msg",       f"URL belongs to a denied category in policy"),
    ]
    return sev, _kv(pairs)


def _event_system_log(dt, devname, devid) -> tuple:
    logid, subtype, tmpl = random.choice(_SYSTEM_EVENTS)
    admin_ip = rand_private_ip()
    desc = tmpl.format(ip=admin_ip)
    sev = 5

    pairs = [
        ("date",    fortinet_date(dt)),
        ("time",    fortinet_time(dt)),
        ("devname", devname),
        ("devid",   devid),
        ("eventtime", int(dt.timestamp() * 1_000_000_000)),
        ("tz",      "+0000"),
        ("logid",   logid),
        ("type",    "event"),
        ("subtype", subtype),
        ("level",   "notice"),
        ("vd",      "root"),
        ("logdesc", desc),
        ("msg",     desc),
    ]
    return sev, _kv(pairs)


def _event_vpn_log(dt, devname, devid) -> tuple:
    logid, tmpl = random.choice(_VPN_EVENTS)
    user = rand_user()
    ip = rand_private_ip()
    peer = rand_public_ip()
    desc = tmpl.format(user=user, ip=ip, peer=peer)
    sev = 5

    pairs = [
        ("date",    fortinet_date(dt)),
        ("time",    fortinet_time(dt)),
        ("devname", devname),
        ("devid",   devid),
        ("eventtime", int(dt.timestamp() * 1_000_000_000)),
        ("tz",      "+0000"),
        ("logid",   logid),
        ("type",    "event"),
        ("subtype", "vpn"),
        ("level",   "notice"),
        ("vd",      "root"),
        ("logdesc", "SSL VPN tunnel statistics"),
        ("action",  "tunnel-up" if "up" in desc.lower() else "tunnel-down"),
        ("tunneltype", "ssl-web"),
        ("tunnelid",   random.randint(1000, 9999)),
        ("remip",   ip),
        ("user",    user),
        ("group",   "VPN-Users"),
        ("dst_host","N/A"),
        ("msg",     desc),
    ]
    return sev, _kv(pairs)


class FortinetGenerator(BaseAppGenerator):
    LOG_TYPES = ["traffic", "utm", "event"]

    def generate(
        self,
        hostname: Optional[str] = None,
        facility: Optional[int] = None,
        severity: Optional[int] = None,
        log_type: Optional[str] = None,
    ) -> SyslogMessage:
        dt = now_utc()
        devname = hostname or random.choice(_HOSTNAMES)
        model_prefix = _MODELS.get(devname, "FG200F")
        devid = f"{model_prefix}{random.randint(1_000_000_000, 9_999_999_999):010d}"
        fac = facility if facility is not None else 23  # local7
        log_type = log_type or random.choice(self.LOG_TYPES)

        utm_subtypes = [_utm_ips_log, _utm_webfilter_log]
        event_subtypes = [_event_system_log, _event_vpn_log]

        generators = {
            "traffic": lambda: _traffic_log(dt, devname, devid),
            "utm":     lambda: random.choice(utm_subtypes)(dt, devname, devid),
            "event":   lambda: random.choice(event_subtypes)(dt, devname, devid),
        }
        if log_type not in generators:
            raise ValueError(
                f"Unknown Fortinet log type '{log_type}'. Choices: {', '.join(self.LOG_TYPES)}"
            )

        default_sev, body = generators[log_type]()
        sev = severity if severity is not None else default_sev

        return SyslogMessage(
            facility=fac,
            severity=sev,
            timestamp=dt,
            hostname=devname,
            app_name="FortiGate",
            proc_id="-",
            msg_id=log_type.upper(),
            structured_data={},
            message=body,
        )
