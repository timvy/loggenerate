"""
F5 BIG-IP syslog log generator.

Supported log types: ltm, asm, apm

LTM (Local Traffic Manager) format
  <PRI>Mmm DD HH:MM:SS bigip SEVERITY proc[PID]: ERRCODE:SEV: MESSAGE
  F5 embeds a severity keyword between the hostname and process name in the
  syslog TAG field — handled via rfc3164_tag in SyslogMessage.

ASM (Application Security Manager / WAF) format
  Message body is a comma-separated key=value block prefixed with "ASM:".

APM (Access Policy Manager) format
  Same error-code pattern as LTM but from the apmd process.

Error code format: XXXXXXXX:Y:
  XX       — module ID (01 = TMM, 02 = MCPD, 03 = httpd …)
  XXXXXX   — error number within module
  :Y:      — log level digit (mirrors syslog severity 0-7)
"""

import random
from typing import Optional

from loggenerate.apps.base import BaseAppGenerator
from loggenerate.models import SyslogMessage
from loggenerate.utils import (
    now_utc, rand_private_ip, rand_public_ip,
    rand_ephemeral_port, rand_well_known_port,
    rand_country, rand_user,
)

_HOSTNAMES = [
    "bigip1.corp.example.com", "bigip2.corp.example.com",
    "f5-ltm-01", "f5-prod-01", "f5-dr-01",
]
_VIRTUALS = [
    "/Common/vs_app_http", "/Common/vs_app_https",
    "/Common/vs_rdp", "/Common/vs_api_gw",
]
_POOLS = [
    "/Common/pool_web", "/Common/pool_api",
    "/Common/pool_app", "/Common/pool_db",
]
_POLICIES = [
    "/Common/asm_policy_strict", "/Common/asm_policy_relaxed",
    "/Common/waf_policy_api",
]
_ATTACK_TYPES = [
    "SQL Injection", "Cross-site Scripting", "CSRF",
    "Directory Traversal", "Command Injection", "HTTP Response Splitting",
]
_VIOLATIONS = [
    "SQL-Injection", "XSS", "CSRF",
    "Evasion-Technique", "HTTP-protocol-compliance-failed",
    "Illegal-file-type", "Illegal-method",
]
_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
_URIS = ["/app/login", "/api/v1/users", "/admin/", "/search", "/upload", "/api/v2/data"]
_SEV_NAMES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# (error_code, sev_digit, process, message_template)
# sev_digit mirrors the syslog severity level digit used after the colon
_LTM_EVENTS = [
    ("01010028", 4, "tmm",  "Pool member {member}:{mport} monitor status down."),
    ("01010201", 5, "tmm",  "Pool member {member}:{mport} monitor status up."),
    ("01260013", 3, "tmm",  "SSL Handshake failed for TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"),
    ("01070640", 3, "tmm",  "SSL: CA_BUNDLE error, error:14090086:SSL routines:"
                            "SSL3_GET_SERVER_CERTIFICATE:certificate verify failed for {dst_ip}:{dst_port}"),
    ("01070734", 3, "tmm",  "Connection error: hsl {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                            "(Error: Connection refused)"),
    ("01220001", 5, "tmm",  "Connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} "
                            "VS: {virtual} pool: {pool}"),
    ("01420002", 6, "tmm",  "AUDIT - client {src_ip} request: GET {uri} HTTP/1.1 response: 200"),
    ("01230140", 5, "tmm",  "Limiting open port RST response from {src_ip}:{src_port} "
                            "to {dst_ip}:{dst_port} to 250 packets/sec"),
    ("01260009", 3, "tmm",  "Connection error: ssl_hs_rxhello:38: "
                            "unsupported version from {src_ip}:{src_port}"),
    ("0107143e", 5, "tmm",  "Node {member}:{mport} monitor status down; "
                            "state: unchecked; reason: No successful responses received before deadline."),
]

_APM_EVENTS = [
    ("01490005", 5, "apmd", "/Common/access_profile:Common:{session}: "
                            "Received session variable 'session.server.network.name' = '{pool}'"),
    ("01490107", 4, "apmd", "/Common/access_profile:Common:{session}: "
                            "Access policy result: Logon_Denied"),
    ("014e0003", 5, "apmd", "/Common/access_profile:Common:{session}: "
                            "Session started from client IP {src_ip}"),
    ("01490127", 5, "apmd", "/Common/access_profile:Common:{session}: "
                            "Following rule from 'logon_page' to 'ad_auth'"),
    ("014e0025", 5, "apmd", "/Common/access_profile:Common:{session}: "
                            "Logout request from {src_ip}"),
]


def _ltm_log(src_ip, dst_ip, src_port, dst_port, hostname) -> tuple:
    err_code, sev_digit, proc, tmpl = random.choice(_LTM_EVENTS)
    member = rand_private_ip()
    pid = random.randint(1000, 65535)
    session = f"{random.randint(0, 0xffffffff):08x}"
    pool = random.choice(_POOLS)
    virtual = random.choice(_VIRTUALS)
    uri = random.choice(_URIS)

    text = tmpl.format(
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        member=member, mport=rand_well_known_port(),
        session=session, pool=pool, virtual=virtual, uri=uri,
    )
    sev_kw = _SEV_NAMES[sev_digit]
    # F5 RFC 3164 TAG: "notice tmm[12345]"
    rfc3164_tag = f"{sev_kw} {proc}[{pid}]"
    # Message body includes the error code prefix
    message = f"{err_code}:{sev_digit}: {text}"
    return sev_digit, proc, str(pid), rfc3164_tag, message


def _apm_log(src_ip, hostname) -> tuple:
    err_code, sev_digit, proc, tmpl = random.choice(_APM_EVENTS)
    pid = random.randint(1000, 65535)
    session = f"{random.randint(0, 0xffffffff):08x}"
    pool = random.choice(_POOLS)

    text = tmpl.format(src_ip=src_ip, session=session, pool=pool)
    sev_kw = _SEV_NAMES[sev_digit]
    rfc3164_tag = f"{sev_kw} {proc}[{pid}]"
    message = f"{err_code}:{sev_digit}: {text}"
    return sev_digit, proc, str(pid), rfc3164_tag, message


def _asm_log(dt, hostname, src_ip, dst_ip) -> tuple:
    attack_type = random.choice(_ATTACK_TYPES)
    violation = random.choice(_VIOLATIONS)
    method = random.choice(_METHODS)
    uri = random.choice(_URIS)
    policy = random.choice(_POLICIES)
    dst_port = rand_well_known_port()
    src_port = rand_ephemeral_port()
    support_id = str(random.randint(10_000_000_000_000, 99_999_999_999_999))
    qs = "id%3D1%27" if "SQL" in attack_type else "q%3D%3Cscript%3E"
    sig_id = str(random.randint(200_000_000, 299_999_999))

    pairs = [
        ("unit_hostname",        hostname),
        ("management_ip_address", rand_private_ip()),
        ("http_class_name",      policy),
        ("web_application_name", policy),
        ("policy_name",          policy),
        ("violations",           violation),
        ("support_id",           support_id),
        ("request_status",       "blocked"),
        ("response_code",        "0"),
        ("ip_client",            src_ip),
        ("route_domain",         "0"),
        ("method",               method),
        ("protocol",             "HTTP"),
        ("query_string",         qs),
        ("x_forwarded_for_header_value", "N/A"),
        ("sig_ids",              sig_id),
        ("sig_names",            f"{attack_type} (Headers)"),
        ("date_time",            dt.strftime("%Y-%m-%d %H:%M:%S")),
        ("severity",             "Critical"),
        ("attack_type",          attack_type),
        ("geo_location",         rand_country()),
        ("ip_reputation",        "N/A"),
        ("username",             "N/A"),
        ("session_id",           "N/A"),
        ("src_port",             str(src_port)),
        ("dest_port",            str(dst_port)),
        ("dest_ip",              dst_ip),
        ("sub_violations",       f"{violation}:{attack_type} detected in parameter value"),
        ("virus",                "N/A"),
        ("violation_rating",     str(random.randint(3, 5))),
        ("uri",                  uri),
        ("request",              f"{method} {uri}?{qs} HTTP/1.1\\r\\nHost: {dst_ip}\\r\\n"),
    ]
    body = "ASM:" + ",".join(f'{k}="{v}"' for k, v in pairs)
    return 4, "ASM", "-", "ASM", body   # sev=warning


class F5BigIPGenerator(BaseAppGenerator):
    LOG_TYPES = ["ltm", "asm", "apm"]

    def generate(
        self,
        hostname: Optional[str] = None,
        facility: Optional[int] = None,
        severity: Optional[int] = None,
        log_type: Optional[str] = None,
    ) -> SyslogMessage:
        dt = now_utc()
        host = hostname or random.choice(_HOSTNAMES)
        fac = facility if facility is not None else 16  # local0
        log_type = log_type or random.choice(self.LOG_TYPES)

        src_ip = rand_private_ip()
        dst_ip = rand_public_ip()
        src_port = rand_ephemeral_port()
        dst_port = rand_well_known_port()

        if log_type == "ltm":
            default_sev, app_name, proc_id, rfc3164_tag, message = _ltm_log(
                src_ip, dst_ip, src_port, dst_port, host
            )
        elif log_type == "apm":
            default_sev, app_name, proc_id, rfc3164_tag, message = _apm_log(src_ip, host)
        elif log_type == "asm":
            default_sev, app_name, proc_id, rfc3164_tag, message = _asm_log(
                dt, host, src_ip, dst_ip
            )
        else:
            raise ValueError(
                f"Unknown F5 log type '{log_type}'. Choices: {', '.join(self.LOG_TYPES)}"
            )

        return SyslogMessage(
            facility=fac,
            severity=severity if severity is not None else default_sev,
            timestamp=dt,
            hostname=host,
            app_name=app_name,
            proc_id=proc_id,
            msg_id="-",
            rfc3164_tag=rfc3164_tag if log_type != "asm" else None,
            message=message,
        )
