from loggenerate.models import SyslogMessage

_SYSLOG_TO_CEF_SEV = {0: 10, 1: 9, 2: 8, 3: 7, 4: 6, 5: 5, 6: 3, 7: 1}


def _escape_header(v: str) -> str:
    return v.replace("\\", "\\\\").replace("|", "\\|")


def format_message(msg: SyslogMessage) -> str:
    """
    CEF:0|Vendor|Product|Version|EventClassID|Name|Severity|Extension
    msg.app_name   → Device Product  (e.g. "LF" for Strata Logging Service)
    msg.msg_id     → Device Event Class ID  (e.g. "GLOBALPROTECT")
    msg.message    → pre-built extension key=value string (built by the generator)
    """
    cef_sev = _SYSLOG_TO_CEF_SEV.get(msg.severity, 3)
    vendor = _escape_header("Palo Alto Networks")
    product = _escape_header(msg.app_name or "LF")
    event_class = _escape_header(msg.msg_id or "-")
    name = _escape_header((msg.msg_id or "-").lower())
    return f"CEF:0|{vendor}|{product}|2.0|{event_class}|{name}|{cef_sev}|{msg.message}"
