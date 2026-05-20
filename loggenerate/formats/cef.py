from loggenerate.models import SyslogMessage


def format_message(msg: SyslogMessage) -> str:
    """Wraps a pre-built CEF line (msg.message) in an RFC 5424 syslog envelope."""
    pri = (msg.facility * 8) + msg.severity
    ts = msg.timestamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{msg.timestamp.microsecond // 1000:03d}Z"
    hostname = msg.hostname or "-"
    app_name = msg.app_name or "-"
    proc_id = msg.proc_id or "-"
    msg_id = msg.msg_id or "-"
    return f"<{pri}>1 {ts} {hostname} {app_name} {proc_id} {msg_id} - {msg.message}"
