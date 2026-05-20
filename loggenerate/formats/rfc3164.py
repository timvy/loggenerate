from loggenerate.models import SyslogMessage

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def format_message(msg: SyslogMessage) -> str:
    """
    RFC 3164 BSD syslog:
      <PRI>Mmm DD HH:MM:SS HOSTNAME TAG[PID]: MSG
    Day is space-padded; year is omitted.
    """
    ts = msg.timestamp
    timestamp = (
        f"{_MONTHS[ts.month - 1]} {ts.day:2d} "
        f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d}"
    )

    if msg.rfc3164_tag:
        tag = msg.rfc3164_tag
    elif msg.proc_id and msg.proc_id != "-":
        tag = f"{msg.app_name}[{msg.proc_id}]"
    else:
        tag = msg.app_name

    return f"<{msg.priority}>{timestamp} {msg.hostname} {tag}: {msg.message}"
