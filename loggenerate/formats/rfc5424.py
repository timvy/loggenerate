from loggenerate.models import SyslogMessage


def _escape_sd_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_message(msg: SyslogMessage) -> str:
    """
    RFC 5424 syslog:
      <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    Timestamp is RFC 3339 with millisecond precision and UTC 'Z' suffix.
    """
    ts = msg.timestamp
    timestamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"

    if msg.structured_data:
        sd_parts = []
        for sd_id, params in msg.structured_data.items():
            parts = [sd_id]
            for k, v in params.items():
                parts.append(f'{k}="{_escape_sd_value(str(v))}"')
            sd_parts.append(f"[{' '.join(parts)}]")
        sd = "".join(sd_parts)
    else:
        sd = "-"

    proc_id = msg.proc_id or "-"
    msg_id = msg.msg_id or "-"
    hostname = msg.hostname or "-"
    app_name = msg.app_name or "-"

    return (
        f"<{msg.priority}>1 {timestamp} {hostname} "
        f"{app_name} {proc_id} {msg_id} {sd} {msg.message}"
    )
