from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional


FACILITY_NAMES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3,
    "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
    "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

SEVERITY_NAMES = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}


@dataclass
class SyslogMessage:
    facility: int
    severity: int
    timestamp: datetime
    hostname: str
    app_name: str
    proc_id: str = "-"
    msg_id: str = "-"
    structured_data: Dict[str, Dict[str, str]] = field(default_factory=dict)
    message: str = ""
    # When set, RFC 3164 uses this string verbatim as the TAG instead of
    # constructing "app_name[proc_id]". Needed for devices (e.g. F5) that
    # embed a severity keyword before the process name.
    rfc3164_tag: Optional[str] = None

    @property
    def priority(self) -> int:
        return (self.facility * 8) + self.severity
