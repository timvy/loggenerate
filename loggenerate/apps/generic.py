import random
from typing import Optional

from loggenerate.apps.base import BaseAppGenerator
from loggenerate.models import SyslogMessage
from loggenerate.utils import (
    now_utc, rand_private_ip, rand_public_ip,
    rand_ephemeral_port, rand_well_known_port,
)

_MESSAGES = [
    "Connection established from {src}:{sp} to {dst}:{dp}",
    "Connection closed from {src}:{sp} to {dst}:{dp} after {dur}s",
    "User {user} authenticated successfully from {src}",
    "Failed authentication attempt for user {user} from {src}",
    "Service restarted after configuration reload",
    "Disk usage at {pct}% on /var/log",
    "Memory usage: {used}MB / {total}MB ({mpct}%)",
    "CPU usage spike: {cpu}% on core {core}",
    "Connection timeout waiting for response from {dst}:{dp}",
    "TLS handshake completed with {dst}:{dp} (TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384)",
    "Rate limit triggered: {src} exceeded {rate} req/s",
    "Health check failed for backend {dst}:{dp}",
    "Health check recovered for backend {dst}:{dp}",
    "Certificate expiry warning: cert for {dst} expires in {days} days",
]

_USERS = ["admin", "root", "operator", "monitor", "service", "backup"]


class GenericAppGenerator(BaseAppGenerator):
    def generate(
        self,
        hostname: Optional[str] = None,
        facility: Optional[int] = None,
        severity: Optional[int] = None,
        log_type: Optional[str] = None,
    ) -> SyslogMessage:
        src = rand_private_ip()
        dst = rand_public_ip()
        sp = rand_ephemeral_port()
        dp = rand_well_known_port()
        used = random.randint(1024, 16384)
        total = 16384

        message = random.choice(_MESSAGES).format(
            src=src, sp=sp, dst=dst, dp=dp,
            dur=random.randint(1, 3600),
            user=random.choice(_USERS),
            pct=random.randint(60, 99),
            used=used, total=total,
            mpct=round(used / total * 100),
            cpu=random.randint(10, 99),
            core=random.randint(0, 7),
            rate=random.randint(100, 10000),
            days=random.randint(1, 30),
        )

        return SyslogMessage(
            facility=facility if facility is not None else 1,   # user
            severity=severity if severity is not None else 6,   # info
            timestamp=now_utc(),
            hostname=hostname or "server01",
            app_name="application",
            proc_id=str(random.randint(1000, 65535)),
            message=message,
        )
