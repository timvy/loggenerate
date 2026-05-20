from abc import ABC, abstractmethod
from typing import Optional

from loggenerate.models import SyslogMessage


class BaseAppGenerator(ABC):
    @abstractmethod
    def generate(
        self,
        hostname: Optional[str] = None,
        facility: Optional[int] = None,
        severity: Optional[int] = None,
        log_type: Optional[str] = None,
    ) -> SyslogMessage:
        pass
