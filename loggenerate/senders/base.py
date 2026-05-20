from abc import ABC, abstractmethod


class BaseSender(ABC):
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    @abstractmethod
    def send(self, message: str, octet_framing: bool = False) -> None:
        pass

    @staticmethod
    def frame(message: str, octet_framing: bool) -> bytes:
        """
        RFC 6587 framing:
          non-transparent  → message bytes + LF
          octet counting   → "<len> " + message bytes + LF
        The trailing LF is added even in octet-counting mode for
        compatibility with mixed-mode receivers; the length count
        covers only the message bytes themselves.
        """
        msg_bytes = message.encode("utf-8")
        if octet_framing:
            return f"{len(msg_bytes)} ".encode() + msg_bytes + b"\n"
        return msg_bytes + b"\n"
