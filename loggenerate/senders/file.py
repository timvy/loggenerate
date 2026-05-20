from loggenerate.senders.base import BaseSender


class FileSender(BaseSender):
    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = None

    def open(self) -> None:
        self._fh = open(self.path, "ab")

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def send(self, message: str, octet_framing: bool = False) -> None:
        self._fh.write(self.frame(message, octet_framing))
        self._fh.flush()
