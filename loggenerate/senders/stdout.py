import sys

from loggenerate.senders.base import BaseSender


class StdoutSender(BaseSender):
    def send(self, message: str, octet_framing: bool = False) -> None:
        if octet_framing:
            msg_bytes = message.encode("utf-8")
            sys.stdout.buffer.write(f"{len(msg_bytes)} ".encode() + msg_bytes + b"\n")
            sys.stdout.buffer.flush()
        else:
            print(message)
