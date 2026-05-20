import socket
import ssl

from loggenerate.senders.base import BaseSender


class NetworkSender(BaseSender):
    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        tls_ca: str = None,
        tls_cert: str = None,
        tls_key: str = None,
        tls_no_verify: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.tls_ca = tls_ca
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_no_verify = tls_no_verify
        self._sock = None

    def open(self) -> None:
        if self.protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.protocol == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self.host, self.port))
        elif self.protocol == "tls":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if self.tls_no_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            elif self.tls_ca:
                ctx.load_verify_locations(self.tls_ca)
            else:
                ctx.load_default_certs()
            if self.tls_cert and self.tls_key:
                ctx.load_cert_chain(self.tls_cert, self.tls_key)
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
            self._sock.connect((self.host, self.port))
        else:
            raise ValueError(f"Unknown protocol '{self.protocol}'. Choices: udp, tcp, tls")

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def send(self, message: str, octet_framing: bool = False) -> None:
        # UDP is connectionless and doesn't support octet framing (RFC 6587 §3.3)
        data = self.frame(message, octet_framing and self.protocol != "udp")
        if self.protocol == "udp":
            self._sock.sendto(data, (self.host, self.port))
        else:
            self._sock.sendall(data)
