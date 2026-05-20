from loggenerate.senders.stdout import StdoutSender
from loggenerate.senders.file import FileSender
from loggenerate.senders.network import NetworkSender


def get_sender(args):
    if args.output == "stdout":
        return StdoutSender()
    if args.output == "file":
        return FileSender(args.output_file)
    if args.output == "syslog":
        return NetworkSender(
            host=args.host,
            port=args.port,
            protocol=args.protocol,
            tls_ca=getattr(args, "tls_ca", None),
            tls_cert=getattr(args, "tls_cert", None),
            tls_key=getattr(args, "tls_key", None),
            tls_no_verify=getattr(args, "tls_no_verify", False),
        )
    raise ValueError(f"Unknown output '{args.output}'")
