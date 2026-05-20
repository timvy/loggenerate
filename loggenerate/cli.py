import argparse
import random
import sys
import time

from loggenerate.apps import get_app_generator
from loggenerate.formats import get_formatter
from loggenerate.senders import get_sender


_EPILOG = """
Examples:
  # 10 PAN-OS traffic logs to stdout (RFC 5424)
  python -m loggenerate --app paloalto --count 10

  # Fortinet traffic logs to a file in RFC 3164 format
  python -m loggenerate --app fortinet --format rfc3164 --count 100 \\
      --output file --output-file /tmp/fortinet.log

  # F5 LTM logs to a remote syslog receiver over UDP
  python -m loggenerate --app f5 --log-type ltm --output syslog \\
      --host 192.168.1.100 --port 514 --protocol udp --count 50

  # PAN-OS threat logs over TCP with octet framing at 10 msg/s (infinite)
  python -m loggenerate --app paloalto --log-type threat --output syslog \\
      --host 192.168.1.100 --port 601 --protocol tcp --octet-framing \\
      --rate 10 --count 0

  # FortiGate UTM logs over TLS with custom CA
  python -m loggenerate --app fortinet --log-type utm --output syslog \\
      --host syslog.corp.example.com --port 6514 --protocol tls \\
      --tls-ca /etc/ssl/certs/ca.pem --count 20

Supported log types per application:
  generic   — (no --log-type needed)
  paloalto  — traffic, threat, system, config, globalprotect
  f5        — ltm, asm, apm
  fortinet  — traffic, utm, event

Strata Logging Service (SLS) CEF log types — use with --format cef:
  python -m loggenerate --app paloalto --log-type sls-globalprotect --format cef --count 5
  python -m loggenerate --app paloalto --log-type sls-traffic --format cef --count 5

Syslog facilities (--facility):
  0=kern  1=user  2=mail  3=daemon  4=auth  5=syslog
  16=local0 … 23=local7

Syslog severities (--severity):
  0=emerg  1=alert  2=crit  3=err  4=warning  5=notice  6=info  7=debug
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m loggenerate",
        description="Generate realistic syslog messages and send them to stdout, a file, or a syslog receiver.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )

    gen = p.add_argument_group("Message generation")
    gen.add_argument(
        "--app",
        choices=["generic", "paloalto", "f5", "fortinet"],
        default="generic",
        help="Application to simulate (default: generic)",
    )
    gen.add_argument(
        "--log-type", metavar="TYPE",
        help="Log sub-type for the chosen application (see epilog for valid values)",
    )
    gen.add_argument(
        "--format",
        choices=["rfc3164", "rfc5424", "cef"],
        default="rfc5424",
        help="Syslog message format (default: rfc5424)",
    )
    gen.add_argument(
        "--count", type=int, default=1, metavar="N",
        help="Number of messages to generate; 0 = infinite (default: 1)",
    )
    gen.add_argument(
        "--rate", type=float, default=0, metavar="MSG/S",
        help="Target send rate in messages per second; 0 = unlimited (default: 0)",
    )
    gen.add_argument(
        "--hostname",
        help="Override source hostname in generated messages",
    )
    gen.add_argument(
        "--facility", type=int, choices=range(0, 24), metavar="0-23",
        help="Override syslog facility number",
    )
    gen.add_argument(
        "--severity", type=int, choices=range(0, 8), metavar="0-7",
        help="Override syslog severity number",
    )
    gen.add_argument(
        "--seed", type=int,
        help="Random seed for reproducible output",
    )

    out = p.add_argument_group("Output destination")
    out.add_argument(
        "--output",
        choices=["stdout", "file", "syslog"],
        default="stdout",
        help="Where to send generated messages (default: stdout)",
    )
    out.add_argument(
        "--output-file", metavar="PATH",
        help="File path when --output=file",
    )

    net = p.add_argument_group("Network (--output syslog)")
    net.add_argument(
        "--host", default="127.0.0.1",
        help="Syslog receiver host (default: 127.0.0.1)",
    )
    net.add_argument(
        "--port", type=int, default=514,
        help="Syslog receiver port (default: 514)",
    )
    net.add_argument(
        "--protocol", choices=["udp", "tcp", "tls"], default="udp",
        help="Transport protocol (default: udp)",
    )
    net.add_argument(
        "--octet-framing", action="store_true",
        help="Enable RFC 6587 octet-counting framing (TCP/TLS only)",
    )

    tls = p.add_argument_group("TLS options (--protocol tls)")
    tls.add_argument("--tls-ca",   metavar="FILE", help="CA certificate file")
    tls.add_argument("--tls-cert", metavar="FILE", help="Client certificate file")
    tls.add_argument("--tls-key",  metavar="FILE", help="Client private key file")
    tls.add_argument(
        "--tls-no-verify", action="store_true",
        help="Disable TLS server certificate verification",
    )

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.output == "file" and not args.output_file:
        parser.error("--output-file is required when --output=file")
    if args.octet_framing and args.protocol == "udp":
        parser.error("--octet-framing is not supported with UDP (RFC 6587 §3.3)")

    _CEF_LOG_TYPES = {"sls-globalprotect", "sls-traffic"}
    if args.format == "cef":
        if args.app != "paloalto":
            parser.error("--format cef is only supported with --app paloalto")
        if args.log_type and args.log_type not in _CEF_LOG_TYPES:
            parser.error(
                f"--log-type '{args.log_type}' does not produce CEF output; "
                f"use sls-globalprotect or sls-traffic with --format cef"
            )
    if args.log_type in _CEF_LOG_TYPES and args.format != "cef":
        parser.error(
            f"--log-type {args.log_type} produces CEF output; add --format cef"
        )

    if args.seed is not None:
        random.seed(args.seed)

    app_gen   = get_app_generator(args.app)
    formatter = get_formatter(args.format)
    sender    = get_sender(args)

    sent = 0
    interval = 1.0 / args.rate if args.rate > 0 else 0

    try:
        with sender:
            while args.count == 0 or sent < args.count:
                msg = app_gen.generate(
                    hostname=args.hostname,
                    facility=args.facility,
                    severity=args.severity,
                    log_type=args.log_type,
                )
                line = formatter(msg)
                sender.send(line, octet_framing=args.octet_framing)
                sent += 1

                if interval and (args.count == 0 or sent < args.count):
                    time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\nInterrupted — sent {sent} message(s).", file=sys.stderr)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
