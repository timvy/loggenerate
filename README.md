# loggenerate

Realistic syslog message generator for network security devices. Generates vendor-accurate log output for testing SIEM ingestion, log parsers, and syslog pipelines — with no external dependencies.

## Quick start

```bash
# stdout, RFC 5424 (default)
python3 -m loggenerate --app paloalto --count 10

# RFC 3164 to a file
python3 -m loggenerate --app paloalto --log-type traffic --format rfc3164 \
    --count 1000 --output file --output-file /tmp/pan-traffic.log

# Stream to a remote syslog receiver over TCP
python3 -m loggenerate --app fortinet --log-type utm --output syslog \
    --host 192.168.1.100 --port 514 --protocol tcp --count 500

# Infinite stream at 100 msg/s over TLS
python3 -m loggenerate --app paloalto --log-type threat --output syslog \
    --host siem.corp.example.com --port 6514 --protocol tls \
    --rate 100 --count 0

# Reproducible output
python3 -m loggenerate --app paloalto --count 5 --seed 42
```

## Supported applications and log types

| `--app` | `--log-type` | `--format` | Description |
|---------|-------------|------------|-------------|
| `generic` | *(none)* | rfc3164, **rfc5424** | Generic syslog messages |
| `paloalto` | `traffic` | rfc3164, **rfc5424** | PAN-OS 10.2+ traffic logs (118-field CSV) |
| `paloalto` | `threat` | rfc3164, **rfc5424** | PAN-OS threat/URL/vulnerability logs |
| `paloalto` | `system` | rfc3164, **rfc5424** | PAN-OS system events |
| `paloalto` | `config` | rfc3164, **rfc5424** | PAN-OS configuration change logs |
| `paloalto` | `globalprotect` | rfc3164, **rfc5424** | PAN-OS GlobalProtect logs (50-field CSV) |
| `paloalto` | `sls-globalprotect` | **cef** | Strata Logging Service GlobalProtect CEF |
| `paloalto` | `sls-traffic` | **cef** | Strata Logging Service traffic CEF |
| `f5` | `ltm` | rfc3164, **rfc5424** | F5 BIG-IP Local Traffic Manager |
| `f5` | `asm` | rfc3164, **rfc5424** | F5 BIG-IP Application Security Manager |
| `f5` | `apm` | rfc3164, **rfc5424** | F5 BIG-IP Access Policy Manager |
| `fortinet` | `traffic` | rfc3164, **rfc5424** | FortiGate traffic logs |
| `fortinet` | `utm` | rfc3164, **rfc5424** | FortiGate UTM (IPS, web filter, AV) |
| `fortinet` | `event` | rfc3164, **rfc5424** | FortiGate event logs |

Default format is **rfc5424**. `sls-*` log types require `--format cef` and generate RFC 5424-wrapped CEF matching the Strata Logging Service on-wire format.

When `--log-type` is omitted, a random non-CEF type is chosen for the selected app.

## Options

```
Message generation:
  --app           Application to simulate (default: generic)
  --log-type      Log sub-type for the chosen application
  --format        rfc3164 | rfc5424 | cef  (default: rfc5424)
  --count N       Messages to generate; 0 = infinite  (default: 1)
  --rate MSG/S    Send rate in messages/second; 0 = unlimited  (default: 0)
  --hostname      Override source hostname
  --facility      Syslog facility number (0–23)
  --severity      Syslog severity number (0–7)
  --seed          Random seed for reproducible output

Output destination:
  --output        stdout | file | syslog  (default: stdout)
  --output-file   File path when --output=file

Network (--output syslog):
  --host          Receiver host  (default: 127.0.0.1)
  --port          Receiver port  (default: 514)
  --protocol      udp | tcp | tls  (default: udp)
  --octet-framing RFC 6587 octet-counting framing (TCP/TLS only)

TLS (--protocol tls):
  --tls-ca        CA certificate file
  --tls-cert      Client certificate file
  --tls-key       Client private key file
  --tls-no-verify Disable server certificate verification
```

## Output examples

**PAN-OS traffic — RFC 5424**
```
<134>1 2026-05-20T13:40:44.858Z PA-VM50 PAN-OS - TRAFFIC [pan@2773 type="TRAFFIC" src="10.107.68.145" dst="76.76.19.19" app="sap"] 1,2026/05/20 13:40:44,123456789012,TRAFFIC,end,2048,...
```

**PAN-OS traffic — RFC 3164**
```
<134>May 20 13:40:45 PA-EDGE-01 PAN-OS: 1,2026/05/20 13:40:45,987654321098,TRAFFIC,end,2048,...
```

**Strata Logging Service traffic — CEF (wrapped in RFC 5424)**
```
<14>1 2026-05-20T13:22:46.121Z logfwd20-8303414a-1714-4b57-91bd-a974db22576b-taskmanager-5brhj logforwarder - panwlogs - CEF:0|Palo Alto Networks|LF|2.0|TRAFFIC|end|3|dtz=UTC rt=May 20 2026 13:22:45 deviceExternalId=007951000755670 PanOSConfigVersion=11.2 ...
```

## Architecture

```
Generator (apps/)  →  Formatter (formats/)  →  Sender (senders/)
```

- **Generators** produce a `SyslogMessage` with a vendor-accurate body (raw CSV or key=value string). Each app subclasses `BaseAppGenerator` and implements `generate()`.
- **Formatters** are pure functions that wrap the message in a syslog envelope (RFC 3164, RFC 5424, or CEF+RFC5424).
- **Senders** are context managers that deliver to stdout, a file, or a remote syslog receiver (UDP/TCP/TLS).

### Adding a new app

1. Create `loggenerate/apps/<name>.py` subclassing `BaseAppGenerator`.
2. Register it in `loggenerate/apps/__init__.py`.
3. Add the `--app` choice in `cli.py`.

## Installation

No install step required. Clone and run directly:

```bash
git clone <repo>
cd loggenerate
python3 -m loggenerate --help
```

Python 3.9+ required. No third-party dependencies.
