# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the generator (no build step needed)
python3 -m loggenerate --app paloalto --format rfc5424 --count 5
python3 -m loggenerate --app paloalto --log-type traffic --format rfc3164 --count 5
python3 -m loggenerate --app f5 --log-type ltm --count 5
python3 -m loggenerate --app fortinet --log-type utm --count 5

# Reproducible output
python3 -m loggenerate --app paloalto --count 3 --seed 42

# Send to a remote syslog receiver
python3 -m loggenerate --app paloalto --output syslog --host 192.168.1.100 --port 514 --count 100
```

No test suite or linter is configured. No install step is needed — run directly with `python3 -m loggenerate` from the repo root.

## Architecture

The pipeline is: **generator → formatter → sender**. The CLI (`cli.py`) wires these three together; each is independently swappable.

### Data model (`models.py`)
`SyslogMessage` is the single transfer object between generators and formatters. Key fields:
- `facility`, `severity` → compute `priority` via `(facility * 8) + severity`
- `structured_data: Dict[str, Dict[str, str]]` → RFC 5424 SD elements; ignored by RFC 3164
- `rfc3164_tag: Optional[str]` — when `None`, RFC 3164 builds `app_name[proc_id]`; when `""`, no tag or colon is emitted (PAN-OS style); when a non-empty string, used verbatim as the TAG

### Generators (`apps/`)
Each app subclasses `BaseAppGenerator` and implements `generate(hostname, facility, severity, log_type) -> SyslogMessage`.

The message body is the **raw vendor CSV or key=value string** — not a human-readable message. Formatters wrap it in the appropriate syslog envelope.

**PAN-OS traffic logs** return a 3-tuple `(severity, body, app_name)` from `_traffic_log` and `_threat_log` so the caller can use the same `app_name` in both the CSV body (field 15) and the RFC 5424 structured data. System and config logs return 2-tuples. The traffic CSV follows the PAN-OS 10.2+ 118-field schema: 47 core fields + 5 DGH fields + device name (field 53) + 50 extended fields + high-res ISO 8601 timestamp (field 104) + 14 trailing fields.

### Formatters (`formats/`)
Pure functions `format_message(SyslogMessage) -> str`. RFC 3164 omits year from timestamp and ignores `structured_data`. RFC 5424 uses millisecond-precision UTC timestamps with `Z` suffix.

### Senders (`senders/`)
Context managers inheriting `BaseSender`. `BaseSender.frame()` handles RFC 6587 octet-counting vs newline framing. `NetworkSender` supports UDP, TCP, and TLS (with optional client cert and CA override).

### Shared data (`utils.py`)
All randomised primitives live here: IP pools, application names, user names, port lists, country names, and vendor timestamp formatters (`pan_timestamp`, `fortinet_date`/`fortinet_time`). Add new values to the lists in this file when expanding realism.

## Adding a new app generator

1. Create `loggenerate/apps/<name>.py` with a class subclassing `BaseAppGenerator`.
2. Register it in `loggenerate/apps/__init__.py` under `_GENERATORS`.
3. Add `--app` choice in `cli.py`'s `build_parser()`.

## PAN-OS CSV field notes

Real PAN-OS devices in RFC 3164 mode emit the CSV body directly after the hostname with no TAG (set `rfc3164_tag=""`). The `interzone-default` rule, `not-applicable` application, and `any` URL category are valid values for denied/dropped traffic where no application was identified. Zone names commonly use an `L3-` prefix (e.g. `L3-Trust`, `L3-dmz-secaas`). vsys numbering can exceed vsys4 on multi-vsys deployments.
