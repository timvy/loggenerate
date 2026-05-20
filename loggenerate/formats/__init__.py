from loggenerate.formats import rfc3164, rfc5424, cef

_FORMATTERS = {
    "rfc3164": rfc3164.format_message,
    "rfc5424": rfc5424.format_message,
    "cef":     cef.format_message,
}


def get_formatter(name: str):
    if name not in _FORMATTERS:
        raise ValueError(f"Unknown format '{name}'. Choices: {', '.join(_FORMATTERS)}")
    return _FORMATTERS[name]
