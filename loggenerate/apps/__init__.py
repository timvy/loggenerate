from loggenerate.apps.generic import GenericAppGenerator
from loggenerate.apps.paloalto import PaloAltoGenerator
from loggenerate.apps.f5bigip import F5BigIPGenerator
from loggenerate.apps.fortinet import FortinetGenerator

_GENERATORS = {
    "generic":  GenericAppGenerator,
    "paloalto": PaloAltoGenerator,
    "f5":       F5BigIPGenerator,
    "fortinet": FortinetGenerator,
}


def get_app_generator(name: str):
    if name not in _GENERATORS:
        raise ValueError(f"Unknown app '{name}'. Choices: {', '.join(_GENERATORS)}")
    return _GENERATORS[name]()
