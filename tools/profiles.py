"""Firmware selection profiles; patch locations are discovered at runtime."""

_BUILDS = {
    "11B651": "7.0.6", "11D167": "7.1",
    "11D201": "7.1.1",
    "11D257": "7.1.2",
    "12A365": "8.0", "12A402": "8.0.1", "12A405": "8.0.2",
    "12B411": "8.1", "12B435": "8.1.1", "12B440": "8.1.2",
    "12B466": "8.1.3", "12D508": "8.2", "12F70": "8.3",
    "12H143": "8.4", "12H321": "8.4.1",
}

PROFILES = {
    f"n53-{build}": {
        "name": f"n53-{build}", "device": "iPhone6,2", "board": "n53ap",
        "version": version, "build": build,
    }
    for build, version in _BUILDS.items()
}

def get_profile(name):
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"unsupported profile {name!r}; available: {', '.join(PROFILES)}") from exc
