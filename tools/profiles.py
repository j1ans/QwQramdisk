"""Firmware/device profiles; patch locations are discovered at runtime."""

IOS7_BUILDS = {
    "11B651": "7.0.6",
    "11D167": "7.1",
    "11D201": "7.1.1",
    "11D257": "7.1.2",
}

IOS8_BUILDS = {
    "12A365": "8.0",
    "12A402": "8.0.1",
    "12A405": "8.0.2",
    "12B411": "8.1",
    "12B435": "8.1.1",
    "12B440": "8.1.2",
    "12B466": "8.1.3",
    "12D508": "8.2",
    "12F70": "8.3",
    "12H143": "8.4",
    "12H321": "8.4.1",
}

DEVICES = {
    "n51": {
        "device": "iPhone6,1", "board": "n51ap", "display_name": "iPhone 5s (GSM)",
        "cpid": 0x8960, "bdid": 0x00, "ticket": 7, "exploit": "ipwnder",
    },
    "n53": {
        "device": "iPhone6,2", "board": "n53ap", "display_name": "iPhone 5s (Global)",
        "cpid": 0x8960, "bdid": 0x02, "ticket": 7, "exploit": "ipwnder",
    },
    "n56": {
        "device": "iPhone7,1", "board": "n56ap", "display_name": "iPhone 6 Plus",
        "cpid": 0x7000, "bdid": 0x04, "ticket": 8, "exploit": "gaster",
    },
    "n61": {
        "device": "iPhone7,2", "board": "n61ap", "display_name": "iPhone 6",
        "cpid": 0x7000, "bdid": 0x06, "ticket": 8, "exploit": "gaster",
    },
}


def _profiles_for(model, builds):
    device = DEVICES[model]
    return {
        f"{model}-{build}": {
            "name": f"{model}-{build}", **device,
            "version": version, "build": build,
        }
        for build, version in builds.items()
    }


PROFILES = {}
PROFILES.update(_profiles_for("n51", {**IOS7_BUILDS, **IOS8_BUILDS}))
PROFILES.update(_profiles_for("n53", {**IOS7_BUILDS, **IOS8_BUILDS}))

# The first iPhone 6 Plus release used build 12A366; iPhone 6 used 12A365.
N56_IOS8_BUILDS = {**IOS8_BUILDS}
N56_IOS8_BUILDS.pop("12A365")
N56_IOS8_BUILDS["12A366"] = "8.0"
# Both A8 phones use 12B436 for 8.1.1 rather than the A7 build 12B435.
for model in ("n56", "n61"):
    builds = {**(N56_IOS8_BUILDS if model == "n56" else IOS8_BUILDS)}
    builds.pop("12B435")
    builds["12B436"] = "8.1.1"
    PROFILES.update(_profiles_for(model, builds))


def _hex_field(value, label):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {label} reported by irecovery: {value!r}") from exc


def register_experimental_profile(device, version, firmware):
    """Register an auto-detected A7/A8/A8X profile for this process."""
    if version.split(".", 1)[0] not in {"7", "8"}:
        raise ValueError("experimental auto-detection is limited to iOS 7 and 8")
    cpid = _hex_field(device["CPID"], "CPID")
    bdid = _hex_field(device["BDID"], "BDID")
    if cpid not in {0x8960, 0x7000, 0x7001}:
        raise ValueError(
            f"CPID 0x{cpid:X} is not an iOS 7/8 arm64 A7/A8/A8X device")
    board = device["MODEL"].lower()
    short_board = board[:-2] if board.endswith("ap") else board
    build = firmware["buildid"]
    name = f"{short_board}-{build}"
    PROFILES[name] = {
        "name": name,
        "device": device["PRODUCT"],
        "board": board,
        "display_name": device.get("NAME", device["PRODUCT"]),
        "cpid": cpid,
        "bdid": bdid,
        "ticket": 7 if cpid == 0x8960 else 8,
        "exploit": "ipwnder" if cpid == 0x8960 else "gaster",
        "version": version,
        "build": build,
        "experimental": True,
    }
    return name


def get_profile(name):
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"unsupported profile {name!r}; available: {', '.join(PROFILES)}") from exc


def validation_status(profile):
    """Return the strongest completed validation without overstating support."""
    name = profile["name"] if isinstance(profile, dict) else profile
    get_profile(name)
    if get_profile(name).get("experimental"):
        return "experimental-device-untested-use-at-own-risk"
    model, build = name.split("-", 1)
    if name in ("n53-11D201", "n53-12F70"):
        return "device-tested"
    if name in ("n51-11D201", "n51-12F70"):
        return "build-tested"
    if model in ("n56", "n61"):
        if build == "12F70":
            return "supported-build-tested-device-untested"
        if build in {"12A365", "12A366", "12B411", "12D508", "12H321"}:
            return "supported-pattern-tested-device-untested"
        return "supported-device-untested"
    if build in {"11B651", "11D167", "11D201", "11D257",
                 "12A365", "12B411", "12D508", "12F70", "12H321"}:
        return "pattern-tested"
    return "cataloged"
