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
    "n66m": {
        "device": "iPhone8,2", "board": "n66map", "display_name": "iPhone 6s Plus",
        "cpid": 0x8003, "bdid": 0x06, "ticket": 9, "exploit": "gaster",
    },
    "n66": {
        "device": "iPhone8,2", "board": "n66ap", "display_name": "iPhone 6s Plus",
        "cpid": 0x8000, "bdid": 0x06, "ticket": 9, "exploit": "gaster",
    },
    "n71": {
        "device": "iPhone8,1", "board": "n71ap", "display_name": "iPhone 6s",
        "cpid": 0x8000, "bdid": 0x04, "ticket": 9, "exploit": "gaster",
    },
    "n71m": {
        "device": "iPhone8,1", "board": "n71map", "display_name": "iPhone 6s",
        "cpid": 0x8003, "bdid": 0x04, "ticket": 9, "exploit": "gaster",
    },
    "j81": {
        "device": "iPad5,3", "board": "j81ap", "display_name": "iPad Air 2",
        "cpid": 0x7001, "bdid": 0x06, "ticket": 8, "exploit": "gaster",
    },
    "j82": {
        "device": "iPad5,4", "board": "j82ap", "display_name": "iPad Air 2",
        "cpid": 0x7001, "bdid": 0x02, "ticket": 8, "exploit": "gaster",
    },
    "j85": {
        "device": "iPad4,4", "board": "j85ap", "display_name": "iPad mini 2",
        "cpid": 0x8960, "bdid": 0x0A, "ticket": 7, "exploit": "ipwnder",
    },
    "j86": {
        "device": "iPad4,5", "board": "j86ap", "display_name": "iPad mini 2",
        "cpid": 0x8960, "bdid": 0x0C, "ticket": 7, "exploit": "ipwnder",
    },
    "j87": {
        "device": "iPad4,6", "board": "j87ap", "display_name": "iPad mini 2",
        "cpid": 0x8960, "bdid": 0x0E, "ticket": 7, "exploit": "ipwnder",
    },
    "j85m": {
        "device": "iPad4,7", "board": "j85map", "display_name": "iPad mini 3",
        "cpid": 0x8960, "bdid": 0x32, "ticket": 7, "exploit": "ipwnder",
    },
    "j86m": {
        "device": "iPad4,8", "board": "j86map", "display_name": "iPad mini 3",
        "cpid": 0x8960, "bdid": 0x34, "ticket": 7, "exploit": "ipwnder",
    },
    "j87m": {
        "device": "iPad4,9", "board": "j87map", "display_name": "iPad mini 3",
        "cpid": 0x8960, "bdid": 0x36, "ticket": 7, "exploit": "ipwnder",
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

# iOS 9 iBoot-2817 patterns were checked against each of these exact
# product/board/build identities. Two releases had more than one IPSW build;
# callers must select the installed build explicitly in those cases.
IOS9_SHARED_BUILDS = {
    "13A452": "9.0.2", "13B143": "9.1", "13C75": "9.2",
    "13D15": "9.2.1", "13E238": "9.3.1", "13F69": "9.3.2",
    "13G34": "9.3.3", "13G35": "9.3.4", "13G36": "9.3.5",
}
IOS9_NON_A9_EARLY = {"13A344": "9.0", "13A404": "9.0.1"}
IOS9_A9_EARLY = {"13A405": "9.0.1"}
IOS9_A7_93 = {"13E233": "9.3", "13E237": "9.3"}
IOS9_A8_93 = {"13E233": "9.3"}
IOS9_A9_93 = {"13E234": "9.3"}
IOS9_D20_MODELS = {"j81", "j82", "n61", "n71", "n71m",
                   "j85m", "j86m", "j87m", "n66", "n66m"}
for model in ("j81", "j82", "n61", "n71", "n71m", "n51", "n53",
              "j85", "j86", "j87", "j85m", "j86m", "j87m",
              "n66", "n66m"):
    builds = dict(IOS9_SHARED_BUILDS)
    if model in IOS9_D20_MODELS:
        builds["13D20"] = "9.2.1"
    if model in {"n51", "n53", "j85", "j86", "j87"}:
        builds.update(IOS9_NON_A9_EARLY)
        builds.update(IOS9_A7_93)
    elif model in {"n71", "n71m", "n66", "n66m"}:
        builds.update(IOS9_A9_EARLY)
        builds.update(IOS9_A9_93)
        builds["13A342" if model in {"n71", "n71m"} else "13A343"] = "9.0"
    else:
        builds.update(IOS9_NON_A9_EARLY)
        builds.update(IOS9_A8_93)
    PROFILES.update(_profiles_for(model, builds))


def _hex_field(value, label):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {label} reported by irecovery: {value!r}") from exc


def register_dynamic_profile(device, version, firmware):
    """Register a pattern-supported A7/A8/A8X profile for this process."""
    if version.split(".", 1)[0] not in {"7", "8"}:
        raise ValueError("A7/A8 auto-detection is limited to iOS 7 and 8")
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
        "dynamic": True,
    }
    return name


def get_profile(name):
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"unsupported profile {name!r}; available: {', '.join(PROFILES)}") from exc


def profile_for_board(board, version, build=None):
    """Select one built-in firmware profile without querying a device."""
    board = board.strip().lower()
    if board.endswith("ap"):
        board = board[:-2]
    matches = sorted(name for name, profile in PROFILES.items()
                     if profile["board"].lower() == board + "ap"
                     and profile["version"] == version
                     and (build is None or profile["build"].lower() == build.lower()))
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise ValueError(
            f"multiple iOS {version} builds for board {board}: "
            f"{', '.join(matches)}; specify --build BUILD")
    suffix = f" build {build}" if build else ""
    raise ValueError(
        f"no built-in profile for board {board} iOS {version}{suffix}; "
        "check ./qwqramdisk versions")


def validation_status(profile):
    """Return user-facing support status without gating iOS 7/8 models."""
    name = profile["name"] if isinstance(profile, dict) else profile
    p = get_profile(name)
    if p["version"].split(".", 1)[0] in {"7", "8"}:
        return "supported"
    if name == "n66m-13E238":
        return "device-tested"
    if name == "n66-13A405":
        return "device-tested-ssh-rw"
    if p["version"].startswith("9."):
        return "experimental-offline"
    return "unsupported"
