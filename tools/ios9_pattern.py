"""Fail-closed iBoot-2817 pattern patches for A7/A8/A9 iOS 9 SSH ramdisks."""

from pathlib import Path

from .common import patch_bytes, write_manifest
from .lzss import unpack
from .offsetfinder import (
    MOV_X0_0_RET, MOV_X0_1, NOP, RawArm64, adr_target,
    branch_target, encode_adr, find_unique, is_bl, is_cb, read_word,
)


DECODER = bytes.fromhex("e8071f32e00000b4c10000b4")
CALLBACK_PROLOGUE = bytes.fromhex("fa67bba9f85f01a9")
EARLY_DISABLE = bytes.fromhex("a80090370000801201008052")
IBSS_GID = bytes.fromhex("e803202a13010013e0030d32")
IBSS_UID = bytes.fromhex("e803202a01010013e00313aa")
IBEC_MASK = bytes.fromhex(
    "7f02007109008012a812891a1f0000718112891ae00308aa")
LEGACY_MASK = bytes.fromhex(
    "7f020071090080128812891a1f000071a112891ae00308aa")
BOOTARGS = (
    b"rd=md0 -v debug=0x2014e amfi_get_out_of_my_way=1 "
    b"cs_enforcement_disable=1\0"
)


def _validate(raw, stage):
    sizes = {"iBSS": (0x20000, 0x40000),
             "iBEC": (0x40000, 0xC0000)}
    if (stage not in sizes or len(raw) % 0x1000
            or not sizes[stage][0] <= len(raw) <= sizes[stage][1]
            or raw[:4] != bytes.fromhex("00000090")):
        raise ValueError(f"{stage}: not a decrypted iBoot-2817 arm64 image")
    version = raw[0x280:0x2C0].split(b"\0", 1)[0].decode("ascii", "replace")
    if not version.startswith("iBoot-2817."):
        raise ValueError(f"{stage}: unsupported iBoot family {version!r}")
    marker = f"{stage} for ".encode()
    if marker not in raw:
        raise ValueError(f"{stage}: stage identity marker missing")
    return version


def _callback(raw, finder):
    decoder = find_unique(raw, DECODER, "Image4 manifest decoder")
    call = finder.find_call_ref(decoder, "Image4 decoder call")
    refs = [(off, adr_target(read_word(raw, off), off))
            for off in range(call + 4, call + 0x40, 4)
            if adr_target(read_word(raw, off), off) is not None
            and read_word(raw, off) & 31 == 2]
    if len(refs) != 1:
        raise ValueError("Image4 validation callback reference is ambiguous")
    ref, callback = refs[0]
    if raw[callback:callback + 8] != CALLBACK_PROLOGUE:
        raise ValueError("Image4 validation callback prologue changed")
    return callback, ref


def _early_disable(raw):
    site = find_unique(raw, EARLY_DISABLE, "GID/UID early-disable decision")
    gid, uid = site + 12, site + 32
    if not is_bl(read_word(raw, gid)) or not is_bl(read_word(raw, uid)):
        raise ValueError("GID/UID disable calls changed")
    if branch_target(read_word(raw, gid), gid) != branch_target(read_word(raw, uid), uid):
        raise ValueError("GID/UID disable calls no longer share a writer")
    return gid, uid


def _second_call_after_string(raw, finder, literal):
    string_off = find_unique(raw, literal + b"\0", literal.decode())
    ref = finder.find_literal_ref(string_off, literal.decode() + " XREF")
    calls = [off for off in range(ref + 4, ref + 0x40, 4)
             if is_bl(read_word(raw, off))]
    if len(calls) != 2:
        raise ValueError(f"{literal.decode()}: expected two calls after XREF")
    return ref, calls[1]


def locate(raw, stage):
    """Return checked semantic patch sites, never a firmware-specific offset list."""
    version = _validate(raw, stage)
    finder = RawArm64(raw)
    callback, callback_ref = _callback(raw, finder)
    gid_disable, uid_disable = _early_disable(raw)
    patches = [
        (callback, CALLBACK_PROLOGUE, MOV_X0_0_RET,
         "accept Image4 validation callback", {"xref": callback_ref}),
    ]
    legacy = LEGACY_MASK in raw
    a9_mask = (IBSS_GID in raw if stage == "iBSS" else IBEC_MASK in raw)
    if legacy == a9_mask:
        raise ValueError("iOS 9 bootx AES mask family is unknown or ambiguous")
    if stage == "iBSS":
        if legacy:
            mask = find_unique(raw, LEGACY_MASK, "A7/A8 iBSS bootx UID mask")
            uid, writer = mask + 16, mask + 24
            patches.append((uid, bytes.fromhex("a112891a"),
                            bytes.fromhex("e103152a"),
                            "retain A7/A8 UID AES at bootx", {}))
        else:
            gid = find_unique(raw, IBSS_GID, "iBSS bootx GID mask") + 4
            uid = find_unique(raw, IBSS_UID, "iBSS bootx UID mask") + 4
            if uid != gid + 16:
                raise ValueError("iBSS GID/UID boot masks are not adjacent")
            writer = uid + 8
            patches += [
                (gid, bytes.fromhex("13010013"), bytes.fromhex("13008052"),
                 "retain GID AES at bootx", {}),
                (uid, bytes.fromhex("01010013"), bytes.fromhex("01008052"),
                 "retain UID AES at bootx", {}),
            ]
    elif stage == "iBEC":
        if legacy:
            mask = find_unique(raw, LEGACY_MASK, "A7/A8 iBEC bootx UID mask")
            uid, writer = mask + 16, mask + 24
            patches.append((uid, bytes.fromhex("a112891a"),
                            bytes.fromhex("e103152a"),
                            "retain A7/A8 UID AES at bootx", {}))
        else:
            mask = find_unique(raw, IBEC_MASK, "iBEC bootx GID/UID mask")
            gid, uid, writer = mask + 8, mask + 16, mask + 24
        _, debug_call = _second_call_after_string(raw, finder, b"debug-enabled")
        uid_ref, uid_call = _second_call_after_string(raw, finder, b"uid-aes-key")
        uid_branch = uid_call + 4
        if read_word(raw, uid_branch) != 0x34000080:
            raise ValueError("uid-aes-key publication branch changed")
        default = find_unique(raw, b"rd=md0 nand-enable-reformat=1 -progress\0",
                              "default ramdisk boot arguments")
        boot_ref = finder.find_adr_ref(default, "default boot arguments XREF")
        if read_word(raw, boot_ref) & 31 != 9:
            raise ValueError("boot-arguments ADR no longer loads x9")
        csel = boot_ref + 20
        csel_word = read_word(raw, csel)
        if csel_word & 0xFFFFFFE0 != 0x9A890140:
            raise ValueError("boot-arguments CSEL x10/x9 changed")
        pagezero = find_unique(raw, b"__PAGEZERO\0", "Mach-O segment name")
        page_refs = [off for off in finder.find_adr_refs(pagezero)
                     if boot_ref - 0x200 < off < boot_ref
                     and read_word(raw, off) & 31 == 1]
        if len(page_refs) != 1:
            raise ValueError("boot-arguments parser reference is ambiguous")
        page_ref = page_refs[0]
        scratch = find_unique(raw, b"Reliance on this certificate by any",
                              "certificate scratch string")
        end = raw.find(b"\0", scratch)
        if end < 0 or len(BOOTARGS) > end - scratch + 1:
            raise ValueError("certificate scratch is too short for boot arguments")
        patches += [
            (debug_call, raw[debug_call:debug_call + 4], MOV_X0_1,
             "accept debug capability", {}),
            (uid_branch, raw[uid_branch:uid_branch + 4], NOP,
             "publish uid-aes-key", {"xref": uid_ref}),
            (scratch, raw[scratch:scratch + len(BOOTARGS)], BOOTARGS,
             "relocate ramdisk boot arguments", {}),
            (page_ref, raw[page_ref:page_ref + 4], encode_adr(page_ref, scratch, 1),
             "redirect boot parser argument reference", {"target": scratch}),
            (boot_ref, raw[boot_ref:boot_ref + 4], encode_adr(boot_ref, scratch, 9),
             "redirect default boot arguments", {"target": scratch}),
            (csel, raw[csel:csel + 4],
             (0xAA0903E0 | (csel_word & 31)).to_bytes(4, "little"),
             "select ramdisk boot arguments", {}),
        ]
        if not legacy:
            patches += [
                (gid, bytes.fromhex("a812891a"), bytes.fromhex("08008052"),
                 "retain GID AES at bootx", {}),
                (uid, bytes.fromhex("8112891a"), bytes.fromhex("e103142a"),
                 "retain UID AES at bootx", {}),
            ]
    else:
        raise ValueError(f"unsupported iOS 9 boot stage {stage!r}")
    if not is_bl(read_word(raw, writer)):
        raise ValueError("bootx AES writer call changed")
    if not legacy and (branch_target(read_word(raw, writer), writer)
                       != branch_target(read_word(raw, gid_disable), gid_disable)):
        raise ValueError("bootx and early AES-disable writers differ")
    if not legacy:
        patches.append((gid_disable, raw[gid_disable:gid_disable + 4], NOP,
                        "skip early GID AES disable", {}))
    patches.append((uid_disable, raw[uid_disable:uid_disable + 4], NOP,
                    "skip early UID AES disable", {}))
    for off, before, after, note, _ in patches:
        if off < 0 or off + len(before) > len(raw) or raw[off:off + len(before)] != before:
            raise ValueError(f"{note}: unexpected instruction/data at 0x{off:x}")
        if len(before) != len(after):
            raise ValueError(f"{note}: patch changes size")
    return version, patches


def patch_stage(source, destination, stage, manifest=None):
    source, destination = Path(source), Path(destination)
    raw = bytearray(source.read_bytes())
    version, patches = locate(bytes(raw), stage)
    records = []
    for off, before, after, note, extra in patches:
        patch_bytes(raw, off, before.hex(), after.hex(), note)
        records.append({"offset": off, "before": before.hex(), "after": after.hex(),
                        "note": note, "locator": "iBoot-2817 pattern+xref", **extra})
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    if manifest:
        write_manifest(manifest, source, destination, records,
                       {"stage": stage, "iboot_version": version})
    return destination


def pack_stock_kernel(source, destination, manifest=None):
    """Preserve the complete release IM4P, including its appended monitor."""
    source, destination = Path(source), Path(destination)
    blob = source.read_bytes()
    off = blob.find(b"complzss")
    if blob[13:17] != b"krnl" or off < 0:
        raise ValueError("iOS 9 kernel is not a krnl/complzss IM4P")
    info, macho = unpack(blob[off:])
    tail = len(blob) - off - 0x180 - info["csize"]
    if tail < 0x1000 or b"Darwin Kernel Version 15." not in macho:
        raise ValueError("iOS 9 stock kernel monitor or Mach-O changed")
    prepared = bytearray(blob)
    prepared[13:17] = b"rkrn"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(prepared)
    if manifest:
        write_manifest(manifest, source, destination,
                       [{"offset": 13, "before": "6b726e6c", "after": "726b726e",
                         "note": "restore kernel tag, preserve monitor"}],
                       {"format": "IM4P/complzss", "monitor_tail_bytes": tail})
    return destination
