"""Small iOS 7/8 ARM64 offset finder inspired by liboffsetfinder64.

It intentionally implements only the instructions used by these patchers.
Every public finder is fail-closed: zero or multiple matches are errors.
"""
import struct


NOP = bytes.fromhex("1f2003d5")
MOV_X0_0_RET = bytes.fromhex("000080d2c0035fd6")
MOV_X0_1 = bytes.fromhex("200080d2")
MOV_W8_3 = bytes.fromhex("68008052")


def sign_extend(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def words(data):
    for off in range(0, len(data) - 3, 4):
        yield off, struct.unpack_from("<I", data, off)[0]


def unique(items, label):
    items = list(items)
    if len(items) != 1:
        rendered = ", ".join(f"0x{x:x}" for x in items[:12])
        raise ValueError(f"{label}: expected one match, got {len(items)} ({rendered})")
    return items[0]


def find_all(data, needle):
    found, start = [], 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return found
        found.append(pos)
        start = pos + 1


def find_unique(data, needle, label):
    return unique(find_all(data, needle), label)


def read_word(data, off):
    if off < 0 or off + 4 > len(data) or off & 3:
        raise ValueError(f"unaligned/out-of-range instruction offset 0x{off:x}")
    return struct.unpack_from("<I", data, off)[0]


def is_bl(word):
    return word & 0xFC000000 == 0x94000000


def is_b(word):
    return word & 0xFC000000 == 0x14000000


def is_cb(word):
    return word & 0x7E000000 == 0x34000000


def cb_nonzero(word):
    return bool(word & 0x01000000)


def branch_target(word, pc):
    if is_bl(word) or is_b(word):
        return pc + sign_extend(word & 0x03FFFFFF, 26) * 4
    if is_cb(word) or word & 0xFF000010 == 0x54000000:
        return pc + sign_extend((word >> 5) & 0x7FFFF, 19) * 4
    raise ValueError(f"0x{word:08x} is not a supported immediate branch")


def encode_b(pc, target):
    delta = target - pc
    if delta & 3 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError("unencodable ARM64 B target")
    return struct.pack("<I", 0x14000000 | ((delta // 4) & 0x03FFFFFF))


def encode_bl(pc, target):
    delta = target - pc
    if delta & 3 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError("unencodable ARM64 BL target")
    return struct.pack("<I", 0x94000000 | ((delta // 4) & 0x03FFFFFF))


def adr_target(word, pc):
    if word & 0x9F000000 != 0x10000000:
        return None
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    return pc + sign_extend(imm, 21)


def adrp_target(word, pc):
    if word & 0x9F000000 != 0x90000000:
        return None
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    return (pc & ~0xFFF) + (sign_extend(imm, 21) << 12)


def add_imm(word):
    if word & 0xFF000000 != 0x91000000:
        return None
    return ((word >> 10) & 0xFFF) << (12 if word & (1 << 22) else 0)


def encode_adr(pc, target, rd):
    delta = target - pc
    if not -(1 << 20) <= delta < (1 << 20):
        raise ValueError("unencodable ARM64 ADR target")
    imm = delta & 0x1FFFFF
    word = 0x10000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd
    return struct.pack("<I", word)


class RawArm64:
    def __init__(self, data):
        self.data = data

    def find_call_ref(self, target, label):
        return unique((off for off, word in words(self.data)
                       if is_bl(word) and branch_target(word, off) == target), label)

    def find_adr_refs(self, target):
        return [off for off, word in words(self.data) if adr_target(word, off) == target]

    def find_adr_ref(self, target, label):
        return unique(self.find_adr_refs(target), label)

    def find_adrp_add_refs(self, target):
        """Find ADRP+ADD literal references in a flat, page-aligned image.

        iBoot's load address is page aligned, so computing the page delta from
        file offsets preserves the immediate encoded in the instruction.  The
        returned offset is the ADD, which can be replaced by a single ADR while
        leaving the preceding ADRP harmlessly overwritten on the next step.
        """
        refs = []
        for off, word in words(self.data):
            if off + 8 > len(self.data):
                continue
            page = adrp_target(word, off)
            if page is None:
                continue
            second = read_word(self.data, off + 4)
            imm = add_imm(second)
            rd = word & 31
            if (imm is not None and ((second >> 5) & 31) == rd
                    and (second & 31) == rd and page + imm == target):
                refs.append(off + 4)
        return refs

    def find_literal_refs(self, target):
        return self.find_adr_refs(target) + self.find_adrp_add_refs(target)

    def find_literal_ref(self, target, label):
        return unique(self.find_literal_refs(target), label)

    def next_bl(self, start, limit, label):
        return unique((off for off in range(start, limit, 4)
                       if is_bl(read_word(self.data, off))), label)


def macho_segments(data):
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("input is not a little-endian arm64 Mach-O")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            vm, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            yield vm, vmsize, fileoff, filesize
        off += size


class MachOArm64:
    def __init__(self, data):
        self.data = data
        self.segments = list(macho_segments(data))

    def offset_to_va(self, off):
        for vm, _vmsize, fileoff, filesize in self.segments:
            if fileoff <= off < fileoff + filesize:
                return vm + off - fileoff
        raise ValueError(f"file offset 0x{off:x} is not mapped")

    def va_to_offset(self, va):
        for vm, vmsize, fileoff, filesize in self.segments:
            delta = va - vm
            if 0 <= delta < vmsize:
                if delta >= filesize:
                    raise ValueError(f"VA 0x{va:x} is in zero-fill data")
                return fileoff + delta
        raise ValueError(f"VA 0x{va:x} is not mapped")

    def literal_refs(self, target):
        refs = []
        for vm, _vmsize, fileoff, filesize in self.segments:
            end = min(fileoff + filesize, len(self.data))
            for off in range(fileoff, end - 7, 4):
                pc = vm + off - fileoff
                word = read_word(self.data, off)
                if adr_target(word, pc) == target:
                    refs.append(off)
                    continue
                page = adrp_target(word, pc)
                if page is None:
                    continue
                second = read_word(self.data, off + 4)
                imm = add_imm(second)
                rd = word & 31
                if (imm is not None and ((second >> 5) & 31) == rd
                        and (second & 31) == rd and page + imm == target):
                    refs.append(off)
        return refs

    def string_refs(self, string):
        targets = {}
        for off in find_all(self.data, string + b"\0"):
            va = self.offset_to_va(off)
            targets[va] = off
        result = []
        for vm, _vmsize, fileoff, filesize in self.segments:
            end = min(fileoff + filesize, len(self.data))
            for off in range(fileoff, end - 7, 4):
                pc = vm + off - fileoff
                word = read_word(self.data, off)
                target = adr_target(word, pc)
                if target in targets:
                    result.append((off, targets[target], target))
                    continue
                page = adrp_target(word, pc)
                if page is None:
                    continue
                second = read_word(self.data, off + 4)
                imm = add_imm(second)
                rd = word & 31
                if (imm is not None and ((second >> 5) & 31) == rd
                        and (second & 31) == rd and page + imm in targets):
                    target = page + imm
                    result.append((off, targets[target], target))
        return result


def validate_iboot(data):
    if len(data) < 0x1000 or read_word(data, 0) != 0x90000000:
        raise ValueError("input is not a decrypted 64-bit iBoot image")
    version = data[0x280:0x2C0].split(b"\0", 1)[0].decode("ascii", "replace")
    if not version.startswith(("iBoot-1940.", "iBoot-2261.")):
        raise ValueError(
            f"unsupported iBoot family {version!r}; expected iOS 7.1 "
            "iBoot-1940.x or iOS 8 iBoot-2261.x")
    return version
