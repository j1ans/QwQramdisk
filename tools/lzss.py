"""Apple complzss codec used by pre-iOS 10 kernelcaches."""
import struct
import hashlib
import subprocess
import tempfile
import zlib
from pathlib import Path

N = 4096
F = 18
THRESHOLD = 2
HDR = 0x180


def decode(src, limit):
    ring = bytearray(b" " * (N + F - 1))
    out = bytearray()
    si, r, flags = 0, N - F, 0
    while True:
        flags >>= 1
        if not flags & 0x100:
            if si >= len(src):
                break
            flags = src[si] | 0xFF00
            si += 1
        if flags & 1:
            if si >= len(src) or len(out) == limit:
                break
            c = src[si]; si += 1
            out.append(c); ring[r] = c; r = (r + 1) & (N - 1)
        else:
            if si + 1 >= len(src):
                break
            i, j = src[si], src[si + 1]; si += 2
            i |= (j & 0xF0) << 4
            count = (j & 0x0F) + THRESHOLD + 1
            for k in range(count):
                if len(out) == limit:
                    return bytes(out)
                c = ring[(i + k) & (N - 1)]
                out.append(c); ring[r] = c; r = (r + 1) & (N - 1)
    return bytes(out)


def _encode_python(data):
    out = bytearray()
    ring_off = N - F
    pos = 0
    flags = count = flag_pos = 0

    def ridx(p):
        return (p + ring_off) & (N - 1)

    def begin_unit():
        nonlocal count, flag_pos
        if count == 0:
            flag_pos = len(out); out.append(0)
        count += 1

    def end_unit(literal):
        nonlocal flags, count
        if literal:
            flags |= 1 << (count - 1)
        if count == 8:
            out[flag_pos] = flags
            flags = count = 0

    while pos < len(data):
        best_len = best_pos = 0
        if pos + 3 <= len(data):
            key = data[pos:pos + 3]
            start = max(0, pos - (N - 1))
            end = pos
            # bytes.rfind performs the expensive window search in C. Checking
            # several recent candidates retains good compression without the
            # per-byte Python dictionary maintenance of the original encoder.
            for _ in range(24):
                candidate = data.rfind(key, start, end)
                if candidate < 0:
                    break
                cap = min(F, len(data) - pos)
                length = 0
                while length < cap and data[candidate + length] == data[pos + length]:
                    length += 1
                if length > best_len:
                    best_len, best_pos = length, candidate
                    if length == cap:
                        break
                end = candidate
        if best_len >= 3:
            begin_unit()
            best_i = ridx(best_pos)
            out += bytes((best_i & 0xFF,
                          ((best_i >> 8) << 4) | (best_len - 3)))
            end_unit(False)
            pos += best_len
        else:
            begin_unit(); out.append(data[pos]); end_unit(True)
            pos += 1
    if count:
        out[flag_pos] = flags
    return bytes(out)


def encode(data):
    """Encode with the bundled native helper, retaining Python as fallback."""
    source = Path(__file__).with_name("lzssenc.c")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    binary = Path(tempfile.gettempdir()) / f"qwqramdisk-lzssenc-{digest}"
    try:
        if not binary.is_file():
            subprocess.run(["cc", "-O3", str(source), "-o", str(binary)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        with tempfile.TemporaryDirectory(prefix="ios8-lzss-") as directory:
            inp, out = Path(directory) / "input", Path(directory) / "output"
            inp.write_bytes(data)
            subprocess.run([str(binary), str(inp), str(out)], check=True)
            return out.read_bytes()
    except (OSError, subprocess.SubprocessError):
        return _encode_python(data)


def unpack(blob):
    if blob[:8] != b"complzss":
        raise ValueError("not a complzss payload")
    adler, usize, csize = struct.unpack_from(">III", blob, 8)
    macho = decode(blob[HDR:HDR + csize], usize)
    if len(macho) != usize:
        raise ValueError(f"decompressed size {len(macho)} != {usize}")
    if zlib.adler32(macho) & 0xFFFFFFFF != adler:
        raise ValueError("kernelcache Adler-32 mismatch")
    return {"usize": usize, "csize": csize,
            "platform": blob[0x40:0x80].split(b"\0")[0]}, macho


def pack(macho, platform=b"S5L8960X"):
    compressed = encode(macho)
    header = bytearray(HDR)
    header[:8] = b"complzss"
    struct.pack_into(">III", header, 8, zlib.adler32(macho) & 0xFFFFFFFF,
                     len(macho), len(compressed))
    header[0x40:0x80] = platform.ljust(64, b"\0")
    return bytes(header) + compressed
