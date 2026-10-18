# Bundled runtime

This directory contains the x86_64 and arm64 macOS runtimes and the x86_64
experimental Linux offline-build runtime used by QwQramdisk. Native binaries
live under `bin/<platform>/<arch>`. The macOS tools were copied from
Legacy-iOS-Kit commit
`bd921d51d8d84232d668adfd54e3e1e2edff9a33`. Linux `pzb`, `img4`, and `hfsplus`
were copied unchanged from Legacy-iOS-Kit commit
`0f05c64974d37c538b9a4e6eac8840333b3e66dd`, paths
`bin/linux/x86_64/{pzb,img4,hfsplus}`. A separate checkout is not required.

The experimental Linux set is for offline creation only. It uses system glibc,
OpenSSL 3
(`libcrypto.so.3`), libcurl 4 (`libcurl.so.4`), zlib, libstdc++, and libgcc.
On Ubuntu 22.04 install `libssl3 libcurl4 zlib1g libstdc++6`; Python 3 runs the
CLI and an optional C compiler accelerates LZSS compression. No Linux USB,
DFU, or SSH transport binaries are bundled in this change. Linux arm64 is not
currently supported.

| File/resource | Upstream / purpose |
|---|---|
| `pzb` | libfragmentzip partial IPSW download |
| `img4` | img4lib decryption and IMG4 wrapping |
| `hfsplus` | HFS ramdisk editing |
| `irecovery` + libraries | libirecovery DFU transport |
| `ipwnder` | ipwnder_lite A7 checkm8 flow on Apple Silicon macOS |
| `gaster` | A7 checkm8 on Intel macOS, A8 checkm8, and USB reset |
| `iproxy` + libraries | libusbmuxd SSH forwarding |
| `sshpass` | non-interactive SSH password input |
| `IM4M7`, `IM4M8` | A7/A8 ramdisk IMG4 tickets from Legacy-iOS-Kit |
| `sbplist.tar` | SSH ramdisk launchd configuration from Legacy-iOS-Kit |
| `iram.tar` | exploit3dguy/iArchive iRam userland, distributed by Legacy-iOS-Kit |

Exact hashes are in `SHA256SUMS`. The Legacy-iOS-Kit GPLv3 text is retained in
`licenses/Legacy-iOS-Kit-GPL-3.0.txt`. Individual tools and libraries remain
under their respective upstream licenses; source links and credits are listed
in the project README.
