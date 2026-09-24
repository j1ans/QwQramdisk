# Bundled runtime

This directory contains the complete x86_64 and arm64 macOS and Linux runtimes
used by QwQramdisk. Native binaries live under `bin/<os>/<arch>`. The macOS
files were copied from Legacy-iOS-Kit commit
`bd921d51d8d84232d668adfd54e3e1e2edff9a33`; the Linux files were copied from
commit `15263963392b548d3ab56ce95c08b37265394b31`. A separate Legacy-iOS-Kit
checkout is not required.

| File/resource | Upstream / purpose |
|---|---|
| `pzb` | libfragmentzip partial IPSW download |
| `img4` | img4lib decryption and IMG4 wrapping |
| `hfsplus` | HFS ramdisk editing |
| `irecovery` + libraries | libirecovery DFU transport |
| `ipwnder` | ipwnder_lite A7 checkm8 flow on Apple Silicon macOS |
| `gaster` | A7 checkm8 on Intel macOS/Linux, A8 checkm8, and USB reset |
| `iproxy` + libraries | libusbmuxd SSH forwarding |
| `sshpass` | non-interactive SSH password input |
| `IM4M7`, `IM4M8` | A7/A8 ramdisk IMG4 tickets from Legacy-iOS-Kit |
| `sbplist.tar` | SSH ramdisk launchd configuration from Legacy-iOS-Kit |
| `iram.tar` | exploit3dguy/iArchive iRam userland, distributed by Legacy-iOS-Kit |

Exact hashes are in `SHA256SUMS`. The Legacy-iOS-Kit GPLv3 text is retained in
`licenses/Legacy-iOS-Kit-GPL-3.0.txt`. Individual tools and libraries remain
under their respective upstream licenses; source links and credits are listed
in the project README.
