#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$ROOT/ramdisk/ios7-keydiag"

xcrun clang \
    -target arm64-apple-ios7.0 \
    -isysroot "$SDK" \
    -Os -Wall -Wextra -Werror \
    "$ROOT/diagnostics/ios7_keydiag.c" \
    -framework IOKit -framework CoreFoundation \
    -o "$OUT"
codesign -f -s - "$OUT"
chmod 755 "$OUT"
file "$OUT"
shasum -a 256 "$OUT"
