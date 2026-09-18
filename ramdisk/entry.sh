#!/bin/bash
export PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin
exec >/dev/console 2>&1
echo '============================================================'
echo ' qwqramdisk — iOS 7/8 arm64 — mount data with: mount-mnt2'
echo ' SSH root password: alpine'
echo '============================================================'
/usr/local/bin/dropbear -E &
exec /usr/local/bin/ramdisk-usb-start
