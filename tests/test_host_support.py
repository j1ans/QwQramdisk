import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.common import host_platform, kit_bin
from tools.boot import _pwn_command
from qwqramdisk import LINUX_UDEV_RULE, ensure_linux_udev_rule


class HostPlatformTests(unittest.TestCase):
    def test_linux_arch_aliases(self):
        self.assertEqual(host_platform("Linux", "x86_64"),
                         ("linux", "x86_64"))
        self.assertEqual(host_platform("Linux", "amd64"),
                         ("linux", "x86_64"))
        self.assertEqual(host_platform("Linux", "aarch64"),
                         ("linux", "arm64"))

    def test_unknown_host_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "unsupported host platform"):
            host_platform("FreeBSD", "x86_64")

    def test_linux_resolver_never_falls_back_to_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong = root / "bin/linux/arm64/example"
            wrong.parent.mkdir(parents=True)
            wrong.write_text("#!/bin/sh\n")
            wrong.chmod(0o755)
            uname = mock.Mock(sysname="Linux", machine="x86_64")
            with mock.patch("tools.common.os.uname", return_value=uname):
                with self.assertRaises(FileNotFoundError):
                    kit_bin(root, "example")

    def test_linux_resolver_requires_executable_bit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin/linux/x86_64/example"
            binary.parent.mkdir(parents=True)
            binary.write_text("not executable")
            uname = mock.Mock(sysname="Linux", machine="x86_64")
            with mock.patch("tools.common.os.uname", return_value=uname):
                with self.assertRaises(FileNotFoundError):
                    kit_bin(root, "example")
                binary.chmod(0o755)
                self.assertEqual(kit_bin(root, "example"), binary.resolve())

    def test_linux_a7_uses_gaster_instead_of_macos_ipwnder(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with mock.patch("tools.boot.host_platform",
                            return_value=("linux", "x86_64")), \
                    mock.patch("tools.boot.kit_bin",
                               return_value=Path("/tools/gaster")):
                exploit, command, apple_silicon = _pwn_command(
                    "/tools", output, {"exploit": "ipwnder"})
            self.assertEqual(exploit, "gaster")
            self.assertEqual(command, ["/tools/gaster", "pwn"])
            self.assertFalse(apple_silicon)

    def test_embedded_linux_rule_matches_legacy_ios_kit(self):
        self.assertEqual(
            LINUX_UDEV_RULE,
            'SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", '
            'MODE:="0666", TAG+="uaccess"\n')
        self.assertNotIn("GROUP=", LINUX_UDEV_RULE)

    def test_existing_linux_rule_is_not_replaced(self):
        fake_path = mock.Mock()
        fake_path.is_file.return_value = True
        fake_path.stat.return_value.st_size = 1
        with mock.patch("qwqramdisk.LINUX_UDEV_PATH", fake_path), \
                mock.patch("qwqramdisk.subprocess.run") as run:
            self.assertFalse(ensure_linux_udev_rule())
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
