#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import tools.boot as boot


class DarwinArm64:
    sysname = "Darwin"
    machine = "arm64"


class PwnRetryTests(unittest.TestCase):
    def run_case(self, queries, ipwnder_results, retries=3):
        queries = iter(queries)
        ipwnder_results = iter(ipwnder_results)
        calls = []

        def fake_run(command, **kwargs):
            command = tuple(map(str, command)); calls.append(command)
            if command[-1] == "-q":
                return next(queries)
            if Path(command[0]).name == "ipwnder":
                return subprocess.CompletedProcess(
                    command, next(ipwnder_results), "", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory(prefix="ios7-pwn-retry.") as tmp:
            with patch.object(boot.os, "uname", return_value=DarwinArm64()), \
                 patch.object(boot, "kit_bin",
                              side_effect=lambda root, name: Path("/tmp") / name), \
                 patch.object(boot.subprocess, "run", side_effect=fake_run), \
                 patch.object(boot.time, "sleep"):
                result = boot._pwn_retry(
                    "/kit", Path(tmp), Path("/tmp/irecovery"), retries, 1)
        return result, calls

    def test_retries_failed_exploit_while_device_remains_in_dfu(self):
        result, calls = self.run_case([
            subprocess.CompletedProcess([], 0, "MODE: DFU\n", ""),
            subprocess.CompletedProcess([], 0, "MODE: DFU\nPWND: checkm8\n", ""),
        ], [255, 0])
        self.assertIn("PWND", result)
        self.assertEqual(2, sum(Path(call[0]).name == "ipwnder"
                                for call in calls))

    def test_accepts_pwnd_marker_after_nonzero_exploit_exit(self):
        result, calls = self.run_case([
            subprocess.CompletedProcess([], 0, "MODE: DFU\nPWND: checkm8\n", ""),
        ], [255])
        self.assertIn("PWND", result)
        self.assertFalse(any(Path(call[0]).name == "gaster" for call in calls))

    def test_waits_for_transient_usb_reenumeration(self):
        result, _ = self.run_case([
            subprocess.CompletedProcess([], 1, "", "no device"),
            subprocess.CompletedProcess([], 0, "MODE: DFU\nPWND: checkm8\n", ""),
        ], [0])
        self.assertIn("PWND", result)


if __name__ == "__main__":
    unittest.main()
