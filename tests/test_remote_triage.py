"""Local-only regression tests for the SSH triage runner.

All SSH calls are intercepted by a synthetic executable in a temporary PATH.
No real host, credentials, or network connection are used.
"""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tools" / "remote_triage.sh"


FAKE_SSH = r'''#!/usr/bin/env python3
import json
import os
import sys

with open(os.environ["MOCK_SSH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"argv": sys.argv[1:], "remote": sys.argv[-1]}) + "\n")
sys.stdin.read()
if sum(1 for _ in open(os.environ["MOCK_SSH_LOG"], encoding="utf-8")) == 1:
    print("=== CONNECTIVITY 2026-01-01T00:00:00Z ===")
    print("synthetic-host")
    print("Linux synthetic 1 x86_64 GNU/Linux")
    print("uid=0(root) gid=0(root)")
    print("2026-01-01T00:00:00Z")
    print("up 1 day")
'''


class RemoteTriageRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="remote-triage-test-")
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "ssh-args.jsonl"
        fake = self.bin / "ssh"
        fake.write_text(FAKE_SSH, encoding="utf-8")
        fake.chmod(0o700)
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["MOCK_SSH_LOG"] = str(self.log)

    def tearDown(self):
        self.temp.cleanup()

    def run_runner(self, *args):
        return subprocess.run(
            ["bash", str(RUNNER), *args],
            capture_output=True,
            text=True,
            timeout=45,
            env=self.env,
            check=False,
        )

    def test_since_is_data_and_evidence_is_private_and_repeatable(self):
        output = self.root / "private evidence"
        sentinel = self.root / "must-not-execute"
        payload = f'1 day ago"; touch {sentinel}; #'

        result = self.run_runner(
            "--host", "example.invalid",
            "--port", "2222",
            "--user", "analyst",
            "--output-dir", str(output),
            "--since", payload,
            "--step-timeout", "2",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(calls), 13)
        remote_command = calls[0]["remote"]
        self.assertIn("SINCE=", remote_command)
        self.assertNotIn("; touch", remote_command)
        syntax = subprocess.run(
            ["bash", "-n", "-c", remote_command],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        artifacts = list(output.iterdir())
        self.assertEqual(len(artifacts), 14)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0 for path in artifacts))
        manifest = (output / "evidence.sha256").read_text().splitlines()
        self.assertEqual(len(manifest), 13)
        self.assertFalse(any("evidence.sha256" in line for line in manifest))

    def test_nonempty_output_directory_is_not_overwritten(self):
        output = self.root / "existing"
        output.mkdir(mode=0o755)
        existing = output / "prior-evidence"
        existing.write_text("preserve me", encoding="utf-8")

        result = self.run_runner(
            "--host", "example.invalid",
            "--output-dir", str(output),
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(existing.read_text(), "preserve me")
        self.assertFalse(self.log.exists())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)

    def test_invalid_port_is_rejected_before_creating_output(self):
        output = self.root / "not-created"

        result = self.run_runner(
            "--host", "example.invalid",
            "--port", "99999",
            "--output-dir", str(output),
        )

        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertFalse(self.log.exists())

    def test_hash_helper_handles_spaces_and_repeat_runs(self):
        helper_doc = (REPO / "skills" / "common" / "helpers.md").read_text(encoding="utf-8")
        match = re.search(
            r"# \[risk:ro\] \[mode:auto\] \[module:hash_evidence\]\n(.*?)\n```",
            helper_doc,
            re.S,
        )
        self.assertIsNotNone(match)
        output = self.root / "evidence with spaces"
        output.mkdir(mode=0o700)
        artifact = output / "host artifact with spaces.txt"
        artifact.write_text("synthetic evidence\n", encoding="utf-8")
        env = os.environ.copy()
        env["OUTPUT_DIR"] = str(output)

        for _ in range(2):
            result = subprocess.run(
                ["bash", "-c", match.group(1)],
                capture_output=True,
                text=True,
                timeout=5,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            check = subprocess.run(
                ["sha256sum", "-c", "evidence.sha256"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=output,
                check=False,
            )
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            manifest = (output / "evidence.sha256").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(manifest), 1)
            self.assertIn("host artifact with spaces.txt", manifest[0])
            self.assertNotIn("evidence.sha256", manifest[0])


if __name__ == "__main__":
    unittest.main()
