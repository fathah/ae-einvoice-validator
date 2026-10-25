"""Security boundaries of the local release scanner, without network access."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("security_scan", Path(__file__).with_name("security_scan.py"))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class SourceSnapshotTests(unittest.TestCase):
    def test_shallow_history_cannot_be_reported_as_a_complete_source_scan(self):
        with tempfile.TemporaryDirectory() as path:
            with patch.object(scanner.subprocess, "check_output", return_value=b"true\n"), patch.object(scanner, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "Complete repository history"):
                    scanner.source_scan(Path(path) / "gitleaks", Path(path))
            run.assert_not_called()

    def test_symlink_scans_link_text_without_reading_external_content(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            root, destination = directory / "repo", directory / "snapshot"
            root.mkdir()
            destination.mkdir()
            external = directory / "private"
            external.write_text("private target bytes must stay outside the scan")
            (root / "sdk").symlink_to(external)
            with patch.object(scanner, "ROOT", root), patch.object(scanner.subprocess, "check_output", return_value=b"sdk\0"):
                scanner.snapshot(destination)
            self.assertEqual((destination / "sdk").read_bytes(), os.fsencode(external))

    def test_real_environment_file_is_rejected_even_when_git_tracks_it(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / ".env.backend").write_text("synthetic")
            with patch.object(scanner, "ROOT", root), patch.object(scanner.subprocess, "check_output", return_value=b".env.backend\0"):
                with self.assertRaisesRegex(RuntimeError, "Real environment files"):
                    scanner.snapshot(root / "snapshot")

    def test_symlink_parent_cannot_import_external_files(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / "linked").symlink_to(root.parent, target_is_directory=True)
            with patch.object(scanner, "ROOT", root), patch.object(scanner.subprocess, "check_output", return_value=b"linked/private\0"):
                with self.assertRaisesRegex(RuntimeError, "Unsafe source snapshot parent"):
                    scanner.snapshot(root / "snapshot")


class ImageScanTests(unittest.TestCase):
    def test_scan_cannot_inherit_registry_credentials_or_suppression_config(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            archive = root / "local-image.tar"
            archive.touch()
            with patch.dict(os.environ, {"TRIVY_PASSWORD": "synthetic", "GITHUB_TOKEN": "synthetic"}), patch.object(scanner, "run") as run:
                scanner.image_scan(root / "trivy", archive, root / "cache", root)
            command, environment = run.call_args.args[:2]
            self.assertNotIn("TRIVY_PASSWORD", environment)
            self.assertNotIn("GITHUB_TOKEN", environment)
            self.assertEqual(Path(command[command.index("--config") + 1]).read_text(), "{}\n")
            self.assertEqual(Path(command[command.index("--ignorefile") + 1]).read_text(), "")
            self.assertEqual(command[command.index("--input") + 1], archive)
            self.assertIn("--offline-scan", command)
            self.assertEqual(run.call_args.kwargs["cwd"], root)


class ScannerInstallTests(unittest.TestCase):
    def install_fixture(self, root, member_size, checksum_valid=True):
        raw = b"synthetic archive bytes"
        pins = root / "pins.json"
        pins.write_text(json.dumps({"trivy": {"repository": "aquasecurity/trivy", "version": "test", "archives": {
            "Darwin-arm64": {"name": "test.tar.gz", "sha256": hashlib.sha256(raw if checksum_valid else b"different").hexdigest()}
        }}}))
        member = tarfile.TarInfo("trivy")
        member.size = member_size
        archive = MagicMock()
        archive.__enter__.return_value = archive
        archive.getmember.return_value = member
        archive.extractfile.return_value = io.BytesIO(b"synthetic executable")
        with patch.object(scanner, "PINS", pins), patch.object(scanner.platform, "system", return_value="Darwin"), patch.object(scanner.platform, "machine", return_value="arm64"), patch.object(scanner.urllib.request, "urlopen", return_value=io.BytesIO(raw)), patch.object(scanner.tarfile, "open", return_value=archive):
            return scanner.install("trivy", root)

    def test_checksum_verified_large_scanner_is_supported(self):
        with tempfile.TemporaryDirectory() as path:
            executable = self.install_fixture(Path(path), 200 * 1024 * 1024)
            self.assertEqual(executable.read_bytes(), b"synthetic executable")
            self.assertEqual(executable.stat().st_mode & 0o777, 0o755)

    def test_oversized_or_unverified_scanner_is_never_written(self):
        for size, valid in [(257 * 1024 * 1024, True), (1024, False)]:
            with self.subTest(size=size, valid=valid), tempfile.TemporaryDirectory() as path:
                root = Path(path)
                with self.assertRaises(RuntimeError):
                    self.install_fixture(root, size, valid)
                self.assertFalse((root / "trivy").exists())


if __name__ == "__main__":
    unittest.main()
