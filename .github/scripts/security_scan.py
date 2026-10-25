#!/usr/bin/env python3
"""Local-only, fail-closed source and OCI archive security checks."""
import argparse
import hashlib
import io
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / ".github/security-tools.json"


def install(name, directory):
    pin = json.loads(PINS.read_text())[name]
    selected = pin["archives"][platform.system() + "-" + platform.machine()]
    url = f'https://github.com/{pin["repository"]}/releases/download/v{pin["version"]}/{selected["name"]}'
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(100 * 1024 * 1024 + 1)
    if len(raw) > 100 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != selected["sha256"]:
        raise RuntimeError("Scanner archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        member = archive.getmember(name)
        # Pinned Trivy 0.75.0 Darwin ARM64 is 165,317,138 bytes, exceeding
        # 150 MiB. Keep a finite extraction bound that also supports that build.
        if not member.isfile() or member.size > 256 * 1024 * 1024:
            raise RuntimeError("Invalid scanner archive")
        executable = directory / name
        executable.write_bytes(archive.extractfile(member).read())
        executable.chmod(0o755)
    return executable


def run(command, environment=None, cwd=ROOT):
    subprocess.run([str(value) for value in command], check=True, cwd=cwd, env=environment, timeout=900)


def snapshot(destination):
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).split(b"\0")
    for raw in names:
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        source = ROOT / relative
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("Unsafe source snapshot path")
        if any((ROOT / parent).is_symlink() for parent in relative.parents if parent != Path(".")):
            raise RuntimeError("Unsafe source snapshot parent")
        if source.name.startswith(".env") and not source.name.endswith(".example"):
            raise RuntimeError("Real environment files cannot enter a source scan")
        target = destination / relative
        if source.is_symlink():
            # Git stores a link's target text. Scan that same text without reading
            # any external file (repository SDK skill links are intentional).
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(os.fsencode(os.readlink(source)))
            continue
        if not source.exists():
            continue
        if not source.is_file():
            raise RuntimeError("Unsupported source snapshot entry")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def source_scan(executable, temporary):
    # No credential environment, ignore file, inline bypass, external service,
    # or report upload. Reports contain fully redacted values and stay temporary.
    environment = {"PATH": os.environ["PATH"], "HOME": str(temporary), "GIT_CONFIG_NOSYSTEM": "1"}
    shallow = subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=ROOT, env=environment).strip()
    if shallow != b"false":
        raise RuntimeError("Complete repository history is required for source scanning")
    ignored = temporary / "empty-ignore"
    ignored.write_text("")
    common = [executable, "--config", ROOT / ".gitleaks.toml", "--redact=100", "--no-banner", "--log-level=error", "--ignore-gitleaks-allow", "--gitleaks-ignore-path", ignored, "--timeout", "600", "--exit-code", "1", "--report-format", "json"]
    run([*common, "--report-path", temporary / "history.json", "git", "--log-opts=--all", ROOT], environment)
    tree = temporary / "source"
    tree.mkdir()
    snapshot(tree)
    run([*common, "--report-path", temporary / "source.json", "dir", tree], environment)
    print("Source history and current non-ignored files passed (reports local and redacted).")


def image_scan(executable, archive, cache, temporary):
    if not archive.is_file():
        raise RuntimeError("Local image archive is missing")
    # Do not inherit a working-tree Trivy configuration or suppression policy.
    configuration = temporary / "trivy.yaml"
    configuration.write_text("{}\n")
    ignored = temporary / "empty-ignore"
    ignored.write_text("")
    flags = ["--config", configuration, "--disable-telemetry", "--skip-version-check", "--no-progress", "--table-mode", "detailed", "--timeout", "10m", "--cache-dir", cache,
             "--db-repository", "ghcr.io/aquasecurity/trivy-db:2", "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db:1"]
    # Only public advisory/index databases are downloaded; no target is supplied.
    environment = {"PATH": os.environ["PATH"], "HOME": str(temporary)}
    run([executable, "image", "--download-db-only", *flags], environment)
    run([executable, "image", "--download-java-db-only", *flags], environment)
    # The target is a local archive: no Docker socket, registry fallback, Maven
    # lookup, VEX update, telemetry, manifest upload, or suppression file.
    run([executable, "image", "--input", archive, *flags, "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--ignorefile", ignored, "--exit-code", "1"], environment, cwd=temporary)
    print("Local image archive passed the HIGH/CRITICAL vulnerability gate.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["source", "image"])
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--tool", type=Path, help="Use an already checksum-verified local binary")
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ziqx-validator-security-") as path:
        temporary = Path(path)
        executable = args.tool.resolve() if args.tool else install("gitleaks" if args.mode == "source" else "trivy", temporary)
        if args.mode == "source":
            source_scan(executable, temporary)
        else:
            if not args.archive:
                parser.error("image mode requires --archive")
            image_scan(executable, args.archive.resolve(), (args.cache or temporary / "cache").resolve(), temporary)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("Security scan failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
