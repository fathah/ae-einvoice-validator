#!/usr/bin/env python3
"""Exercise the deployable API without touching an existing project or .env."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def main():
    image = os.environ.get("EINVOICE_VALIDATOR_TEST_IMAGE", "ziqx-ae-einvoice-validator:validation")
    with tempfile.TemporaryDirectory(prefix="ziqx-validator-compose-") as raw:
        directory = Path(raw)
        shutil.copy2(ROOT / "compose.yaml", directory / "compose.yaml")
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]
        token = secrets.token_hex(32)
        (directory / ".env").write_text(f"VALIDATOR_IMAGE={image}\nVALIDATOR_BIND_PORT={port}\nEINVOICE_VALIDATOR_TOKEN={token}\n")
        project = "ziqx-validator-test-" + secrets.token_hex(6)
        command = ["docker", "compose", "--project-name", project, "--project-directory", raw]
        # Ignore any user-configured HTTP proxy, including for the loopback fixture.
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            run(*command, "config", "--quiet")
            assert run(*command, "config", "--services") == "validator", "deployment must run only the validator"
            run(*command, "up", "--detach", "--wait", "--wait-timeout", "90")
            validator = run(*command, "ps", "--quiet", "validator")
            network = json.loads(run("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", validator))
            assert len(network) == 1, "validator must only join its own Compose network"
            owner = run("docker", "network", "inspect", "--format", '{{index .Labels "com.docker.compose.project"}}', next(iter(network)))
            assert owner == project, "validator network must belong to this independent Compose project"
            ports = run("docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", validator)
            assert json.loads(ports) == {"8081/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}, "validator must publish only its loopback API port"
            base = f"http://127.0.0.1:{port}"
            with client.open(base + "/v1/healthz", timeout=5) as response:
                health = json.load(response)
            body = (ROOT / "testdata/generated-invoice.xml").read_bytes()
            for route, header in (("/v1/validate", "X-Ziqx-Specification"), ("/validate", "X-Wusooly-Specification")):
                request = urllib.request.Request(base + route, data=body, headers={"Content-Type": "application/xml", "Authorization": "Bearer " + token, header: "pint-ae-1.0.4"})
                with client.open(request, timeout=35) as response:
                    report = json.load(response)
                assert report["valid"] and report["xsdValid"] and report["rulesExecuted"] == 2 and not report["failedRules"]
                assert report["documentDigest"] == hashlib.sha256(body).hexdigest()
                assert report["resourceManifestDigest"] == health["resourceManifestDigest"]
            request = urllib.request.Request(base + "/v1/validate", data=body, headers={"Content-Type": "application/xml", "X-Ziqx-Specification": "pint-ae-1.0.4"})
            try:
                client.open(request, timeout=5).close()
                raise AssertionError("unauthenticated request was accepted")
            except urllib.error.HTTPError as error:
                assert error.code == 401
                error.close()
            print("PASS: single-container Compose API, direct loopback access, authenticated v1/legacy validation, separate project network.")
        finally:
            run(*command, "down", "--remove-orphans")


if __name__ == "__main__":
    main()
