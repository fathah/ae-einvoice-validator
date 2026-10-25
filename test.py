#!/usr/bin/env python3
"""Run actual official rules in an isolated cached validator image; no provider calls."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent
IMAGE = os.environ.get("EINVOICE_VALIDATOR_TEST_IMAGE", "ziqx-ae-einvoice-validator:validation")
TOKEN = "synthetic-test-token-never-a-provider-secret"
GENERATED_FIXTURES = ["generated-invoice.xml", "generated-credit.xml"] + [
    f"generated-{kind}-{document}.xml"
    for kind in ["taxable-discount", "zero-rated", "exempt", "reverse-charge", "disbursement", "rounding", "outside-scope"]
    for document in ["invoice", "credit"]
]

def run(*args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)

def main():
    run("docker", "image", "inspect", IMAGE)
    name = "ziqx-einvoice-validator-test-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="ziqx-validator-public-fixtures-") as temporary:
        fixtures = Path(temporary)
        fixtures.chmod(0o755)
        with zipfile.ZipFile(ROOT / "resources/pint-ae-1.0.4/billing-resources.zip") as archive:
            invoice = archive.read("trn-invoice/example/Standard tax invoice.xml")
            credit = archive.read("trn-creditnote/example/Standard tax credit Note.xml")
        facts = {
            "invoice.xml": invoice,
            "credit.xml": credit,
            "rules-failure.xml": re.sub(rb"<cbc:ProfileID>.*?</cbc:ProfileID>", b"<cbc:ProfileID>invalid-profile</cbc:ProfileID>", invoice, flags=re.S),
            "xsd-failure.xml": b'<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"/>',
            "entity.xml": b'<!DOCTYPE Invoice [<!ENTITY private SYSTEM "file:///etc/passwd">]><Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">&private;</Invoice>',
            "remote-entity.xml": b'<!DOCTYPE Invoice SYSTEM "http://169.254.169.254/private"><Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"/>',
            "deep.xml": b"<a>" * 65 + b"</a>" * 65,
            "oversize.xml": b"x" * (8 * 1024 * 1024 + 1),
        }
        facts.update({file: (ROOT / "testdata" / file).read_bytes() for file in GENERATED_FIXTURES})
        assert facts["rules-failure.xml"] != invoice
        for key, value in facts.items():
            (fixtures / key).write_bytes(value)
        run("docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,mode=1777", "--memory", "1536m", "--cpus", "2", "--pids-limit", "96", "-e", "EINVOICE_VALIDATOR_TOKEN=" + TOKEN, "--mount", "type=bind,src=" + str(fixtures) + ",dst=/fixtures,readonly", IMAGE)
        try:
            for _ in range(20):
                response = run("docker", "exec", name, "wget", "-q", "-T", "2", "-O", "-", "http://127.0.0.1:8081/v1/healthz", check=False)
                if response.returncode == 0:
                    break
                time.sleep(.25)
            else:
                raise AssertionError("private validator did not become ready")
            health = json.loads(response.stdout)
            expected_manifest = hashlib.sha256((ROOT / "resources/pint-ae-1.0.4/manifest.json").read_bytes()).hexdigest()
            assert health == {"specificationVersion": "pint-ae-1.0.4", "resourceManifestDigest": expected_manifest}
            def request(file, token=TOKEN, encoding=None, legacy=False):
                cmd = ["docker", "exec", name, "wget", "-S", "-T", "35", "-O", "-", "--header", "Content-Type: application/xml", "--header", ("X-Wusooly-Specification" if legacy else "X-Ziqx-Specification") + ": pint-ae-1.0.4", "--post-file", "/fixtures/" + file]
                if token:
                    cmd.extend(["--header", "Authorization: Bearer " + token])
                if encoding:
                    cmd.extend(["--header", "Content-Encoding: " + encoding])
                cmd.append("http://127.0.0.1:8081" + ("/validate" if legacy else "/v1/validate"))
                return run(*cmd, check=False)
            # Retain the unversioned API for existing server-to-server clients.
            assert json.loads(request("invoice.xml", legacy=True).stdout)["valid"]
            failed_fixtures = []
            for file in ["invoice.xml", "credit.xml"] + GENERATED_FIXTURES:
                reply = request(file)
                assert reply.returncode == 0, reply.stderr.decode()
                report = json.loads(reply.stdout)
                if not (report["valid"] and report["xsdValid"] and report["rulesExecuted"] == 2 and report["failedRules"] == []):
                    failed_fixtures.append((file, report))
                assert report["documentDigest"] == hashlib.sha256(facts[file]).hexdigest()
                assert report["resourceManifestDigest"] == expected_manifest
            assert not failed_fixtures, failed_fixtures
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                concurrent_replies = list(pool.map(lambda _: request("invoice.xml"), range(3)))
            assert sum(reply.returncode == 0 for reply in concurrent_replies) == 2
            assert sum(b"503" in reply.stderr for reply in concurrent_replies) == 1
            for reply in concurrent_replies:
                if reply.returncode == 0:
                    assert json.loads(reply.stdout)["valid"]
            report = json.loads(request("rules-failure.xml").stdout)
            assert report["xsdValid"] and report["rulesExecuted"] == 2 and not report["valid"] and report["failedRules"]
            assert b"invalid-profile" not in json.dumps(report).encode()
            for file in ["xsd-failure.xml", "entity.xml", "remote-entity.xml", "deep.xml"]:
                report = json.loads(request(file).stdout)
                assert not report["valid"] and not report["xsdValid"] and report["rulesExecuted"] == 0
                assert report["failedRules"] and "root:" not in json.dumps(report)
            assert b"413" in request("oversize.xml").stderr
            assert b"415" in request("invoice.xml", encoding="gzip").stderr
            assert b"401" in request("invoice.xml", token="").stderr
            headers = "POST /validate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\nContent-Type: application/xml\r\n\r\n"
            hold = "(printf '%s' '" + headers + "'; sleep 5) | nc -w 6 127.0.0.1 8081"
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                held = [pool.submit(run, "docker", "exec", name, "/bin/sh", "-c", hold, check=False) for _ in range(4)]
                time.sleep(.75)
                health_response = run("docker", "exec", name, "wget", "-q", "-T", "2", "-O", "-", "http://127.0.0.1:8081/v1/healthz", check=False)
                assert health_response.returncode == 0, "header-only denied bodies occupied every private HTTP worker"
                for pending in held:
                    assert b"401" in pending.result().stdout
            assert run("docker", "logs", name).stdout == b""
            inspected = json.loads(run("docker", "inspect", name).stdout)[0]
            assert inspected["HostConfig"]["NetworkMode"] == "none" and inspected["Config"]["User"] == "65532:65532"
            assert inspected["HostConfig"]["ReadonlyRootfs"]
            print("PASS: real offline XSD + both PINT-AE rule sets, invoice/credit fixtures, failed rules, XXE/DTD/depth/body/encoding/auth limits; no document logs.")
        finally:
            run("docker", "rm", "-f", name, check=False)

if __name__ == "__main__":
    main()
