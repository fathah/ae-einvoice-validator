"""Verify the standalone resource closure and API contract without other repositories."""
import hashlib
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    def test_every_frozen_resource_and_original_entry_matches_its_manifest(self):
        resources = ROOT / "resources/pint-ae-1.0.4"
        manifest = json.loads((resources / "manifest.json").read_text())
        self.assertEqual(manifest["specificationVersion"], "pint-ae-1.0.4")
        for artifact in manifest["artifacts"]:
            content = (resources / artifact["filename"]).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), artifact["sha256"])
            self.assertEqual(len(content), artifact["bytes"])
            with zipfile.ZipFile(resources / artifact["filename"]) as archive:
                for entry in artifact["entries"]:
                    content = archive.read(entry["path"])
                    self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"])

    def test_api_contract_has_versioned_routes_and_authenticated_validation(self):
        contract = json.loads((ROOT / "openapi.yaml").read_text())
        self.assertEqual(contract["info"]["title"], "Ziqx UAE e-Invoice Validator")
        self.assertIn("get", contract["paths"]["/v1/healthz"])
        operation = contract["paths"]["/v1/validate"]["post"]
        self.assertEqual(operation["security"], [{"serviceToken": []}])
        self.assertEqual(operation["parameters"][0]["name"], "X-Ziqx-Specification")
        self.assertTrue(contract["paths"]["/validate"]["post"]["deprecated"])

    def test_build_and_fixture_inputs_are_self_contained(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertNotIn("backend/", dockerfile)
        self.assertNotIn("internal/einvoice", dockerfile)
        self.assertIn("brotli-libs>=1.2.1-r0", dockerfile)
        self.assertEqual(len(list((ROOT / "testdata").glob("generated-*.xml"))), 16)


if __name__ == "__main__":
    unittest.main()
