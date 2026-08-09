from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import (  # noqa: E402
    ManifestError,
    canonical_bytes,
    load_manifest,
    strict_load_bytes,
    validate_manifest,
)


FIXTURES = ROOT / "fixtures" / "contracts"
EXPECTED = "sha256:0448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45"


class ManifestTests(unittest.TestCase):
    def test_valid_reordered_manifests_share_digest(self) -> None:
        minimal = load_manifest(FIXTURES / "workflow.valid.minimal.json")
        reordered = load_manifest(FIXTURES / "workflow.valid.reordered.json")
        self.assertEqual(EXPECTED, minimal.digest)
        self.assertEqual(minimal.digest, reordered.digest)
        self.assertEqual(minimal.canonical, reordered.canonical)
        self.assertEqual(
            hashlib.sha256(minimal.canonical).hexdigest(),
            EXPECTED.removeprefix("sha256:"),
        )

    def test_canonical_bytes_use_utf16_property_order(self) -> None:
        value = {"\ue000": 1, "\U00010000": 2}
        self.assertEqual('{"\U00010000":2,"\ue000":1}'.encode("utf-8"), canonical_bytes(value))

    def test_duplicate_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "duplicate object name") as caught:
            load_manifest(FIXTURES / "workflow.invalid.duplicate-key.json")
        self.assertEqual("IS_MANIFEST_DUPLICATE_KEY", caught.exception.code)

    def test_float_is_rejected(self) -> None:
        with self.assertRaises(ManifestError) as caught:
            load_manifest(FIXTURES / "workflow.invalid.float.json")
        self.assertEqual("IS_MANIFEST_NUMBER_DOMAIN", caught.exception.code)

    def test_network_policy_change_is_rejected(self) -> None:
        with self.assertRaises(ManifestError) as caught:
            load_manifest(FIXTURES / "workflow.invalid.network.json")
        self.assertEqual("IS_MANIFEST_SCHEMA", caught.exception.code)

    def test_integer_cannot_substitute_for_security_boolean(self) -> None:
        value = json.loads((FIXTURES / "workflow.valid.minimal.json").read_text(encoding="utf-8"))
        value["security"]["privileged"] = 0
        with self.assertRaises(ManifestError) as caught:
            validate_manifest(value)
        self.assertEqual("IS_MANIFEST_SCHEMA", caught.exception.code)

    def test_malformed_enum_value_is_invalid_not_internal(self) -> None:
        value = json.loads((FIXTURES / "workflow.valid.minimal.json").read_text(encoding="utf-8"))
        value["steps"][0]["runner"] = ["python"]
        with self.assertRaises(ManifestError) as caught:
            validate_manifest(value)
        self.assertEqual("IS_MANIFEST_SCHEMA", caught.exception.code)

    def test_bom_invalid_utf8_trailing_data_and_surrogate_are_rejected(self) -> None:
        samples = [
            (b"\xef\xbb\xbf{}", "IS_MANIFEST_ENCODING"),
            (b"\xff", "IS_MANIFEST_ENCODING"),
            (b"{}{}", "IS_MANIFEST_JSON"),
            (json.dumps({"value": "\ud800"}).encode("ascii"), "IS_MANIFEST_UNICODE"),
        ]
        for raw, expected in samples:
            with self.subTest(expected=expected):
                with self.assertRaises(ManifestError) as caught:
                    strict_load_bytes(raw)
                self.assertEqual(expected, caught.exception.code)


if __name__ == "__main__":
    unittest.main()
