"""Repository metadata consistency tests."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "custom_components" / "repsol_vivit" / "manifest.json"
README_PATH = ROOT / "README.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"


class MetadataTests(unittest.TestCase):
    """Ensure public version metadata stays aligned."""

    def test_public_version_is_consistent(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        version = manifest["version"]
        readme = README_PATH.read_text(encoding="utf-8")
        changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

        self.assertEqual(version, "2.1.1")
        self.assertIn(f"version-{version}-blue.svg", readme)
        self.assertIn(f"**Versión:** {version}", readme)
        self.assertIsNotNone(re.search(rf"^## {re.escape(version)}\b", changelog, re.MULTILINE))


if __name__ == "__main__":
    unittest.main()
