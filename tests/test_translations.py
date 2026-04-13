"""Translation consistency tests."""
from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRANSLATIONS_DIR = ROOT / "custom_components" / "repsol_vivit" / "translations"
LANGUAGES = ("es", "en", "pt")


def _load_translation(language: str) -> dict:
    return json.loads((TRANSLATIONS_DIR / f"{language}.json").read_text(encoding="utf-8"))


class TranslationTests(unittest.TestCase):
    """Ensure the main translation keys exist for every supported language."""

    def test_reauth_keys_exist_in_all_languages(self) -> None:
        for language in LANGUAGES:
            data = _load_translation(language)
            reauth = data["config"]["step"]["reauth_confirm"]["data"]
            self.assertIn("username", reauth, language)
            self.assertIn("password", reauth, language)
            self.assertIn("contract_not_found", data["config"]["error"], language)
            self.assertIn("reauth_successful", data["config"]["abort"], language)

    def test_options_keys_exist_in_all_languages(self) -> None:
        for language in LANGUAGES:
            data = _load_translation(language)
            options = data["options"]["step"]["init"]["data"]
            self.assertIn("update_interval_minutes", options, language)
            self.assertIn("enable_virtual_battery_sensors", options, language)


if __name__ == "__main__":
    unittest.main()
