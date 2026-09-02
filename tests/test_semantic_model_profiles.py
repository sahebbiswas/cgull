"""Tests for built-in semantic-model profiles."""

import os
import tempfile
import unittest

from cgull.config import load_config
from cgull.semantic_model_profiles import (
    BUILTIN_SEMANTIC_MODEL_PROFILE_VERSIONS,
    EMBEDDED_SECURITY_PROFILE,
    EMBEDDED_SECURITY_PROFILE_VERSION,
)
from cgull.semantic_models import (
    SemanticLocation,
    SemanticLocationKind,
    ValidationProperty,
    parse_semantic_models,
)


class TestEmbeddedSecurityProfile(unittest.TestCase):
    def test_profile_version_is_pinned(self):
        self.assertEqual(EMBEDDED_SECURITY_PROFILE, "embedded-security")
        self.assertEqual(EMBEDDED_SECURITY_PROFILE_VERSION, 1)
        self.assertEqual(
            BUILTIN_SEMANTIC_MODEL_PROFILE_VERSIONS[EMBEDDED_SECURITY_PROFILE], 1
        )

    def test_profile_covers_embedded_trust_boundary_families(self):
        registry = parse_semantic_models({"profiles": ["embedded-security"]})

        for source in (
            "mailbox_receive",
            "uart_receive",
            "spi_receive",
            "i2c_receive",
            "dma_descriptor_receive",
            "firmware_image_receive",
            "update_manifest_receive",
        ):
            self.assertIn(source, registry.sources)

        for sink in (
            "flash_write",
            "flash_erase",
            "nvram_write",
            "mmio_write",
            "dma_start",
            "debug_enable",
            "boot_image_accept",
            "update_activate",
        ):
            self.assertIn(sink, registry.sinks)

        expected_validators = {
            "validate_bounds": ValidationProperty.BOUNDS_CHECKED,
            "validate_range": ValidationProperty.BOUNDS_CHECKED,
            "authenticate_request": ValidationProperty.AUTHENTICATED,
            "authorize_request": ValidationProperty.AUTHORIZED,
            "verify_signature": ValidationProperty.SIGNATURE_VERIFIED,
            "check_version": ValidationProperty.VERSION_CHECKED,
            "check_rollback": ValidationProperty.VERSION_CHECKED,
            "check_allowlist": ValidationProperty.ALLOWLISTED,
        }
        for function, prop in expected_validators.items():
            self.assertEqual(registry.validators[function].property, prop)

    def test_posix_input_models_taint_written_buffer_not_byte_count(self):
        registry = parse_semantic_models({"profiles": ["embedded-security"]})
        read_model = registry.sources["read"]
        self.assertEqual(
            read_model.outputs,
            (SemanticLocation(SemanticLocationKind.OUTPUT_ARGUMENT, 1),),
        )

    def test_project_models_extend_profile(self):
        registry = parse_semantic_models(
            {
                "profiles": ["embedded-security"],
                "sources": [
                    {"function": "vendor_mailbox_rx", "outputs": ["out:1"]}
                ],
                "validators": [
                    {
                        "function": "vendor_acl_check",
                        "target": "arg:0",
                        "property": "authorized",
                        "success": "return_zero",
                    }
                ],
                "sinks": [
                    {
                        "function": "vendor_flash_program",
                        "requirements": {
                            "arg:0": ["bounds_checked", "authorized"]
                        },
                    }
                ],
            }
        )
        self.assertIn("mailbox_receive", registry.sources)
        self.assertIn("vendor_mailbox_rx", registry.sources)
        self.assertIn("vendor_acl_check", registry.validators)
        self.assertIn("vendor_flash_program", registry.sinks)

    def test_overlay_cannot_silently_replace_profile_contract(self):
        with self.assertRaisesRegex(ValueError, "duplicate source model"):
            parse_semantic_models(
                {
                    "profiles": ["embedded-security"],
                    "sources": [
                        {"function": "mailbox_receive", "outputs": ["out:1"]}
                    ],
                }
            )

    def test_unknown_and_duplicate_profiles_fail_closed(self):
        for raw in (
            {"profiles": ["not-a-profile"]},
            {"profiles": ["embedded-security", "embedded-security"]},
            {"profiles": "embedded-security"},
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_semantic_models(raw)

    def test_load_config_enables_profile_and_platform_overlay(self):
        content = """
schema_version = 1

[semantic_models]
profiles = ["embedded-security"]

[[semantic_models.sources]]
function = "hal_mailbox_read"
outputs = ["out:0"]

[[semantic_models.sinks]]
function = "hal_flash_write"
requirements = { "arg:0" = ["bounds_checked", "authorized"] }
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, ".cgull.toml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            cfg = load_config(config_path=path)

        self.assertIsNone(cfg.error)
        self.assertIn("mailbox_receive", cfg.semantic_models.sources)
        self.assertIn("hal_mailbox_read", cfg.semantic_models.sources)
        self.assertIn("hal_flash_write", cfg.semantic_models.sinks)


if __name__ == "__main__":
    unittest.main()
