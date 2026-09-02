"""Tests for embedded trust-boundary semantic models."""

import os
import tempfile
import unittest

from cgull.cfg.model import CFGCall
from cgull.config import CGullConfig, load_config
from cgull.semantic_models import (
    SemanticLocation,
    SemanticLocationKind,
    SuccessConditionKind,
    TUAnalysisSession,
    ValidationProperty,
    parse_semantic_models,
)


class TestSemanticModelParsing(unittest.TestCase):
    def test_parse_source_validator_and_sink_models(self):
        registry = parse_semantic_models(
            {
                "sources": [
                    {"function": "uart_read", "outputs": ["return", "out:1"]},
                ],
                "validators": [
                    {
                        "function": "verify_signature",
                        "target": "arg:0",
                        "property": "signature_verified",
                        "success": "return_zero",
                    },
                    {
                        "function": "check_bounds",
                        "target": "arg:1",
                        "property": "bounds_checked",
                        "success": {"return_equals": 1},
                    },
                ],
                "sinks": [
                    {
                        "function": "flash_write",
                        "requirements": {
                            "arg:0": ["authorized"],
                            "arg:1": ["bounds_checked", "authenticated"],
                        },
                    }
                ],
            }
        )

        source = registry.sources["uart_read"]
        self.assertEqual(source.outputs[0], SemanticLocation(SemanticLocationKind.RETURN))
        self.assertEqual(
            source.outputs[1],
            SemanticLocation(SemanticLocationKind.OUTPUT_ARGUMENT, 1),
        )

        signature = registry.validators["verify_signature"]
        self.assertEqual(signature.property, ValidationProperty.SIGNATURE_VERIFIED)
        self.assertEqual(signature.success.kind, SuccessConditionKind.RETURN_ZERO)

        bounds = registry.validators["check_bounds"]
        self.assertEqual(bounds.property, ValidationProperty.BOUNDS_CHECKED)
        self.assertEqual(bounds.success.kind, SuccessConditionKind.RETURN_EQUALS)
        self.assertEqual(bounds.success.value, 1)

        sink = registry.sinks["flash_write"]
        self.assertEqual(len(sink.requirements), 2)
        self.assertIn(
            ValidationProperty.BOUNDS_CHECKED,
            sink.requirements[1].properties,
        )
        self.assertIn(
            ValidationProperty.AUTHENTICATED,
            sink.requirements[1].properties,
        )

    def test_validator_property_is_typed_and_not_generic(self):
        registry = parse_semantic_models(
            {
                "validators": [
                    {
                        "function": "verify_signature",
                        "target": "arg:0",
                        "property": "signature_verified",
                        "success": "return_zero",
                    }
                ]
            }
        )
        model = registry.validators["verify_signature"]
        self.assertEqual(model.property, ValidationProperty.SIGNATURE_VERIFIED)
        self.assertNotEqual(model.property, ValidationProperty.BOUNDS_CHECKED)

    def test_invalid_model_definitions_fail_clearly(self):
        invalid = [
            {"sources": [{"function": "uart-read", "outputs": ["return"]}]},
            {"sources": [{"function": "uart_read", "outputs": []}]},
            {
                "validators": [
                    {
                        "function": "validate",
                        "target": "arg:x",
                        "property": "bounds_checked",
                        "success": "return_zero",
                    }
                ]
            },
            {
                "validators": [
                    {
                        "function": "validate",
                        "target": "arg:0",
                        "property": "validated",
                        "success": "return_zero",
                    }
                ]
            },
            {
                "sinks": [
                    {"function": "flash_write", "requirements": {"arg:0": []}}
                ]
            },
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_semantic_models(raw)

    def test_duplicate_models_fail(self):
        with self.assertRaises(ValueError):
            parse_semantic_models(
                {
                    "sources": [
                        {"function": "uart_read", "outputs": ["return"]},
                        {"function": "uart_read", "outputs": ["out:0"]},
                    ]
                }
            )

    def test_duplicate_normalized_source_outputs_fail(self):
        cases = [
            ["return", "return"],
            ["out:0", "out:00"],
        ]
        for outputs in cases:
            with self.subTest(outputs=outputs):
                with self.assertRaisesRegex(ValueError, "duplicate output location"):
                    parse_semantic_models(
                        {"sources": [{"function": "uart_read", "outputs": outputs}]}
                    )

    def test_duplicate_normalized_sink_requirements_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate requirement for location"):
            parse_semantic_models(
                {
                    "sinks": [
                        {
                            "function": "flash_write",
                            "requirements": {
                                "arg:0": ["authorized"],
                                "arg:00": ["bounds_checked"],
                            },
                        }
                    ]
                }
            )


class TestSemanticModelLookup(unittest.TestCase):
    def setUp(self):
        self.registry = parse_semantic_models(
            {
                "sources": [
                    {"function": "mailbox_read", "outputs": ["out:0"]},
                ],
                "validators": [
                    {
                        "function": "authorize_command",
                        "target": "arg:0",
                        "property": "authorized",
                        "success": "return_nonzero",
                    }
                ],
                "sinks": [
                    {
                        "function": "debug_enable",
                        "requirements": {"arg:0": ["authorized"]},
                    }
                ],
            }
        )

    def test_direct_call_query(self):
        call = CFGCall(
            direct_callee="debug_enable",
            callee_expression="debug_enable",
            actual_arguments=("command",),
        )
        model = self.registry.for_call(call)
        self.assertTrue(model.is_modeled)
        self.assertIsNotNone(model.sink)
        self.assertIsNone(model.source)

    def test_unmodeled_call_stays_unknown(self):
        call = CFGCall(
            direct_callee="vendor_unknown",
            callee_expression="vendor_unknown",
            actual_arguments=("external",),
            result_target="value",
        )
        model = self.registry.for_call(call)
        self.assertFalse(model.is_modeled)
        self.assertIsNone(model.source)
        self.assertIsNone(model.validator)
        self.assertIsNone(model.sink)

    def test_indirect_call_never_uses_name_as_trust_model(self):
        call = CFGCall(
            direct_callee="mailbox_read",
            callee_expression="reader_fn",
            actual_arguments=("&value",),
            is_indirect=True,
        )
        self.assertFalse(self.registry.for_call(call).is_modeled)

    def test_tu_session_uses_configured_registry(self):
        cfg = CGullConfig(semantic_models=self.registry)
        ast_context = object()
        session = TUAnalysisSession.from_config(ast_context, cfg)
        call = CFGCall(
            direct_callee="authorize_command",
            callee_expression="authorize_command",
            actual_arguments=("command",),
        )
        model = session.model_for_call(call)
        self.assertEqual(model.validator.property, ValidationProperty.AUTHORIZED)


class TestSemanticModelConfigIntegration(unittest.TestCase):
    def test_load_config_parses_models(self):
        content = """
schema_version = 1

[[semantic_models.sources]]
function = "spi_receive"
outputs = ["out:0"]

[[semantic_models.validators]]
function = "check_version"
target = "arg:0"
property = "version_checked"
success = "return_zero"

[[semantic_models.sinks]]
function = "install_update"
requirements = { "arg:0" = ["signature_verified", "version_checked"] }
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, ".cgull.toml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            cfg = load_config(config_path=path)

        self.assertIsNone(cfg.error)
        self.assertIn("spi_receive", cfg.semantic_models.sources)
        self.assertEqual(
            cfg.semantic_models.validators["check_version"].property,
            ValidationProperty.VERSION_CHECKED,
        )
        self.assertIn("install_update", cfg.semantic_models.sinks)

    def test_invalid_security_model_is_config_error(self):
        content = """
[[semantic_models.validators]]
function = "verify_signature"
target = "arg:0"
property = "trusted"
success = "return_zero"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, ".cgull.toml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            cfg = load_config(config_path=path)

        self.assertIsNotNone(cfg.error)
        self.assertIn("Invalid [semantic_models] configuration", cfg.error)


if __name__ == "__main__":
    unittest.main()
