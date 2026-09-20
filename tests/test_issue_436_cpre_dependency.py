"""Smoke coverage for the explicit versioned CPRE dependency (#436)."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from cgull.preprocessor import cpre_api


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestIssue436CpreDependency(unittest.TestCase):
    def test_packaging_declares_versioned_cpre_dependency(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        requirements = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")

        self.assertIn("cpre>=0.11.0,<0.12", pyproject)
        self.assertRegex(
            pyproject,
            re.compile(r'^dependencies\s*=\s*\[[^\]]*cpre>=0\.11\.0,<0\.12', re.M | re.S),
        )
        self.assertIn("cpre>=0.11.0,<0.12", requirements)
        self.assertEqual(
            cpre_api.SUPPORTED_CPRE_VERSION_SPEC,
            ">=0.11.0,<0.12",
        )

    def test_installed_cpre_satisfies_supported_range(self):
        version = cpre_api.assert_supported_cpre()
        self.assertEqual(version, cpre_api.installed_cpre_version())
        self.assertGreaterEqual(
            cpre_api._parse_version(version),
            cpre_api.MIN_CPRE_VERSION,
        )
        self.assertLess(cpre_api._parse_version(version), (0, 12))

    def test_public_expression_and_proof_surface(self):
        expr = cpre_api.conjunction(
            cpre_api.Variable("FEATURE"),
            cpre_api.DefinedVariable("FEATURE"),
        )
        payload = cpre_api.expression_to_dict(expr)
        restored = cpre_api.expression_from_dict(payload)
        self.assertEqual(
            cpre_api.format_expression(restored),
            cpre_api.format_expression(expr),
        )

        sat = cpre_api.satisfiable(expr)
        self.assertTrue(sat.complete)
        self.assertTrue(sat.satisfiable)

        unsat = cpre_api.satisfiable(
            cpre_api.conjunction(cpre_api.TRUE, cpre_api.FALSE)
        )
        self.assertTrue(unsat.complete)
        self.assertFalse(unsat.satisfiable)

    def test_public_conditional_structure_surface(self):
        source = "#if FEATURE\nint x;\n#else\nint y;\n#endif\n"
        tree = cpre_api.parse_conditionals(source)
        self.assertIsInstance(tree, cpre_api.ConditionalStructureTree)
        self.assertEqual(len(tree.blocks), 1)
        self.assertEqual(tree.blocks[0].branches[0].directive.kind, "if")
        self.assertEqual(tree.blocks[0].branches[1].directive.kind, "else")
        self.assertFalse(tree.diagnostics)

    def test_accepted_adapter_name_maps_are_stable(self):
        self.assertEqual(
            cpre_api.STRUCTURE_DIAGNOSTIC_CODE_MAP["invalid_macro"],
            "malformed_macro_directive",
        )
        self.assertEqual(
            cpre_api.WITNESS_ATOM_KIND_MAP["defined"],
            "macro_defined",
        )
        # cpre enum values must remain the migration target names.
        self.assertEqual(
            cpre_api.StructureDiagnosticCode.MALFORMED_MACRO_DIRECTIVE.value,
            "malformed_macro_directive",
        )
        self.assertEqual(
            cpre_api.WitnessAtomKind.MACRO_DEFINED.value,
            "macro_defined",
        )

    def test_unsupported_version_fails_clearly(self):
        with self.assertRaisesRegex(RuntimeError, r"outside the supported range"):
            cpre_api.assert_supported_cpre("0.10.16")
        with self.assertRaisesRegex(RuntimeError, r"outside the supported range"):
            cpre_api.assert_supported_cpre("0.12.0")


if __name__ == "__main__":
    unittest.main()
