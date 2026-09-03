"""Regression tests for declarative call-effect models."""

import unittest

from cgull.analysis_session import AnalysisSession
from cgull.call_effects import ReturnEffect
from cgull.cfg.model import CFGCall
from cgull.semantic_models import SemanticModelConfigError, parse_semantic_models


class _EmptyAstContext:
    functions = ()
    has_pycparser = False
    pycparser_ast = None


class TestCallEffectModels(unittest.TestCase):
    def test_standard_memory_apis_are_seeded_declaratively(self):
        registry = parse_semantic_models({})

        malloc = registry.call_effects.for_function("malloc")
        free = registry.call_effects.for_function("free")
        realloc = registry.call_effects.for_function("realloc")

        self.assertEqual(malloc.return_effect, ReturnEffect.ALLOCATION)
        self.assertEqual(free.deallocates, frozenset({0}))
        self.assertEqual(realloc.return_effect, ReturnEffect.ALLOCATION)
        self.assertEqual(realloc.deallocates, frozenset({0}))

    def test_effect_only_io_call_keeps_security_dataflow_fallback(self):
        registry = parse_semantic_models({})
        call = CFGCall(
            direct_callee="read",
            callee_expression="read",
            actual_arguments=("fd", "&buffer", "size"),
            result_target="count",
        )

        model = registry.for_call(call)
        self.assertIsNotNone(model.effect)
        self.assertEqual(model.effect.output_parameters, frozenset({1}))
        self.assertFalse(model.is_modeled)

    def test_project_model_overrides_builtin_by_function_name(self):
        registry = parse_semantic_models(
            {
                "effects": [
                    {
                        "function": "malloc",
                        "returns": "none",
                        "outputs": [0],
                    }
                ]
            }
        )
        malloc = registry.call_effects.for_function("malloc")
        self.assertEqual(malloc.return_effect, ReturnEffect.NONE)
        self.assertEqual(malloc.output_parameters, frozenset({0}))

    def test_project_wrapper_changes_summary_results_without_rule_code(self):
        default_session = AnalysisSession(_EmptyAstContext())
        self.assertNotIn("pool_alloc", default_session.function_summaries)

        registry = parse_semantic_models(
            {
                "effects": [
                    {"function": "pool_alloc", "returns": "allocation"},
                    {"function": "pool_free", "deallocates": [0]},
                ]
            }
        )
        modeled_session = AnalysisSession(_EmptyAstContext(), semantic_models=registry)

        self.assertTrue(modeled_session.function_summaries["pool_alloc"].returns_allocation)
        self.assertEqual(modeled_session.function_summaries["pool_free"].freed_params, {0})

    def test_rejects_malformed_and_contradictory_effects(self):
        invalid = [
            {"effects": [{"function": "bad-name", "returns": "allocation"}]},
            {"effects": [{"function": "f", "outputs": [-1]}]},
            {"effects": [{"function": "f", "format_argument": -1}]},
            {"effects": [{"function": "f", "size_relationships": [[0]]}]},
            {"effects": [{"function": "f", "deallocates": [0], "outputs": [0]}]},
            {"effects": [{"function": "f", "deallocates": [0], "sanitizes": [0]}]},
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(SemanticModelConfigError):
                    parse_semantic_models(raw)

    def test_effect_kinds_cover_format_output_size_and_sanitizer_semantics(self):
        registry = parse_semantic_models(
            {
                "effects": [
                    {
                        "function": "checked_copy",
                        "outputs": [0],
                        "format_argument": 2,
                        "size_relationships": [[0, 1]],
                        "sanitizes": [3],
                    }
                ]
            }
        )
        effect = registry.call_effects.for_function("checked_copy")
        self.assertEqual(effect.output_parameters, frozenset({0}))
        self.assertEqual(effect.format_argument, 2)
        self.assertEqual(effect.size_relationships, ((0, 1),))
        self.assertEqual(effect.sanitizes, frozenset({3}))


if __name__ == "__main__":
    unittest.main()
