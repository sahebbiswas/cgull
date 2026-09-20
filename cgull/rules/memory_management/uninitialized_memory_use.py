"""
Memory Management Rule Submodule.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from ..base import BaseRule
from ..banned_functions import BannedFunctionsRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext, CFunction, get_type_byte_size, is_unsigned_type
from ...utils import extract_call_args, split_call_args, extract_balanced_parens
from ...cfg import StructuredCFG, CFGEvent, build_cfg, find_function_def, Nullness, Initialization, Allocation, analyze_function_summaries, FunctionSummary
from .helpers import (
    _brace_depths,
    _source_snippet,
    _ast_cfg_for_function,
    _find_unsafe_allocation_use,
    _find_unsafe_param_deref,
    _find_uaf_uses,
    _find_memory_leak_exits,
)

logger = logging.getLogger(__name__)


class UninitializedMemoryUseRule(BaseRule):
    rule_id = "CGULL-023"
    name = "Uninitialized Memory Use"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Prevent reading from local memory locations / variables before they are explicitly initialized."
    implementation_method = "AST parsing to track variable assignment before read"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-457 / CWE-908"
    remediation_suggestion = "Always initialize scalar variables (e.g. int x = 0;) and buffers (char buf[128] = {0};) at declaration."
    sample_vulnerable_code = "int status;\nif (flag) status = 1;\nreturn status; // status uninitialized if flag is false"
    sample_remediated_code = "int status = 0;\nif (flag) status = 1;\nreturn status;"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = self.get_analysis_session(ast_ctx).function_summaries
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)
            if cfg is None:
                # Without a CFG we cannot prove a use-before-init; do not
                # fall back to declaration-without-initializer heuristics.
                continue

            uninit_vars = [
                v_name
                for v_name, var in fn.variables.items()
                if isinstance(v_name, str)
                and not var.has_initializer
                and not var.is_volatile
            ]
            if not uninit_vars:
                continue

            reported = set()
            for node in cfg.nodes.values():
                for v_name in uninit_vars:
                    if v_name in reported:
                        continue
                    # A definition on this node is not a use-before-init, even
                    # when array-to-pointer decay also appears in reads
                    # (sprintf/memset destinations, &var out-params).
                    if v_name in node.writes:
                        continue
                    if v_name not in node.reads:
                        continue
                    init_state = cfg.query_initialization(v_name, node.node_id)
                    if init_state not in (
                        Initialization.UNINITIALIZED,
                        Initialization.MAYBE_INITIALIZED,
                    ):
                        continue

                    use_line = node.line_number or fn.variables[v_name].declaration_line
                    snippet = _source_snippet(ast_ctx, use_line, f"{v_name}")
                    decl_line = fn.variables[v_name].declaration_line
                    if init_state == Initialization.MAYBE_INITIALIZED:
                        message = (
                            f"Local variable '{v_name}' may be read before it is "
                            f"definitely assigned (declared at line {decl_line})."
                        )
                    else:
                        message = (
                            f"Local variable '{v_name}' is read before it is "
                            f"assigned (declared at line {decl_line})."
                        )
                    issues.append(
                        self.create_issue(
                            file_path=file_path,
                            line_number=use_line,
                            code_snippet=snippet,
                            message=message,
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SAFE_FIX,
                            auto_fix_replacement=None,
                        )
                    )
                    reported.add(v_name)
        return issues
