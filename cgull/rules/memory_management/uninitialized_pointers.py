"""
Memory Management Rule Submodule.
"""

import re
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
class UninitializedPointersRule(BaseRule):
    rule_id = "CGULL-021"
    name = "Uninitialized Pointers"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure pointer variables are explicitly initialized to NULL or a valid address upon declaration."
    implementation_method = "AST parsing to check pointer initialization"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-457"
    remediation_suggestion = "Initialize all pointer variables explicitly at declaration: type *ptr = NULL;"
    sample_vulnerable_code = "char *secret_key;\nif (condition) {\n    secret_key = fetch_key();\n}\nuse_key(secret_key); // May hold wild stack garbage"
    sample_remediated_code = "char *secret_key = NULL;\nif (condition) {\n    secret_key = fetch_key();\n}\nif (secret_key) use_key(secret_key);"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = self.get_analysis_session(ast_ctx).function_summaries
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)
            if cfg is not None:
                uninit_ptrs = [v_name for v_name, var in fn.variables.items() if var.is_pointer and not var.has_initializer]
                if not uninit_ptrs:
                    continue
                reported = set()
                for node in cfg.nodes.values():
                    for ptr in uninit_ptrs:
                        if ptr in reported:
                            continue
                        if ptr in node.writes:
                            continue
                        if ptr in node.reads or ptr in node.derefs:
                            if cfg.query_initialization(ptr, node.node_id) in (Initialization.UNINITIALIZED, Initialization.MAYBE_INITIALIZED):
                                decl_line = fn.variables[ptr].declaration_line
                                snippet = _source_snippet(ast_ctx, decl_line, f"char *{ptr};")
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=decl_line,
                                    code_snippet=snippet,
                                    message=f"Pointer variable '{ptr}' is declared uninitialized (wild pointer risk). Initialize to NULL.",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SAFE_FIX,
                                    auto_fix_replacement=snippet.replace(f"{ptr};", f"{ptr} = NULL;")
                                ))
                                reported.add(ptr)
                continue
        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Match pointer declaration without = : e.g. int *p; or char* ptr, *buf;
        m = re.search(r'^[ \t]*(?:static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*+\s*|\w+\s*\*+)(\w+)\s*;', line_content)
        if m:
            v_name = m.group(1)
            if v_name not in ('return', 'break', 'continue'):
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Pointer variable '{v_name}' is declared uninitialized (wild pointer risk). Initialize to NULL.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SAFE_FIX,
                    auto_fix_replacement=line_content.replace(f"{v_name};", f"{v_name} = NULL;")
                ))
        return issues
