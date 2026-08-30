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
class ReturnStackVariableRule(BaseRule):
    rule_id = "CGULL-038"
    name = "Return Stack Variable"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect return statements that expose the address of an automatic-storage local variable or function parameter after the function returns."
    implementation_method = "AST traversal of return expressions and lexical local-variable scopes"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-562"
    remediation_suggestion = "Do not return the address of an automatic-storage local variable or parameter; return caller-owned storage, a static object when appropriate, or dynamically allocated storage instead."
    sample_vulnerable_code = "int *get_value(void) {\n    int value = 42;\n    return &value;\n}"
    sample_remediated_code = "int *get_value(void) {\n    int *value = malloc(sizeof(*value));\n    if (!value) return NULL;\n    *value = 42;\n    return value;\n}"
    analysis_engine = AnalysisEngine.AST

    @staticmethod
    def _returned_local_names(expr, automatic_names: Set[str], array_names: Set[str]) -> Set[str]:
        """Return automatic locals whose storage can escape through `expr`.

        A direct ID is unsafe when it names an automatic array because array-to-
        pointer decay returns its first element's address. An explicit address-of
        expression is unsafe for any automatic object. Casts and pointer arithmetic
        around an address expression are also handled by recursively inspecting
        their operands. Plain uses of local scalar/pointer variables are ignored.
        """
        from pycparser import c_ast

        found: Set[str] = set()

        def root_lvalue(node):
            while isinstance(node, (c_ast.ArrayRef, c_ast.StructRef)):
                node = node.name
            return node

        def visit(node, address_context: bool = False):
            if node is None:
                return
            if isinstance(node, c_ast.ID):
                if node.name in automatic_names and (address_context or node.name in array_names):
                    found.add(node.name)
                return
            if isinstance(node, c_ast.UnaryOp):
                if node.op == '&':
                    operand = node.expr
                    is_safe = False
                    needs_array = False

                    curr = operand
                    while isinstance(curr, (c_ast.ArrayRef, c_ast.StructRef)):
                        if isinstance(curr, c_ast.StructRef):
                            if curr.type == '->':
                                is_safe = True
                                break
                        elif isinstance(curr, c_ast.ArrayRef):
                            needs_array = True
                        curr = curr.name

                    if not is_safe and isinstance(curr, c_ast.ID):
                        if needs_array:
                            if curr.name in array_names:
                                found.add(curr.name)
                        else:
                            if curr.name in automatic_names:
                                found.add(curr.name)
                    elif not is_safe:
                        visit(operand, True)
                    return
                visit(node.expr, address_context)
                return
            if isinstance(node, c_ast.Cast):
                visit(node.expr, address_context)
                return
            if isinstance(node, c_ast.FuncCall):
                visit(node.name, False)
                return
            if isinstance(node, c_ast.ArrayRef):
                # Array-to-pointer decay only applies when the array itself is the
                # returned expression; an indexed scalar is not an escaped address.
                visit(node.name, address_context and False)
                visit(node.subscript, False)
                return
            if isinstance(node, c_ast.StructRef):
                visit(node.name, address_context)
                visit(node.field, False)
                return
            for _, child in node.children():
                visit(child, address_context)

        visit(expr)
        return found

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []

        from pycparser import c_ast

        issues: List[Issue] = []
        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None or funcdef.body is None:
                continue

            class ReturnVisitor(c_ast.NodeVisitor):
                def __init__(self, outer: "ReturnStackVariableRule"):
                    self.outer = outer
                    self.scope_stack = [
                        {p.name: {'is_static': False, 'is_array': False} for p in fn.parameters if p.name}
                    ]
                    self.returns: List[Tuple[c_ast.Return, Set[str]]] = []

                def _get_active_names(self):
                    active_automatic = set()
                    active_arrays = set()
                    for scope in self.scope_stack:
                        for name, info in scope.items():
                            if info['is_static']:
                                active_automatic.discard(name)
                                active_arrays.discard(name)
                            else:
                                active_automatic.add(name)
                                if info['is_array']:
                                    active_arrays.add(name)
                                else:
                                    active_arrays.discard(name)
                    return active_automatic, active_arrays

                def visit_Compound(self, node):
                    self.scope_stack.append({})
                    for item in node.block_items or []:
                        self.visit(item)
                    self.scope_stack.pop()

                def visit_Decl(self, node):
                    if node.name and type(node.type).__name__ != "FuncDecl":
                        is_static = "static" in (node.storage or [])
                        is_array = isinstance(node.type, c_ast.ArrayDecl)
                        self.scope_stack[-1][node.name] = {'is_static': is_static, 'is_array': is_array}
                    # Initializers can contain nested expressions, but declarations
                    # themselves cannot contain return statements in standard C.
                    if node.init is not None:
                        self.visit(node.init)

                def visit_Return(self, node):
                    active_automatic, active_arrays = self._get_active_names()
                    names = self.outer._returned_local_names(
                        node.expr, active_automatic, active_arrays
                    )
                    if names:
                        self.returns.append((node, names))
                    # Do not descend into the return expression a second time.

            visitor = ReturnVisitor(self)
            visitor.visit(funcdef.body)
            line_offset = (
                funcdef.decl.coord.line - fn.start_line
                if funcdef.decl.coord is not None
                else 0
            )

            for node, names in visitor.returns:
                line_no = (node.coord.line - line_offset) if node.coord else fn.start_line
                snippet = _source_snippet(ast_ctx, line_no, "return;")
                names_text = ", ".join(sorted(names))
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    message=(
                        f"Return statement exposes the address of automatic-storage "
                        f"variable(s) '{names_text}', which become invalid when function "
                        "'{0}' returns.".format(fn.name)
                    ),
                    column_number=getattr(node.coord, "column", 1) if node.coord else 1,
                    engine="AST",
                    fix_type=FixType.MANUAL_REVIEW,
                ))

        return issues
