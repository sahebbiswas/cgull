"""Structured CFG construction.

AST inspection and event-fact extraction live in :mod:`cgull.cfg.ast_events`;
this module owns only structured statement-to-graph construction and the
historic ``build_cfg`` entry point.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from ..ast_analyzer import _format_pycparser_expr
from .ast_events import (
    _call_events,
    _deref_vars,
    _deref_vars_with_lines,
    _event_payload,
    _find_ternary_op,
    _find_value_producing_call,
    _function_pointer_names,
    _ids,
    _is_nullish,
    _replace_ast_node,
    _simple_null_facts,
)
from .dataflow import StructuredCFG
from .model import FunctionSummary


def build_cfg(
    funcdef,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    summaries: Optional[Dict[str, FunctionSummary]] = None,
    line_map: Optional[Dict[int, Any]] = None,
) -> StructuredCFG:
    """Build a structured CFG rooted at a pycparser FuncDef body."""
    from pycparser import c_ast

    cfg = StructuredCFG()
    function_pointers = _function_pointer_names(funcdef)
    labels_map: Dict[str, int] = {}
    pending_gotos: List[Tuple[int, str]] = []

    def make_event(stmt) -> int:
        (
            kind,
            reads,
            writes,
            null_writes,
            maybe_null_writes,
            freed,
            allocated,
            derefs,
            deref_lines,
            asserted,
            alias_writes,
            realloc_inputs,
            realloc_bindings,
        ) = _event_payload(
            stmt,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
            summaries=summaries,
            line_map=line_map,
        )
        node_kind = "allocation" if allocated else "free" if freed else kind.lower()
        if kind == "Return":
            expr_str = (
                _format_pycparser_expr(stmt.expr)
                if getattr(stmt, "expr", None) is not None
                else ""
            )
        else:
            expr_str = _format_pycparser_expr(stmt)
        return cfg.new_node(
            node_kind,
            stmt,
            line_map=line_map,
            expr_str=expr_str,
            reads=reads,
            writes=writes,
            null_writes=null_writes,
            maybe_null_writes=maybe_null_writes,
            freed=freed,
            allocated=allocated,
            derefs=derefs,
            deref_lines=deref_lines,
            asserted=asserted,
            alias_writes=alias_writes,
            realloc_inputs=realloc_inputs,
            realloc_bindings=realloc_bindings,
            calls=_call_events(stmt, line_map, function_pointers),
        )

    def build_compound(items, next_entry, break_target, continue_target):
        current = next_entry
        for item in reversed(items or []):
            current = build_stmt(item, current, break_target, continue_target)
        return current

    def build_case(case_node, next_entry, break_target, continue_target):
        return build_compound(
            case_node.stmts, next_entry, break_target, continue_target
        )

    def build_stmt(stmt, next_entry, break_target, continue_target):
        if stmt is None:
            return next_entry
        kind = type(stmt).__name__

        if kind == "If":
            ternary = _find_ternary_op(stmt.cond)
            if ternary is not None:
                coord = getattr(stmt, "coord", None)
                cond_t = _replace_ast_node(stmt.cond, ternary, ternary.iftrue)
                cond_f = _replace_ast_node(stmt.cond, ternary, ternary.iffalse)
                if_t = c_ast.If(
                    cond=cond_t,
                    iftrue=stmt.iftrue,
                    iffalse=stmt.iffalse,
                    coord=coord,
                )
                if_f = c_ast.If(
                    cond=cond_f,
                    iftrue=stmt.iftrue,
                    iffalse=stmt.iffalse,
                    coord=coord,
                )
                outer_if = c_ast.If(
                    cond=ternary.cond,
                    iftrue=if_t,
                    iffalse=if_f,
                    coord=coord,
                )
                return build_stmt(
                    outer_if, next_entry, break_target, continue_target
                )
        elif kind not in {
            "Compound",
            "While",
            "DoWhile",
            "For",
            "Switch",
            "Label",
            "Goto",
            "Break",
            "Continue",
        }:
            ternary = _find_ternary_op(stmt)
            if ternary is not None:
                coord = getattr(stmt, "coord", None)
                stmt_t = _replace_ast_node(stmt, ternary, ternary.iftrue)
                stmt_f = _replace_ast_node(stmt, ternary, ternary.iffalse)
                if_stmt = c_ast.If(
                    cond=ternary.cond,
                    iftrue=stmt_t,
                    iffalse=stmt_f,
                    coord=coord,
                )
                return build_stmt(if_stmt, next_entry, break_target, continue_target)

        if kind == "Compound":
            return build_compound(
                stmt.block_items, next_entry, break_target, continue_target
            )

        if kind in {
            "Decl",
            "Assignment",
            "FuncCall",
            "Return",
            "UnaryOp",
            "BinaryOp",
            "ExprList",
            "Cast",
            "ArrayRef",
            "StructRef",
        }:
            node = make_event(stmt)
            is_exit_call = False
            if kind == "FuncCall":
                callee_name = _format_pycparser_expr(getattr(stmt, "name", None))
                if callee_name in {
                    "exit",
                    "_exit",
                    "_Exit",
                    "abort",
                    "quick_exit",
                    "fatal",
                    "panic",
                    "err",
                    "errx",
                }:
                    is_exit_call = True
            if kind != "Return" and not is_exit_call:
                cfg.connect(node, next_entry)
            return node

        if kind == "If":
            cond = cfg.new_node(
                "if_cond",
                stmt,
                line_map=line_map,
                expr_str=_format_pycparser_expr(stmt.cond),
                reads=_ids(stmt.cond),
                calls=_call_events(stmt.cond, line_map, function_pointers),
            )
            true_add, true_remove = _simple_null_facts(stmt.cond)
            false_add, false_remove = true_remove, true_add
            cfg.connect(
                cond,
                build_stmt(
                    stmt.iftrue, next_entry, break_target, continue_target
                ),
                add=true_add,
                remove={*true_remove},
            )
            if stmt.iffalse is not None:
                cfg.connect(
                    cond,
                    build_stmt(
                        stmt.iffalse,
                        next_entry,
                        break_target,
                        continue_target,
                    ),
                    add=false_add,
                    remove={*false_remove},
                )
            else:
                cfg.connect(
                    cond,
                    next_entry,
                    add=false_add,
                    remove={*false_remove},
                )
            return cond

        if kind in {"While", "DoWhile"}:
            if kind == "While":
                cond = cfg.new_node(
                    "while_cond",
                    stmt,
                    line_map=line_map,
                    expr_str=_format_pycparser_expr(stmt.cond),
                    reads=_ids(stmt.cond),
                    calls=_call_events(stmt.cond, line_map, function_pointers),
                )
                body = build_stmt(stmt.stmt, cond, next_entry, cond)
                true_add, true_remove = _simple_null_facts(stmt.cond)
                false_add, false_remove = true_remove, true_add
                cfg.connect(cond, body, add=true_add, remove=true_remove)
                cfg.connect(
                    cond, next_entry, add=false_add, remove=false_remove
                )
                return cond
            cond = cfg.new_node(
                "do_cond",
                stmt,
                line_map=line_map,
                expr_str=_format_pycparser_expr(stmt.cond),
                reads=_ids(stmt.cond),
                calls=_call_events(stmt.cond, line_map, function_pointers),
            )
            body = build_stmt(stmt.stmt, cond, next_entry, cond)
            true_add, true_remove = _simple_null_facts(stmt.cond)
            false_add, false_remove = true_remove, true_add
            cfg.connect(cond, body, add=true_add, remove=true_remove)
            cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
            return body

        if kind == "For":
            cond_expr = stmt.cond
            cond = cfg.new_node(
                "for_cond",
                stmt,
                line_map=line_map,
                expr_str=(
                    _format_pycparser_expr(cond_expr) if cond_expr else "1"
                ),
                reads=_ids(cond_expr) if cond_expr is not None else set(),
                calls=_call_events(cond_expr, line_map, function_pointers),
            )
            iter_node = None
            if stmt.next is not None:
                iter_node = make_event(stmt.next)
                cfg.connect(iter_node, cond)
            body = build_stmt(
                stmt.stmt, iter_node or cond, next_entry, iter_node or cond
            )
            true_add, true_remove = _simple_null_facts(cond_expr)
            false_add, false_remove = true_remove, true_add
            cfg.connect(cond, body, add=true_add, remove=true_remove)
            cfg.connect(cond, next_entry, add=false_add, remove=false_remove)
            if stmt.init is not None:
                init_node = make_event(stmt.init)
                cfg.connect(init_node, cond)
                return init_node
            return cond

        if kind == "Switch":
            switch_node = cfg.new_node(
                "switch_cond",
                stmt,
                line_map=line_map,
                expr_str=_format_pycparser_expr(stmt.cond),
                reads=_ids(stmt.cond),
                calls=_call_events(stmt.cond, line_map, function_pointers),
            )
            body = stmt.stmt
            cases = (
                list(getattr(body, "block_items", []) or [])
                if type(body).__name__ == "Compound"
                else []
            )
            case_entries = [None] * len(cases)
            fallthrough = next_entry
            for i in range(len(cases) - 1, -1, -1):
                case = cases[i]
                if type(case).__name__ not in {"Case", "Default"}:
                    continue
                case_entries[i] = build_case(
                    case, fallthrough, next_entry, continue_target
                )
                fallthrough = case_entries[i]
            for entry in case_entries:
                if entry is not None:
                    cfg.connect(switch_node, entry)
            if not any(type(c).__name__ == "Default" for c in cases):
                cfg.connect(switch_node, next_entry)
            return switch_node

        if kind == "Break":
            node = make_event(stmt)
            cfg.connect(node, break_target)
            return node

        if kind == "Continue":
            node = make_event(stmt)
            cfg.connect(node, continue_target)
            return node

        if kind == "Label":
            label_node = cfg.new_node(
                "label", stmt, line_map=line_map, expr_str=stmt.name
            )
            labels_map[stmt.name] = label_node
            inner_entry = build_stmt(
                stmt.stmt, next_entry, break_target, continue_target
            )
            cfg.connect(label_node, inner_entry)
            return label_node

        if kind == "Goto":
            goto_node = cfg.new_node(
                "goto",
                stmt,
                line_map=line_map,
                expr_str=f"goto {stmt.name}",
            )
            pending_gotos.append((goto_node, stmt.name))
            return goto_node

        node = make_event(stmt)
        cfg.connect(node, next_entry)
        return node

    cfg.entry = build_stmt(funcdef.body, None, None, None)

    for goto_node, label_name in pending_gotos:
        if label_name in labels_map:
            cfg.connect(goto_node, labels_map[label_name])

    cfg.build_basic_blocks()
    return cfg


def find_function_def(ast, name: str):
    for ext in getattr(ast, "ext", []) or []:
        if (
            type(ext).__name__ == "FuncDef"
            and getattr(ext.decl, "name", None) == name
        ):
            return ext
    return None


__all__ = ["build_cfg", "find_function_def"]
