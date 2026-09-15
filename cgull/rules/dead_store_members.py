"""Direct aggregate-subobject support for CGULL-042.

This layer consumes the object-aware expression effects without changing the
CFG's historic scalar read/write contract. Only direct ``.`` member stores on
eligible local bindings participate; pointer-member and otherwise indirect
stores stay conservative.
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from ..cfg import analyze_function_summaries, build_cfg, find_function_def
from ..cfg.expression_effects import StorageEffect, ordered_storage_effects
from ..models import FixType
from .dead_stores import DeadStoresRule as _BaseDeadStoresRule


MemberTarget = Tuple[str, Tuple[str, ...]]


def _raw_variables(fn):
    variables = getattr(fn, "variables", {})
    if isinstance(variables, dict):
        return list(variables.values())
    return list(variables)


def _eligible_member_roots(fn) -> Set[str]:
    """Return unambiguous local bindings safe for member-level reasoning."""
    param_names = {p.name for p in getattr(fn, "parameters", ()) if p.name}
    by_name = defaultdict(list)
    for variable in _raw_variables(fn):
        name = getattr(variable, "name", None)
        if not name or name in param_names or name.startswith("__"):
            continue
        if getattr(variable, "is_volatile", False) or getattr(variable, "address_taken", False):
            continue
        by_name[name].append(variable)

    # The CFG scalar contract is name-based. Avoid inventing binding precision
    # for same-named shadowed locals until the CFG itself can carry that identity.
    return {name for name, variables in by_name.items() if len(variables) == 1}


def _event_expression(node):
    ast_node = getattr(node, "_ast_node", None)
    if ast_node is None:
        return None
    if node.kind in {"if_cond", "while_cond", "do_cond", "for_cond", "switch_cond"}:
        return getattr(ast_node, "cond", None)
    return ast_node


def _effects_for_node(node) -> Tuple[StorageEffect, ...]:
    return ordered_storage_effects(_event_expression(node))


def _is_prefix(prefix: Tuple[str, ...], path: Tuple[str, ...]) -> bool:
    return len(prefix) <= len(path) and path[: len(prefix)] == prefix


def _read_uses_target(effect: StorageEffect, target: MemberTarget) -> bool:
    root, member_path = target
    if effect.action != "read" or effect.root != root:
        return False

    # Whole-object reads consume every stored subobject. Parent/child member
    # reads also overlap semantically (reading s.inner consumes a write to
    # s.inner.field, and reading s.inner.field consumes a write to s.inner).
    return _is_prefix(effect.member_path, member_path) or _is_prefix(
        member_path, effect.member_path
    )


def _write_overwrites_target(effect: StorageEffect, target: MemberTarget) -> bool:
    root, member_path = target
    if effect.action != "write" or effect.root != root:
        return False

    # A whole-object write replaces every member. For subobjects, only a direct
    # write to the same member or an ancestor aggregate fully overwrites the
    # earlier value. A descendant write leaves the rest of the parent value live.
    if not effect.member_path:
        return True
    if not effect.is_direct_subobject:
        return False
    return _is_prefix(effect.member_path, member_path)


def _transition(effects: Tuple[StorageEffect, ...], target: MemberTarget) -> str:
    """Return the first relevant transition: ``read``, ``overwrite``, or ``none``."""
    for effect in effects:
        if _read_uses_target(effect, target):
            return "read"
        if _write_overwrites_target(effect, target):
            return "overwrite"
    return "none"


def _write_is_live(cfg, node_id: int, effect_index: int, target: MemberTarget) -> bool:
    source_effects = _effects_for_node(cfg.nodes[node_id])
    source_transition = _transition(source_effects[effect_index + 1 :], target)
    if source_transition == "read":
        return True
    if source_transition == "overwrite":
        return False

    visited = set()
    worklist = list(cfg.nodes[node_id].successors)
    while worklist:
        current_id = worklist.pop()
        if current_id in visited:
            continue
        visited.add(current_id)

        current = cfg.nodes[current_id]
        transition = _transition(_effects_for_node(current), target)
        if transition == "read":
            return True
        if transition == "overwrite":
            continue
        for successor in current.successors:
            if successor not in visited:
                worklist.append(successor)

    return False


def _member_dead_store_issues(rule, file_path, ast_ctx):
    issues = []
    summaries = (
        analyze_function_summaries(ast_ctx)
        if getattr(ast_ctx, "functions", None)
        else None
    )
    reported: Set[Tuple[int, str, Tuple[str, ...]]] = set()

    for fn in getattr(ast_ctx, "functions", ()):
        eligible_roots = _eligible_member_roots(fn)
        if not eligible_roots:
            continue

        funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
        if funcdef is None:
            continue
        cfg = build_cfg(
            funcdef,
            summaries=summaries,
            line_map=getattr(ast_ctx, "line_map", None),
        )
        if not cfg.nodes:
            continue

        for node_id in sorted(cfg.nodes):
            node = cfg.nodes[node_id]
            effects = _effects_for_node(node)
            for effect_index, effect in enumerate(effects):
                if (
                    effect.action != "write"
                    or not effect.is_direct_subobject
                    or effect.root not in eligible_roots
                ):
                    continue

                target = (effect.root, effect.member_path)
                if _write_is_live(cfg, node_id, effect_index, target):
                    continue

                line_no = int(getattr(node, "line_number", 0) or 0)
                if line_no <= 0:
                    continue
                report_key = (line_no, effect.root, effect.member_path)
                if report_key in reported:
                    continue
                reported.add(report_key)

                member_name = effect.root + "." + ".".join(effect.member_path)
                snippet = (
                    ast_ctx.source_lines[line_no - 1].strip()
                    if 1 <= line_no <= len(ast_ctx.source_lines)
                    else f"{member_name} = ...;"
                )
                location = getattr(node, "source_location", None)
                column = int(getattr(location, "column_number", 0) or 0) or 1
                issues.append(
                    rule.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=(
                            f"Value assigned to local aggregate member '{member_name}' "
                            f"in '{fn.name}' is never read before reassignment or scope "
                            "exit (dead store, CWE-563)."
                        ),
                        column_number=column,
                        engine="AST",
                        fix_type=FixType.MANUAL_REVIEW,
                    )
                )

    return issues


class DeadStoresRule(_BaseDeadStoresRule):
    """CGULL-042 with direct aggregate-subobject dead-store precision."""

    def scan_ast(self, file_path, ast_ctx):
        issues = super().scan_ast(file_path, ast_ctx)
        if not (
            getattr(ast_ctx, "has_pycparser", False)
            and ast_ctx.pycparser_ast is not None
        ):
            return issues
        issues.extend(_member_dead_store_issues(self, file_path, ast_ctx))
        return issues


__all__ = ["DeadStoresRule"]
