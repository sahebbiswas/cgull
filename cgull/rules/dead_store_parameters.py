"""Binding-aware parameter support for CGULL-042 dead-store analysis."""

from dataclasses import dataclass
import re
from typing import Dict, Optional, Set, Tuple

from ..ast_analyzer import CVariable
from ..ast_analyzer.lexical import body_statements
from ..cfg.expression_effects import StorageEffect, ordered_storage_effects
from ..models import FixType
from ..utils import mask_string_and_char_literals
from .dead_store_initializers import (
    pure_declaration_coordinates,
    suppress_cfg_initializer,
)


@dataclass(frozen=True)
class _Binding:
    name: str
    kind: str
    serial: int
    origin_id: int
    is_volatile: bool = False


def has_tracked_parameters(fn) -> bool:
    """Return whether *fn* has named parameters that CGULL-042 can track."""
    return any(
        getattr(param, "name", None)
        and not str(param.name).startswith("__")
        for param in getattr(fn, "parameters", ())
    )


def _has_volatile_qualifier(node) -> bool:
    current = node
    while current is not None:
        if "volatile" in (getattr(current, "quals", None) or ()):
            return True
        current = getattr(current, "type", None)
    return False


def _parameter_declarations(funcdef) -> Dict[str, object]:
    args = getattr(getattr(getattr(funcdef, "decl", None), "type", None), "args", None)
    declarations = {}
    for param in (getattr(args, "params", None) or ()):
        name = getattr(param, "name", None)
        if name:
            declarations[name] = param
    return declarations


class _BindingScopes:
    """Resolve parameter/local identity for names that collide with parameters."""

    def __init__(self, fn, funcdef):
        self.names = {
            param.name
            for param in getattr(fn, "parameters", ())
            if getattr(param, "name", None) and not param.name.startswith("__")
        }
        self.environments: Dict[int, Dict[str, _Binding]] = {}
        self.address_taken: Set[_Binding] = set()
        self._serial = 0

        param_decls = _parameter_declarations(funcdef)
        environment: Dict[str, _Binding] = {}
        for param in getattr(fn, "parameters", ()):
            name = getattr(param, "name", None)
            if not name or name not in self.names:
                continue
            decl = param_decls.get(name)
            binding = self._new_binding(
                name,
                "parameter",
                decl,
                _has_volatile_qualifier(decl)
                or "volatile" in str(getattr(param, "type_name", "")).split(),
            )
            environment[name] = binding

        self._walk(getattr(funcdef, "body", None), environment)

    def _new_binding(self, name: str, kind: str, origin, is_volatile: bool) -> _Binding:
        self._serial += 1
        return _Binding(
            name=name,
            kind=kind,
            serial=self._serial,
            origin_id=id(origin) if origin is not None else 0,
            is_volatile=is_volatile,
        )

    def _record(self, node, environment: Dict[str, _Binding]) -> None:
        if node is None:
            return
        self.environments[id(node)] = dict(environment)
        if type(node).__name__ == "UnaryOp" and getattr(node, "op", None) == "&":
            expr = getattr(node, "expr", None)
            for subnode in self._iter_nodes(expr):
                if type(subnode).__name__ != "ID":
                    continue
                binding = environment.get(getattr(subnode, "name", ""))
                if binding is not None:
                    self.address_taken.add(binding)

    @staticmethod
    def _iter_nodes(node):
        if node is None:
            return
        yield node
        for _name, child in node.children():
            yield from _BindingScopes._iter_nodes(child)

    def _bind_declaration(self, decl, environment: Dict[str, _Binding]):
        name = getattr(decl, "name", None)
        if not name or name not in self.names:
            return environment
        updated = dict(environment)
        updated[name] = self._new_binding(
            name,
            "local",
            decl,
            _has_volatile_qualifier(decl),
        )
        return updated

    def _record_subtree(self, node, environment: Dict[str, _Binding]) -> None:
        if node is None:
            return
        self._record(node, environment)
        for _name, child in node.children():
            self._record_subtree(child, environment)

    def _walk_declaration(self, decl, environment: Dict[str, _Binding]) -> None:
        # The block-scope identifier is visible in its initializer, so record the
        # declaration subtree after installing the binding.
        self._record_subtree(decl, environment)

    def _walk(self, node, environment: Dict[str, _Binding]) -> None:
        if node is None:
            return

        kind = type(node).__name__
        self._record(node, environment)

        if kind == "Compound":
            current = dict(environment)
            for item in (getattr(node, "block_items", None) or ()):
                if type(item).__name__ == "Decl":
                    current = self._bind_declaration(item, current)
                    self._walk_declaration(item, current)
                else:
                    self._walk(item, current)
            return

        if kind == "For":
            current = dict(environment)
            init = getattr(node, "init", None)
            if type(init).__name__ == "DeclList":
                for decl in (getattr(init, "decls", None) or ()):
                    current = self._bind_declaration(decl, current)
                self._record(init, current)
                for decl in (getattr(init, "decls", None) or ()):
                    self._walk_declaration(decl, current)
            elif type(init).__name__ == "Decl":
                current = self._bind_declaration(init, current)
                self._walk_declaration(init, current)
            else:
                self._walk(init, current)

            self._walk(getattr(node, "cond", None), current)
            self._walk(getattr(node, "next", None), current)
            self._walk(getattr(node, "stmt", None), current)
            return

        # A declaration normally arrives through Compound/For above. Retain a
        # conservative fallback for unusual AST shapes without leaking its
        # binding to siblings whose scope we cannot establish here.
        if kind == "Decl":
            current = self._bind_declaration(node, environment)
            self._walk_declaration(node, current)
            return

        for _name, child in node.children():
            self._walk(child, environment)

    def binding_for(self, node, name: str) -> Optional[_Binding]:
        if node is None:
            return None
        return self.environments.get(id(node), {}).get(name)


def _event_expression(node):
    ast_node = getattr(node, "_ast_node", None)
    if ast_node is None:
        return None
    if node.kind in {"if_cond", "while_cond", "do_cond", "for_cond", "switch_cond"}:
        return getattr(ast_node, "cond", None)
    return ast_node


def _bound_effects(node, scopes: _BindingScopes) -> Tuple[Tuple[StorageEffect, Optional[_Binding]], ...]:
    expression = _event_expression(node)
    return tuple(
        (effect, scopes.binding_for(expression, effect.root))
        for effect in ordered_storage_effects(expression)
    )


def _transition(
    effects: Tuple[Tuple[StorageEffect, Optional[_Binding]], ...],
    target: _Binding,
) -> str:
    """Return the first use/overwrite transition for one lexical binding."""
    for effect, binding in effects:
        if binding != target:
            continue
        if effect.action == "read":
            return "read"
        if effect.action == "write" and not effect.member_path:
            return "overwrite"
    return "none"


def _write_is_live(cfg, node_id: int, effect_index: int, target: _Binding, effects_by_node) -> bool:
    source_effects = effects_by_node[node_id]
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

        transition = _transition(effects_by_node[current_id], target)
        if transition == "read":
            return True
        if transition == "overwrite":
            continue
        for successor in cfg.nodes[current_id].successors:
            if successor not in visited:
                worklist.append(successor)
    return False


def _eligible_bound_write(effect, binding, scopes: _BindingScopes) -> bool:
    return (
        binding is not None
        and binding.name in scopes.names
        and effect.action == "write"
        and not effect.member_path
        and not binding.is_volatile
        and binding not in scopes.address_taken
    )


def _suppressed_local_initializer(cfg, node, effect, binding, pure_coordinates) -> bool:
    return (
        binding.kind == "local"
        and effect.write_kind == "initializer"
        and suppress_cfg_initializer(cfg, node, binding.name, pure_coordinates)
    )


def _dead_bound_write_candidates(cfg, scopes: _BindingScopes, pure_coordinates):
    effects_by_node = {
        node_id: _bound_effects(node, scopes) for node_id, node in cfg.nodes.items()
    }
    for node_id in sorted(cfg.nodes):
        node = cfg.nodes[node_id]
        for effect_index, (effect, binding) in enumerate(effects_by_node[node_id]):
            if not _eligible_bound_write(effect, binding, scopes):
                continue
            if _suppressed_local_initializer(
                cfg, node, effect, binding, pure_coordinates
            ):
                continue
            if _write_is_live(cfg, node_id, effect_index, binding, effects_by_node):
                continue
            yield node, binding


def _bound_issue(rule, file_path, ast_ctx, fn, node, binding):
    line_no = int(getattr(node, "line_number", 0) or 0)
    if line_no <= 0:
        return None
    snippet = (
        ast_ctx.source_lines[line_no - 1].strip()
        if 1 <= line_no <= len(ast_ctx.source_lines)
        else f"{binding.name} = ...;"
    )
    location = getattr(node, "source_location", None)
    column = int(getattr(location, "column_number", 0) or 0) or 1
    binding_label = (
        "function parameter" if binding.kind == "parameter" else "local variable"
    )
    return rule.create_issue(
        file_path=file_path,
        line_number=line_no,
        code_snippet=snippet,
        message=(
            f"Value assigned to {binding_label} '{binding.name}' in "
            f"'{fn.name}' is never read before reassignment or scope "
            "exit (dead store, CWE-563)."
        ),
        column_number=column,
        engine="AST",
        fix_type=(
            FixType.SAFE_FIX
            if snippet.endswith(";")
            else FixType.MANUAL_REVIEW
        ),
    )


def parameter_dead_store_issues(rule, file_path, ast_ctx, fn, funcdef, cfg):
    """Report dead explicit stores to parameters and colliding local bindings."""
    if not has_tracked_parameters(fn):
        return []

    scopes = _BindingScopes(fn, funcdef)
    pure_coordinates = pure_declaration_coordinates(funcdef)
    issues = []
    reported = set()

    for node, binding in _dead_bound_write_candidates(
        cfg, scopes, pure_coordinates
    ):
        report_key = (node.node_id, binding.serial)
        if report_key in reported:
            continue
        reported.add(report_key)
        issue = _bound_issue(rule, file_path, ast_ctx, fn, node, binding)
        if issue is not None:
            issues.append(issue)

    return issues


def _fallback_line_scopes(fn):
    statements = list(body_statements(fn.body))
    scope_stack = [0]
    block_counter = 0
    line_scopes = {}

    for offset, line in statements:
        line_scopes[offset] = tuple(scope_stack)
        masked = mask_string_and_char_literals(line)
        for char in masked:
            if char == "{":
                block_counter += 1
                scope_stack.append(block_counter)
            elif char == "}" and len(scope_stack) > 1:
                scope_stack.pop()

    return statements, line_scopes


def _named_parameters(fn):
    return [
        param
        for param in getattr(fn, "parameters", ())
        if getattr(param, "name", None) and not param.name.startswith("__")
    ]


def _make_fallback_parameter(fn, param):
    type_name = str(getattr(param, "type_name", ""))
    variable = CVariable(
        name=param.name,
        type_name=type_name,
        is_pointer=bool(getattr(param, "is_pointer", False)),
        is_signed=("unsigned" not in type_name.split()),
        is_volatile=(
            getattr(param, "is_volatile", False) or "volatile" in type_name.split()
        ),
        is_vla=False,
        array_size_expr=None,
        has_initializer=False,
        declaration_line=int(
            getattr(fn, "start_line_exp", 0)
            or getattr(fn, "start_line", 0)
            or 0
        ),
        is_array=bool(getattr(param, "is_array", False)),
        enclosing_block_id=0,
    )
    variable.declaration_line_exp = variable.declaration_line
    setattr(variable, "_cgull_parameter_binding", True)
    return variable


def _raw_local_bindings(fn):
    if isinstance(fn.variables, dict):
        return list(dict.values(fn.variables))
    return list(fn.variables)


def _local_hides_parameter(local, name: str, scopes, exp_line: int, declaration_scopes) -> bool:
    declaration_line = int(
        getattr(local, "declaration_line_exp", 0)
        or getattr(local, "declaration_line", 0)
        or 0
    )
    local_scope = declaration_scopes.get(declaration_line, ())
    return (
        getattr(local, "name", None) == name
        and bool(local_scope)
        and scopes[:len(local_scope)] == local_scope
        and declaration_line <= exp_line
    )


def _append_unique(values, value: int) -> None:
    if value not in values:
        values.append(value)


def _plain_assignment_target(masked: str) -> Optional[str]:
    match = re.match(
        r"^\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+|->\w+)*\s*=(?!=)",
        masked,
    )
    return match.group(1) if match else None


def _line_reads_parameter(masked: str, name: str) -> bool:
    escaped = re.escape(name)
    if re.search(
        rf"\b{escaped}\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)",
        masked,
    ):
        return True
    if re.search(rf"(?:\+\+|--)\s*\b{escaped}\b", masked):
        return True

    pure_assignment = re.match(
        rf"^\s*{escaped}\s*=(?!=)\s*(.*)$",
        masked,
        re.DOTALL,
    )
    if pure_assignment:
        return bool(re.search(rf"\b{escaped}\b", pure_assignment.group(1)))
    return bool(re.search(rf"\b{escaped}\b", masked))


def _record_fallback_parameter_line(variable, name: str, masked: str, exp_line: int):
    if _plain_assignment_target(masked) == name:
        _append_unique(variable.assigned_lines, exp_line)
        _append_unique(variable.assigned_lines_exp, exp_line)

    if re.search(rf"&\s*\b{re.escape(name)}\b", masked):
        variable.address_taken = True
        _append_unique(variable.address_taken_lines, exp_line)

    if _line_reads_parameter(masked, name):
        _append_unique(variable.read_lines, exp_line)
        _append_unique(variable.read_lines_exp, exp_line)


def fallback_parameter_bindings(fn):
    """Build explicit-write-only parameter bindings for regex fallback mode."""
    parameters = _named_parameters(fn)
    if not parameters:
        return []

    bindings = {
        param.name: _make_fallback_parameter(fn, param)
        for param in parameters
    }
    statements, line_scopes = _fallback_line_scopes(fn)
    fn_start = int(
        getattr(fn, "body_start_line_exp", 0)
        or getattr(fn, "body_start_line", 0)
        or getattr(fn, "start_line", 0)
        or 1
    )
    local_bindings = _raw_local_bindings(fn)
    # AST and lexical parsers allocate different block IDs. Match each local
    # declaration to the lexical scope at its source line instead.
    declaration_scopes = {fn_start + offset: scope for offset, scope in line_scopes.items()}

    for offset, line in statements:
        exp_line = fn_start + offset
        scopes = line_scopes[offset]
        masked = mask_string_and_char_literals(line)
        for name, variable in bindings.items():
            hidden = any(
                _local_hides_parameter(local, name, scopes, exp_line, declaration_scopes)
                for local in local_bindings
            )
            if not hidden:
                _record_fallback_parameter_line(
                    variable, name, masked, exp_line
                )

    return list(bindings.values())


def _expanded_function(fn):
    from copy import copy

    expanded = copy(fn)
    expanded.start_line = (
        getattr(fn, "start_line_exp", 0) or getattr(fn, "start_line", 0)
    )
    expanded.end_line = (
        getattr(fn, "end_line_exp", 0) or getattr(fn, "end_line", 0)
    )
    return expanded


def _protected_parameter_writes(variables, loop_infos):
    protected = set()
    for _header, body_start, body_end, read_names in loop_infos:
        for variable in variables:
            if variable.name not in read_names:
                continue
            loop_writes = [
                line
                for line in sorted(set(variable.assigned_lines))
                if body_start <= line <= body_end
            ]
            if loop_writes:
                protected.add((variable.name, loop_writes[-1]))
    return protected


def _fallback_dead_write_lines(variable, protected):
    writes = sorted(set(variable.assigned_lines))
    reads = sorted(set(variable.read_lines))
    for index, line in enumerate(writes):
        next_line = (
            writes[index + 1]
            if index + 1 < len(writes)
            else float("inf")
        )
        if any(line <= read < next_line for read in reads):
            continue
        if (variable.name, line) not in protected:
            yield line


def _fallback_parameter_issue(
    rule,
    file_path,
    ast_ctx,
    expanded_fn,
    variable,
    line,
    source,
):
    from .fallback_writes import verified_write

    event = verified_write(ast_ctx, expanded_fn, variable, line, source)
    if event is None:
        return None

    end_line = event.expanded_line + event.statement.count("\n")
    issue = rule.create_issue(
        file_path=file_path,
        line_number=event.expanded_line,
        code_snippet="\n".join(
            ast_ctx.source_lines[event.expanded_line - 1 : end_line]
        ).strip(),
        message=(
            f"Value assigned to function parameter '{event.binding[0]}' "
            f"in '{event.function}' is never read before reassignment "
            "or scope exit (dead store, CWE-563)."
        ),
        column_number=event.column,
        engine="AST",
        fix_type=FixType.MANUAL_REVIEW,
    )
    issue.expanded_end_line = end_line
    return issue


def _fallback_function_issues(rule, file_path, ast_ctx, fn, source, loop_infos):
    variables = [
        variable
        for variable in fallback_parameter_bindings(fn)
        if not variable.is_volatile and not variable.address_taken
    ]
    expanded_fn = _expanded_function(fn)
    protected = _protected_parameter_writes(variables, loop_infos)
    for variable in variables:
        for line in _fallback_dead_write_lines(variable, protected):
            issue = _fallback_parameter_issue(
                rule,
                file_path,
                ast_ctx,
                expanded_fn,
                variable,
                line,
                source,
            )
            if issue is not None:
                yield issue


def fallback_parameter_dead_store_issues(rule, file_path, ast_ctx):
    """Report dead explicit parameter writes in lexical fallback mode."""
    from .dead_stores import _collect_loop_infos
    from .fallback_writes import WriteSource

    source = WriteSource(ast_ctx)
    source_text = getattr(ast_ctx, "clean_source", "") or "\n".join(
        ast_ctx.source_lines
    )
    loop_infos = _collect_loop_infos(source_text)
    issues = []

    for fn in getattr(ast_ctx, "functions", ()):
        issues.extend(_fallback_function_issues(
            rule, file_path, ast_ctx, fn, source, loop_infos
        ))

    return issues


__all__ = [
    "fallback_parameter_bindings",
    "fallback_parameter_dead_store_issues",
    "has_tracked_parameters",
    "parameter_dead_store_issues",
]
