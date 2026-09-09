"""Conservative defensive-initialization policy for CGULL-042."""

import re
from collections import deque

from pycparser import CParser, c_ast


def pure_initializer(expr):
    """Recognize value expressions without calls, volatile reads or mutations.

    Unknown identifiers (including unexpanded macros) are deliberately excluded.
    Addressing a named object does not read its value. Avoid sizeof/type-based
    reasoning here because variably modified types can evaluate expressions.
    """
    if isinstance(expr, c_ast.Constant):
        return True
    if isinstance(expr, c_ast.ID):
        return expr.name == "NULL"
    if isinstance(expr, c_ast.UnaryOp):
        if expr.op == "&":
            return isinstance(expr.expr, c_ast.ID)
        return expr.op in {"+", "-", "~", "!"} and pure_initializer(expr.expr)
    if isinstance(expr, c_ast.Cast):
        # Only ordinary scalar/pointer casts; reject array/VLA type expressions.
        typ = expr.to_type.type
        while isinstance(typ, c_ast.PtrDecl):
            typ = typ.type
        return isinstance(typ, c_ast.TypeDecl) and pure_initializer(expr.expr)
    if isinstance(expr, c_ast.BinaryOp):
        return pure_initializer(expr.left) and pure_initializer(expr.right)
    if isinstance(expr, c_ast.InitList):
        return all(pure_initializer(item) for item in expr.exprs)
    if isinstance(expr, c_ast.NamedInitializer):
        return all(isinstance(name, (c_ast.ID, c_ast.Constant)) for name in expr.name) and pure_initializer(expr.expr)
    return False


def overwritten_on_all_paths(cfg, successors, variable):
    """Prove overwrite before exit, read, unknown flow, or an unbounded cycle."""
    pending = list(successors)
    nodes = {}
    proven = set()
    while pending:
        node_id = pending.pop()
        if node_id in nodes:
            continue
        node = cfg.nodes[node_id]
        nodes[node_id] = node
        if variable in node.reads or node.kind == "unknown_control_flow":
            return False
        if variable in node.writes:
            proven.add(node_id)
            continue
        # StructuredGraph represents fall-through out of a function as None,
        # which connect() omits. A conditional with one stored edge can therefore
        # also exit without executing that edge.
        if node.kind == "switch_cond" or (
            node.kind in {"if_cond", "while_cond", "for_cond", "do_cond"}
            and len(node.successors) < 2
        ):
            return False
        if not node.successors:
            return False
        pending.extend(node.successors)
    # Least fixed point: cycles without a guaranteed overwrite remain unproven.
    predecessors = {node_id: [] for node_id in nodes}
    remaining = {}
    for node_id, node in nodes.items():
        if node_id in proven:
            continue
        remaining[node_id] = len(node.successors)
        for successor in node.successors:
            predecessors[successor].append(node_id)
    queue = deque(proven)
    while queue:
        for predecessor in predecessors[queue.popleft()]:
            remaining[predecessor] -= 1
            if remaining[predecessor] == 0:
                proven.add(predecessor)
                queue.append(predecessor)
    return bool(successors) and all(s in proven for s in successors)


def pure_declaration_coordinates(funcdef):
    """Retain original purity before CFG ternary-expression lowering."""
    coordinates = set()
    pending = [funcdef]
    while pending:
        node = pending.pop()
        if isinstance(node, c_ast.Decl) and node.coord is not None and pure_initializer(node.init):
            coordinates.add((node.coord.file, node.coord.line, node.coord.column))
        pending.extend(child for _, child in node.children())
    return coordinates


def suppress_cfg_initializer(cfg, node, variable, pure_coordinates):
    decl = getattr(node, "_ast_node", None)
    coord = getattr(decl, "coord", None)
    return (
        isinstance(decl, c_ast.Decl)
        and decl.name == variable
        and coord is not None
        and (coord.file, coord.line, coord.column) in pure_coordinates
        and pure_initializer(decl.init)
        and overwritten_on_all_paths(cfg, node.successors, variable)
    )


def suppress_lexical_initializer(context, variable, line):
    """Require a known declaration and an unambiguous straight-line overwrite.

    The fallback has line-based bindings rather than CFG events. Only inspect a
    complete, single declaration statement and decline control-flow ambiguity.
    """
    if not variable.has_initializer or line != variable.declaration_line:
        return False
    later = [w for w in variable.assigned_lines if w > line]
    if not later:
        return False
    next_write = min(later)
    source = getattr(context, "clean_source", "") or "\n".join(context.source_lines)
    lines = source.splitlines()
    text = "\n".join(lines[line - 1:next_write])
    match = re.search(r"\b" + re.escape(variable.name) + r"\s*=\s*([^;]+);", text)
    if match is None:
        return False
    # The initializer must start on the declaration line, and cannot include a
    # second declarator/assignment. The small C parser validates the expression.
    if "\n" in text[:match.start()]:
        return False
    tail = text[match.end():]
    if re.search(r"\b" + re.escape(variable.name) + r"\s*=(?!=)", tail.split("\n", 1)[0]):
        # Line-based fallback findings cannot separate this later assignment
        # from the initializer, so keep the finding instead of hiding both.
        return False
    if re.search(r"[{}?:#]|\b(if|else|for|while|do|switch|goto|return|break|continue)\b", tail):
        return False
    overwrite = re.search(r"\b" + re.escape(variable.name) + r"\s*=(?!=)", tail)
    if overwrite is None:
        return False
    # Intervening calls might terminate or otherwise invalidate straight-line
    # reasoning. Calls on the overwriting RHS do not affect the old value.
    if re.search(r"\b\w+\s*\(", tail[:overwrite.start()]):
        return False
    try:
        unit = CParser().parse("void f(void) { int value = " + match.group(1) + "; }")
    except Exception:
        return False
    declarations = unit.ext[0].body.block_items
    return len(declarations) == 1 and pure_initializer(declarations[0].init)
