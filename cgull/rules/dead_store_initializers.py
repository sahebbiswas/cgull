"""Conservative defensive-initialization policy for CGULL-042."""

import re

from pycparser import CParser, c_ast


def pure_initializer(expr, proven_constants=()):
    """Recognize value expressions without calls, volatile reads or mutations.

    Identifiers remain conservative unless the caller has proven them to be
    compile-time constants. Addressing a named object does not read its value.
    Avoid sizeof/type-based reasoning here because variably modified types can
    evaluate expressions.
    """
    if isinstance(expr, c_ast.Constant):
        return True
    if isinstance(expr, c_ast.ID):
        return expr.name == "NULL" or expr.name in proven_constants
    if isinstance(expr, c_ast.UnaryOp):
        if expr.op == "&":
            return isinstance(expr.expr, c_ast.ID)
        return (
            expr.op in {"+", "-", "~", "!"}
            and pure_initializer(expr.expr, proven_constants)
        )
    if isinstance(expr, c_ast.Cast):
        # Only ordinary scalar/pointer casts; reject array/VLA type expressions.
        typ = expr.to_type.type
        while isinstance(typ, c_ast.PtrDecl):
            typ = typ.type
        return (
            isinstance(typ, c_ast.TypeDecl)
            and pure_initializer(expr.expr, proven_constants)
        )
    if isinstance(expr, c_ast.BinaryOp):
        return (
            pure_initializer(expr.left, proven_constants)
            and pure_initializer(expr.right, proven_constants)
        )
    if isinstance(expr, c_ast.InitList):
        return all(
            pure_initializer(item, proven_constants)
            for item in expr.exprs
        )
    if isinstance(expr, c_ast.NamedInitializer):
        return (
            all(
                isinstance(name, (c_ast.ID, c_ast.Constant))
                for name in expr.name
            )
            and pure_initializer(expr.expr, proven_constants)
        )
    return False


def file_scope_enum_constants(ast_root):
    """Return enum constants proven to live at translation-unit scope.

    Function-local enums are intentionally excluded so a same-named identifier
    in another function cannot be mistaken for a constant.
    """
    constants = set()
    for external in getattr(ast_root, "ext", ()) or ():
        if isinstance(external, c_ast.FuncDef):
            continue
        pending = [external]
        while pending:
            node = pending.pop()
            if isinstance(node, c_ast.Enumerator) and node.name:
                constants.add(node.name)
            pending.extend(child for _, child in node.children())
    return constants


def unshadowed_constant_identifiers(funcdef, constants):
    """Remove constants shadowed by an object or typedef in *funcdef*.

    This is deliberately conservative: a declaration anywhere in the function
    with the same ordinary-identifier name withholds the constant proof rather
    than attempting source-order/scope reconstruction here.
    """
    shadowed = set()
    pending = [funcdef]
    while pending:
        node = pending.pop()
        if isinstance(node, (c_ast.Decl, c_ast.Typedef)) and node.name:
            shadowed.add(node.name)
        pending.extend(child for _, child in node.children())
    return set(constants) - shadowed


def pure_declaration_coordinates(funcdef, proven_constants=()):
    """Return identities of declarations whose original initializer is pure.

    The legacy helper name is retained for compatibility with the base rule. The
    values are object identities, not coordinates: CGULL-042 must suppress only
    the exact declaration event represented by a CFG node, never another write
    that merely shares its source line.
    """
    declarations = set()
    pending = [funcdef]
    while pending:
        node = pending.pop()
        if (
            isinstance(node, c_ast.Decl)
            and pure_initializer(node.init, proven_constants)
        ):
            declarations.add(id(node))
        pending.extend(child for _, child in node.children())
    return declarations


def suppress_cfg_initializer(_cfg, node, variable, pure_declarations):
    """Suppress only the exact pure declaration initializer CFG event.

    Declaration initializers are outside CGULL-042's policy regardless of
    whether later control flow overwrites the value or exits the scope first.
    """
    decl = getattr(node, "_ast_node", None)
    return (
        isinstance(decl, c_ast.Decl)
        and decl.name == variable
        and id(decl) in pure_declarations
    )


def suppress_lexical_initializer(context, variable, line):
    """Suppress a fallback finding only for a proven pure declaration initializer.

    Fallback findings are line-based, so require the concrete binding metadata to
    identify this line as the variable's initializer declaration. If more than one
    write to the same binding occurs on that physical line, keep the finding: the
    fallback tier cannot distinguish the initializer from the later assignment.
    """
    if not variable.has_initializer or line != variable.declaration_line:
        return False
    if sum(1 for write_line in variable.assigned_lines if write_line == line) != 1:
        return False

    source = getattr(context, "clean_source", "") or "\n".join(context.source_lines)
    lines = source.splitlines()
    if line < 1 or line > len(lines):
        return False

    # Start at the binding's declaration line and extract only its initializer.
    # The metadata establishes declaration identity; parsing establishes purity.
    text = "\n".join(lines[line - 1:])
    match = re.search(
        r"\b" + re.escape(variable.name) + r"\s*(?:\[[^;]*?\]\s*)?=\s*(.*?);",
        text,
        re.DOTALL,
    )
    if match is None:
        return False

    # assigned_lines is line-based and can collapse multiple writes on one line.
    # Inspect the remainder of the declaration line so the fallback tier does not
    # mistake a later assignment (or increment/decrement) for the initializer.
    first_line_end = text.find("\n")
    if first_line_end < 0:
        first_line_end = len(text)
    if match.end() <= first_line_end:
        tail = text[match.end():first_line_end]
        name = re.escape(variable.name)
        same_line_write = re.search(
            rf"(?:\b{name}\b\s*(?:\+\+|--|(?:<<|>>|[+\-*/%&|^])?=(?!=))|(?:\+\+|--)\s*\b{name}\b)",
            tail,
        )
        if same_line_write is not None:
            return False

    try:
        unit = CParser().parse("void f(void) { int value = " + match.group(1) + "; }")
    except Exception:
        return False
    declarations = unit.ext[0].body.block_items
    return len(declarations) == 1 and pure_initializer(declarations[0].init)
