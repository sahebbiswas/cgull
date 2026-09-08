"""Rule-neutral direct-call signature resolution for parsed C translation units."""

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .configuration import _PRELUDE_LINE_COUNT
from .types import CASTContext, _format_pycparser_type, resolve_typedef_shape


@dataclass(frozen=True)
class CallableParameter:
    """A fixed parameter in a visible callable declaration."""

    name: str
    type_name: str
    is_pointer: bool = False
    is_array: bool = False


@dataclass(frozen=True)
class CallableSignature:
    """Resolved direct-call type information, independent of body availability."""

    name: str
    parameters: Sequence[CallableParameter] = field(default_factory=tuple)
    variadic: bool = False
    has_prototype: bool = True
    provenance: str = "declaration"
    resolved: bool = True
    reason: Optional[str] = None


def _parameter_from_ast(ast_ctx: CASTContext, param) -> CallableParameter:
    type_name, is_ptr, is_fp, _is_vol, _is_signed, _is_vla, _dim, is_arr = _format_pycparser_type(
        param.type,
        ast_ctx.unsigned_typedefs,
    )
    shape = resolve_typedef_shape(type_name, ast_ctx.typedef_shapes) if ast_ctx.typedef_shapes else None
    return CallableParameter(
        name=getattr(param, "name", None) or "",
        type_name=type_name,
        is_pointer=is_ptr or is_fp or bool(shape and shape.is_pointer),
        is_array=is_arr or bool(shape and shape.is_array),
    )


def _signature_from_decl(ast_ctx: CASTContext, decl, provenance: str) -> CallableSignature:
    from pycparser import c_ast

    func_type = decl.type
    args = getattr(func_type, "args", None)
    if args is None:
        # ``f()`` is an old-style/unspecified parameter declaration in C.
        return CallableSignature(
            name=decl.name,
            parameters=(),
            variadic=False,
            has_prototype=False,
            provenance=provenance,
        )

    raw_params = list(getattr(args, "params", None) or [])
    if len(raw_params) == 1 and not isinstance(raw_params[0], c_ast.EllipsisParam):
        p0 = raw_params[0]
        if hasattr(p0, "type"):
            p0_type, p0_ptr, p0_fp, _vol, _sig, _vla, _dim, p0_arr = _format_pycparser_type(
                p0.type,
                ast_ctx.unsigned_typedefs,
            )
            if p0_type == "void" and not p0_ptr and not p0_fp and not p0_arr and not getattr(p0, "name", None):
                return CallableSignature(
                    name=decl.name,
                    parameters=(),
                    variadic=False,
                    has_prototype=True,
                    provenance=provenance,
                )

    params: List[CallableParameter] = []
    variadic = False
    for param in raw_params:
        if isinstance(param, c_ast.EllipsisParam):
            variadic = True
            continue
        if not hasattr(param, "type"):
            continue
        params.append(_parameter_from_ast(ast_ctx, param))

    return CallableSignature(
        name=decl.name,
        parameters=tuple(params),
        variadic=variadic,
        has_prototype=True,
        provenance=provenance,
    )


def _canonical_parameter(param: CallableParameter):
    return (
        " ".join(param.type_name.split()),
        param.is_pointer,
        param.is_array,
    )


def _compatible(left: CallableSignature, right: CallableSignature) -> bool:
    if left.has_prototype != right.has_prototype:
        # A later prototype may refine an earlier unspecified declaration without conflict.
        return not left.has_prototype or not right.has_prototype
    if not left.has_prototype:
        return True
    if left.variadic != right.variadic or len(left.parameters) != len(right.parameters):
        return False
    return all(
        _canonical_parameter(a) == _canonical_parameter(b)
        for a, b in zip(left.parameters, right.parameters)
    )


def _reconcile(name: str, signatures: Sequence[CallableSignature]) -> Optional[CallableSignature]:
    if not signatures:
        return None

    chosen = signatures[0]
    for candidate in signatures[1:]:
        if not _compatible(chosen, candidate):
            return CallableSignature(
                name=name,
                parameters=(),
                has_prototype=False,
                provenance="conflicting-declarations",
                resolved=False,
                reason="conflicting visible declarations",
            )
        # Prefer the most informative prototype, and prefer a definition only as provenance.
        if candidate.has_prototype and not chosen.has_prototype:
            chosen = candidate
        elif candidate.provenance == "definition" and chosen.provenance != "definition":
            chosen = CallableSignature(
                name=chosen.name,
                parameters=chosen.parameters,
                variadic=chosen.variadic,
                has_prototype=chosen.has_prototype,
                provenance="definition",
            )
    return chosen


def _visible_block_signatures(ast_ctx: CASTContext, funcdef, call_node, name: str):
    """Return the innermost visible block-scope declarations, or ``False`` if shadowed by an object."""
    from pycparser import c_ast

    found = None
    blocked = False
    stopped = False
    scopes = []

    def walk(node):
        nonlocal found, blocked, stopped
        if node is None or stopped:
            return
        if node is call_node:
            for scope in reversed(scopes):
                if name in scope:
                    value = scope[name]
                    if value is False:
                        blocked = True
                    else:
                        found = value
                    break
            stopped = True
            return

        if isinstance(node, c_ast.Compound):
            scopes.append({})
            for item in node.block_items or []:
                if stopped:
                    break
                if isinstance(item, c_ast.Decl) and getattr(item, "name", None) == name:
                    if isinstance(item.type, c_ast.FuncDecl):
                        scopes[-1].setdefault(name, []).append(
                            _signature_from_decl(ast_ctx, item, "block-declaration")
                        )
                    else:
                        scopes[-1][name] = False
                walk(item)
            scopes.pop()
            return

        for _child_name, child in node.children():
            walk(child)
            if stopped:
                break

    walk(funcdef.body)
    return False if blocked else found


def resolve_direct_call_signature(ast_ctx: CASTContext, funcdef, call_node) -> Optional[CallableSignature]:
    """Resolve a visible signature for a direct ``ID(...)`` call.

    The query deliberately returns type information only; it never fabricates a function body,
    CFG, ownership summary, or security effect for declaration-only callees.
    """
    from pycparser import c_ast

    if not isinstance(getattr(call_node, "name", None), c_ast.ID):
        return None
    name = call_node.name.name

    block = _visible_block_signatures(ast_ctx, funcdef, call_node, name)
    if block is False:
        return None
    if block:
        return _reconcile(name, block)

    visible_globals: List[CallableSignature] = []
    definitions: List[CallableSignature] = []
    caller_seen = False
    for ext in getattr(ast_ctx.pycparser_ast, "ext", None) or []:
        if isinstance(ext, c_ast.FuncDef):
            signature = _signature_from_decl(ast_ctx, ext.decl, "definition")
            if ext is funcdef:
                caller_seen = True
            if ext.decl.name == name:
                definitions.append(signature)
            continue
        if not caller_seen and isinstance(ext, c_ast.Decl) and isinstance(ext.type, c_ast.FuncDecl):
            if ext.name == name:
                visible_globals.append(_signature_from_decl(ast_ctx, ext, "file-declaration"))

    # Preserve historical definition-backed behavior when no visible prototype exists.
    candidates = visible_globals or definitions
    return _reconcile(name, candidates)
