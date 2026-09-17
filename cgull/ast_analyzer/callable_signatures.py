"""Rule-neutral direct-call signature resolution for parsed C translation units."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .standard_signatures import StandardCallableSignature, standard_callable_signature
from .types import CASTContext, _format_pycparser_type, resolve_typedef_shape


@dataclass(frozen=True)
class CallableParameter:
    """A fixed parameter in a visible or modeled callable declaration."""

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
    return_type: str = ""


def _parameter_from_ast(ast_ctx: CASTContext, param) -> CallableParameter:
    type_name, is_ptr, is_fp, _is_vol, _is_signed, _is_vla, _dim, is_arr = _format_pycparser_type(
        param.type, ast_ctx.unsigned_typedefs
    )
    shape = resolve_typedef_shape(type_name, ast_ctx.typedef_shapes) if ast_ctx.typedef_shapes else None
    return CallableParameter(
        name=getattr(param, "name", None) or "",
        type_name=type_name,
        is_pointer=is_ptr or is_fp or bool(shape and shape.is_pointer),
        is_array=is_arr or bool(shape and shape.is_array),
    )


def _return_type_from_decl(ast_ctx: CASTContext, decl) -> str:
    return_node = getattr(getattr(decl, "type", None), "type", None)
    if return_node is None:
        return ""
    type_name, _is_ptr, _is_fp, _is_vol, _is_signed, _is_vla, _dim, _is_arr = _format_pycparser_type(
        return_node, ast_ctx.unsigned_typedefs
    )
    return type_name


def _signature_from_decl(ast_ctx: CASTContext, decl, provenance: str) -> CallableSignature:
    from pycparser import c_ast

    return_type = _return_type_from_decl(ast_ctx, decl)
    args = getattr(decl.type, "args", None)
    if args is None:
        return CallableSignature(
            name=decl.name,
            parameters=(),
            has_prototype=False,
            provenance=provenance,
            return_type=return_type,
        )

    raw_params = list(getattr(args, "params", None) or [])
    if len(raw_params) == 1 and not isinstance(raw_params[0], c_ast.EllipsisParam):
        p0 = raw_params[0]
        if hasattr(p0, "type"):
            p0_type, p0_ptr, p0_fp, _vol, _sig, _vla, _dim, p0_arr = _format_pycparser_type(
                p0.type, ast_ctx.unsigned_typedefs
            )
            if p0_type == "void" and not p0_ptr and not p0_fp and not p0_arr and not getattr(p0, "name", None):
                return CallableSignature(
                    name=decl.name,
                    parameters=(),
                    has_prototype=True,
                    provenance=provenance,
                    return_type=return_type,
                )

    params: List[CallableParameter] = []
    variadic = False
    for param in raw_params:
        if isinstance(param, c_ast.EllipsisParam):
            variadic = True
        elif hasattr(param, "type"):
            params.append(_parameter_from_ast(ast_ctx, param))
    return CallableSignature(
        name=decl.name,
        parameters=tuple(params),
        variadic=variadic,
        has_prototype=True,
        provenance=provenance,
        return_type=return_type,
    )


def _signature_from_standard(model: StandardCallableSignature) -> CallableSignature:
    return CallableSignature(
        name=model.name,
        return_type=model.return_type,
        parameters=tuple(
            CallableParameter(
                name=param.name,
                type_name=param.type_name,
                is_pointer=param.is_pointer,
                is_array=param.is_array,
            )
            for param in model.parameters
        ),
        variadic=model.variadic,
        has_prototype=True,
        provenance=model.provenance,
    )


def _canonical_parameter(param: CallableParameter):
    return (" ".join(param.type_name.split()), param.is_pointer, param.is_array)


def _compatible(left: CallableSignature, right: CallableSignature) -> bool:
    if left.has_prototype != right.has_prototype:
        return True
    if not left.has_prototype:
        return True
    if left.variadic != right.variadic or len(left.parameters) != len(right.parameters):
        return False
    return all(_canonical_parameter(a) == _canonical_parameter(b) for a, b in zip(left.parameters, right.parameters))


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
        if candidate.has_prototype and not chosen.has_prototype:
            chosen = candidate
        elif candidate.provenance == "definition" and chosen.provenance != "definition":
            chosen = candidate
    return chosen


@dataclass(frozen=True)
class _TranslationUnitCallableState:
    """Immutable top-level callable signatures for one parsed translation unit."""

    ast_root: object
    callable_events: Mapping[str, Tuple[Tuple[int, CallableSignature], ...]]
    function_positions: Mapping[int, int]

    def visible_signatures(self, name: str, caller_position: int) -> Tuple[CallableSignature, ...]:
        events = self.callable_events.get(name, ())
        return tuple(signature for position, signature in events if position <= caller_position)


_TU_STATE_ATTR = "_direct_call_signature_tu_state"


def _build_translation_unit_callable_state(ast_ctx: CASTContext) -> _TranslationUnitCallableState:
    from pycparser import c_ast

    root = ast_ctx.pycparser_ast
    events: Dict[str, List[Tuple[int, CallableSignature]]] = {}
    function_positions: Dict[int, int] = {}

    for position, ext in enumerate(getattr(root, "ext", None) or []):
        if isinstance(ext, c_ast.FuncDef):
            function_positions[id(ext)] = position
            events.setdefault(ext.decl.name, []).append(
                (position, _signature_from_decl(ast_ctx, ext.decl, "definition"))
            )
        elif isinstance(ext, c_ast.Decl) and isinstance(ext.type, c_ast.FuncDecl):
            events.setdefault(ext.name, []).append(
                (position, _signature_from_decl(ast_ctx, ext, "file-declaration"))
            )

    return _TranslationUnitCallableState(
        ast_root=root,
        callable_events=MappingProxyType({name: tuple(items) for name, items in events.items()}),
        function_positions=MappingProxyType(dict(function_positions)),
    )


def _translation_unit_callable_state(ast_ctx: CASTContext) -> _TranslationUnitCallableState:
    """Return context-local top-level callable state, building it once per AST."""

    root = ast_ctx.pycparser_ast
    cached = getattr(ast_ctx, _TU_STATE_ATTR, None)
    if isinstance(cached, _TranslationUnitCallableState) and cached.ast_root is root:
        return cached

    state = _build_translation_unit_callable_state(ast_ctx)
    setattr(ast_ctx, _TU_STATE_ATTR, state)
    return state


class DirectCallSignatureIndex:
    """Precomputed direct-call signature index for one function.

    Translation-unit declarations/definitions are formatted once and cached on
    the owning ``CASTContext``. Construction here only snapshots block-scope
    bindings for this function. Individual call resolution is then an O(1)
    identity lookup plus reconciliation of the small visible declaration set
    for that callee.
    """

    def __init__(
        self,
        ast_ctx: CASTContext,
        funcdef,
        tu_state: Optional[_TranslationUnitCallableState] = None,
    ):
        self.ast_ctx = ast_ctx
        self.funcdef = funcdef
        self._tu_state = tu_state or _translation_unit_callable_state(ast_ctx)
        self._caller_position = self._tu_state.function_positions.get(id(funcdef))
        self._calls: Dict[int, object] = {}
        self._source_signatures: Dict[str, Optional[CallableSignature]] = {}

        self._index_calls()

    def _index_calls(self) -> None:
        from pycparser import c_ast

        scopes: List[Dict[str, object]] = []

        def visible_binding(name: str):
            for scope in reversed(scopes):
                if name in scope:
                    return scope[name]
            return None

        def walk(node):
            if node is None:
                return
            if isinstance(node, c_ast.Compound):
                scopes.append({})
                for item in node.block_items or []:
                    if isinstance(item, c_ast.Decl) and getattr(item, "name", None):
                        if isinstance(item.type, c_ast.FuncDecl):
                            existing = scopes[-1].get(item.name)
                            if not isinstance(existing, list):
                                existing = scopes[-1][item.name] = []
                            existing.append(_signature_from_decl(self.ast_ctx, item, "block-declaration"))
                        else:
                            scopes[-1][item.name] = False
                    walk(item)
                scopes.pop()
                return
            if isinstance(node, c_ast.FuncCall) and isinstance(getattr(node, "name", None), c_ast.ID):
                binding = visible_binding(node.name.name)
                self._calls[id(node)] = tuple(binding) if isinstance(binding, list) else binding
            for _child_name, child in node.children():
                walk(child)

        walk(self.funcdef.body)

    def resolve(self, call_node) -> Optional[CallableSignature]:
        from pycparser import c_ast

        if not isinstance(getattr(call_node, "name", None), c_ast.ID):
            return None
        name = call_node.name.name
        block = self._calls.get(id(call_node))
        if block is False:
            # A same-named local object or function pointer is an explicit rejection,
            # not an absent declaration. Never fall through to a built-in model.
            return None
        if block:
            return _reconcile(name, block)

        if name not in self._source_signatures:
            candidates: Sequence[CallableSignature] = ()
            if self._caller_position is not None:
                candidates = self._tu_state.visible_signatures(name, self._caller_position)
            self._source_signatures[name] = _reconcile(name, candidates)
        source_signature = self._source_signatures[name]
        if source_signature is not None:
            # Resolved, unspecified-parameter, and conflicting source declarations
            # all outrank built-ins. A rejected/ambiguous source declaration must
            # never be silently replaced by a standard-library shape.
            return source_signature

        model = standard_callable_signature(name)
        return _signature_from_standard(model) if model is not None else None


def build_direct_call_signature_index(ast_ctx: CASTContext, funcdef) -> DirectCallSignatureIndex:
    """Build reusable signature-resolution state for all direct calls in ``funcdef``."""
    return DirectCallSignatureIndex(ast_ctx, funcdef)


def resolve_direct_call_signature(ast_ctx: CASTContext, funcdef, call_node) -> Optional[CallableSignature]:
    """Resolve one direct call; prefer a reusable index for repeated lookups."""
    return DirectCallSignatureIndex(ast_ctx, funcdef).resolve(call_node)
