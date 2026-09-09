"""Scan-local direct-call summary indexing without combining translation units.

The existing TU engines own all transfer semantics. A callee-first TU graph
supplies their external inputs; recursive TU components use snapshot rounds.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import os

from pycparser import c_ast

from .analysis_session import AnalysisSession
from .ast_analyzer import CASTParser
from .cfg.call_graph import _bottom_up_scc_order, _strongly_connected_components
from .cfg.security_dataflow import analyze_security_summaries
from .cfg.value_facts import analyze_value_summaries_detailed
from .includes import IncludeResolver, TUIncludeExpander
from .models import AnalysisEngine
from .semantic_models import EMPTY_SEMANTIC_MODELS

DOMAINS = ("function", "ownership", "value", "security")


def profile_key(flags):
    # Preserve value types and explicit undefinitions; do not conflate None/0.
    return tuple(sorted((name, type(value).__name__, repr(value)) for name, value in (flags or {}).items()))


def _type_key(node):
    """Structural C signature with parameter names/coordinates excluded."""
    if node is None:
        return None
    if isinstance(node, (c_ast.Decl, c_ast.Typename)):
        return _type_key(node.type)
    attrs = tuple((name, repr(getattr(node, name))) for name in node.attr_names if name != "declname")
    return type(node).__name__, attrs, tuple(_type_key(child) for _, child in node.children())


def _declarations(ast):
    declarations = defaultdict(list)

    class Visitor(c_ast.NodeVisitor):
        def visit_Decl(self, node):
            if node.name:
                declarations[node.name].append(node)
            self.generic_visit(node)

    Visitor().visit(ast)
    return declarations


def _signature_types(ast):
    """Index named type definitions once, including shadowed typedef variants."""
    types = defaultdict(list)

    class Visitor(c_ast.NodeVisitor):
        def visit_Typedef(self, node):
            types[node.name].append(node.type)
            self.generic_visit(node)

        def visit_Struct(self, node):
            if node.name and node.decls is not None:
                types["struct " + node.name].append(node)
            self.generic_visit(node)

        def visit_Union(self, node):
            if node.name and node.decls is not None:
                types["union " + node.name].append(node)
            self.generic_visit(node)

    Visitor().visit(ast)
    return types


def _signature_key(node, types):
    # Include the transitive named-type dependencies. Equal typedef spellings
    # alone do not establish equal types in separately parsed translation units.
    pending = [node]
    dependencies = {}
    while pending:
        item = pending.pop()
        if isinstance(item, c_ast.IdentifierType):
            keys = item.names if len(item.names) == 1 else ()
        elif isinstance(item, (c_ast.Struct, c_ast.Union)):
            keys = (type(item).__name__.lower() + " " + item.name,) if item.name else ()
        else:
            keys = ()
        for key in keys:
            if key in types and key not in dependencies:
                dependencies[key] = tuple(sorted({_type_key(t) for t in types[key]}, key=repr))
                pending.extend(types[key])
        pending.extend(child for _, child in item.children())
    return _type_key(node), tuple(sorted(dependencies.items()))


@dataclass
class PreparedUnit:
    source: str
    expanded: object
    context: object


class ProjectSummaryIndex:
    """One exact preprocessor/include/model configuration; never process-global."""

    def __init__(self, contexts, semantic_models=EMPTY_SEMANTIC_MODELS, *, max_rounds=64):
        if max_rounds < 1:
            raise ValueError("max_rounds must be positive")
        self.contexts = dict(sorted(contexts.items()))
        self.semantic_models = semantic_models
        self.max_rounds = max_rounds
        self.diagnostics = []
        self.iterations = {}
        self.sessions = {path: AnalysisSession(ctx, semantic_models=semantic_models) for path, ctx in self.contexts.items()}
        self.exports = defaultdict(list)
        self.bindings = {path: {} for path in self.contexts}
        self.outputs = {}
        self.blocked_exports = set()
        self.declarations = {path: _declarations(ctx.pycparser_ast) for path, ctx in self.contexts.items()}
        type_maps = {path: _signature_types(ctx.pycparser_ast) for path, ctx in self.contexts.items()}
        self.signatures = {
            path: {name: {_signature_key(d.type, type_maps[path]) for d in declarations
                          if isinstance(d.type, c_ast.FuncDecl)}
                   for name, declarations in names.items()}
            for path, names in self.declarations.items()
        }
        self.local_names = {}
        for path, ctx in self.contexts.items():
            definitions = defaultdict(int)
            for node in ctx.pycparser_ast.ext:
                if isinstance(node, c_ast.FuncDef):
                    definitions[node.decl.name] += 1
            self.local_names[path] = set(definitions)
            for name in sorted(definitions):
                if not any("static" in d.storage for d in self.declarations[path][name]):
                    self.exports[name].append(path)
                    if definitions[name] > 1:
                        self.blocked_exports.add(name)
        for name, paths in sorted(self.exports.items()):
            if len(paths) > 1 or name in self.blocked_exports:
                self.diagnostics.append(f"AMBIGUOUS_EXTERNAL: {name}: {', '.join(paths)}; cross-TU summary omitted")
        for path, ctx in self.contexts.items():
            names = set()

            class Calls(c_ast.NodeVisitor):
                def visit_FuncCall(self, node):
                    if isinstance(node.name, c_ast.ID):
                        names.add(node.name.name)
                    self.generic_visit(node)

            Calls().visit(ctx.pycparser_ast)
            for name in sorted(names - self.local_names[path]):
                targets = self.exports.get(name, ())
                if len(targets) != 1 or targets[0] == path or name in self.blocked_exports:
                    continue
                target = targets[0]
                declarations = self.declarations[path].get(name, ())
                target_types = self.signatures[target][name]
                # Shadowing, internal declarations, or disagreeing prototypes
                # invalidate the name globally in this TU (a conservative bound).
                incompatible = (
                    len(target_types) != 1
                    or (declarations and self.signatures[path][name] != target_types)
                    or any("static" in d.storage or not isinstance(d.type, c_ast.FuncDecl)
                           for d in declarations)
                )
                if incompatible:
                    self.diagnostics.append(f"INCOMPATIBLE_EXTERNAL: {path}: {name}; cross-TU summary omitted")
                    continue
                self.bindings[path][name] = target

    @staticmethod
    def _exportable(domain, summary):
        if domain != "security":
            return True
        return not any((
            summary.return_from_globals,
            summary.output_from_globals,
            summary.global_from_params,
            summary.global_from_globals,
            summary.external_globals,
        ))

    def _imports(self, path, snapshot):
        return {
            domain: {
                name: snapshot[target][domain][name]
                for name, target in self.bindings[path].items()
                if target in snapshot and name in snapshot[target][domain]
                and self._exportable(domain, snapshot[target][domain][name])
            }
            for domain in DOMAINS
        }

    def _evaluate(self, path, imports):
        ctx = self.contexts[path]
        ctx.project_summaries = imports
        # Reset summary caches between rounds, retaining the original call graph.
        session = AnalysisSession(ctx, semantic_models=self.semantic_models)
        session._call_graph = self.sessions[path].call_graph
        self.sessions[path] = session
        ctx.analysis_session = session
        return {
            "function": dict(session.function_summaries),
            "ownership": dict(session.ownership_summaries),
            "value": dict(analyze_value_summaries_detailed(ctx, self.semantic_models, call_graph=session.call_graph).summaries),
            "security": analyze_security_summaries(ctx, self.semantic_models),
        }

    def build(self):
        adjacency = {path: tuple(sorted(set(bindings.values()))) for path, bindings in self.bindings.items()}
        components = _strongly_connected_components(tuple(self.contexts), adjacency)
        depended_on = {target for targets in adjacency.values() for target in targets}
        for component in _bottom_up_scc_order(components, adjacency):
            recursive = len(component) > 1
            # Skip isolated TUs: preserve the original lazy intra-TU path.
            needed = any(adjacency[path] for path in component) or bool(set(component) & depended_on)
            if not needed:
                continue
            converged = not recursive
            for iteration in range(1, (self.max_rounds if recursive else 1) + 1):
                snapshot = dict(self.outputs)
                updates = {path: self._evaluate(path, self._imports(path, snapshot)) for path in component}
                converged = not recursive or all(snapshot.get(path) == value for path, value in updates.items())
                self.outputs.update(updates)
                if converged:
                    break
            self.iterations[component] = iteration
            if not converged:
                # Discard the component's exports AND imports. Downstream TUs
                # see ordinary unresolved calls, never a partial safety proof.
                self.diagnostics.append(f"PROJECT_CONVERGENCE_LIMIT: {', '.join(component)}: {self.max_rounds} rounds; cross-TU summaries omitted")
                for path in component:
                    self.outputs.pop(path, None)
                    self.contexts[path].project_summaries = {}
                    self.contexts[path].analysis_session = AnalysisSession(self.contexts[path], semantic_models=self.semantic_models)
        return self


def prepare_project(files, config_for_file, profiles=None):
    """Parse each TU/profile once and return per-file worker inputs + diagnostics."""
    prepared = defaultdict(dict)
    groups = defaultdict(dict)
    models = {}
    diagnostics = []
    for path in sorted(set(files)):
        config = config_for_file(path)
        if config.engine_mode == AnalysisEngine.REGEX:
            continue
        registries = [getattr(rule, "_semantic_models", EMPTY_SEMANTIC_MODELS) for rule in config.get_rules()]
        registry = next((r for r in registries if r != EMPTY_SEMANTIC_MODELS), EMPTY_SEMANTIC_MODELS)
        if any(r != EMPTY_SEMANTIC_MODELS and r != registry for r in registries):
            diagnostics.append(f"INCOMPATIBLE_MODELS: {path}; cross-TU summaries omitted")
            continue
        # Registry equality, not repr/order or a mutable process-global cache.
        model_id = next((key for key, value in models.items() if value == registry), len(models))
        models[model_id] = registry
        for flags in ([p.flags for p in profiles] if profiles else [config.defined_syms]):
            key = profile_key(flags)
            if key in prepared[path]:
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as stream:
                    source = stream.read()
                resolver = IncludeResolver(include_roots=config.include_roots, base_dir=os.path.dirname(os.path.abspath(path)))
                expanded = TUIncludeExpander(resolver=resolver, defined_syms=flags).expand(source, source_path=path)
                ctx = CASTParser().parse(expanded.expanded_text, defined_syms=flags)
                prepared[path][key] = PreparedUnit(source, expanded, ctx)
                if ctx.has_pycparser and ctx.pycparser_ast is not None:
                    roots = tuple(os.path.normcase(os.path.realpath(p)) for p in config.include_roots)
                    groups[(key, roots, model_id)][path] = ctx
            except Exception as exc:
                # Normal file scanning retains its established error reporting.
                diagnostics.append(f"PROJECT_PREPARATION_FAILED: {path}: {exc}; cross-TU summaries omitted")
    for (_, _, model_id), contexts in groups.items():
        if len(contexts) < 2:
            continue
        try:
            index = ProjectSummaryIndex(contexts, models[model_id]).build()
            diagnostics.extend(index.diagnostics)
        except Exception as exc:
            # Do not leave partially evaluated safety proofs attached if any
            # existing domain fails on this configuration. The file scan will
            # still report its ordinary rule/parser failures independently.
            for ctx in contexts.values():
                ctx.project_summaries = {}
                ctx.analysis_session = None
            diagnostics.append(f"PROJECT_ANALYSIS_FAILED: {exc}; cross-TU summaries omitted")
    return dict(prepared), tuple(sorted(diagnostics))
