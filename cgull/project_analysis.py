"""Scan-local direct-call summary indexing without combining translation units.

The existing TU engines own all transfer semantics. A callee-first TU graph
supplies their external inputs; recursive TU components use snapshot rounds.
"""
from __future__ import annotations

from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from types import SimpleNamespace
from dataclasses import dataclass
from itertools import chain
import os

from pycparser import c_ast

from .analysis_requirements import (
    normalize_project_summary_domains,
    project_summary_domains,
    required_analysis_for_rules,
)
from .analysis_session import AnalysisSession
from .ast_analyzer import CASTParser
from .cfg.call_graph import _bottom_up_scc_order, _strongly_connected_components
from .cfg.security_dataflow import analyze_security_summaries
from .cfg.value_facts import analyze_value_summaries_detailed
from .includes import IncludeResolver, TUIncludeExpander
from .logging_config import multiprocessing_logging_context
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
    _context: object = None
    preparation_key: object = None
    parse_flags: object = None
    parse_enabled: bool = True

    @property
    def context(self):
        if self._context is None and self.parse_enabled:
            self._context = CASTParser().parse(
                self.expanded.expanded_text,
                defined_syms=self.parse_flags,
            )
        return self._context

    @context.setter
    def context(self, value):
        self._context = value


def _include_roots_key(config):
    return tuple(os.path.normcase(os.path.realpath(path)) for path in config.include_roots)


def _preparation_key(config, flags):
    """Identity for a scan-local expansion/parse result."""
    engine_mode = getattr(config.engine_mode, "value", config.engine_mode)
    return profile_key(flags), _include_roots_key(config), engine_mode


def _profile_flags(config, profiles):
    return [profile.flags for profile in profiles] if profiles else [config.defined_syms]


def _prepare_units_sequential(files, config_for_file, profiles=None, prepared_units=None):
    """Expand each requested file/profile at most once for this scan.

    ``prepared_units`` is scan-local state from an earlier phase (for example TU
    root preparation used for orphan-header classification). Compatible entries
    are reused verbatim; incompatible configuration/profile identities are
    replaced. AST parsing stays lazy so project preparation and single-file
    analysis retain their existing phase/timing ownership.
    """
    prepared = defaultdict(dict)
    for path, units in (prepared_units or {}).items():
        prepared[path].update(units)

    diagnostics = []
    for path in sorted(set(files)):
        config = config_for_file(path)
        source = next((unit.source for unit in prepared[path].values()), None)

        for flags in _profile_flags(config, profiles):
            key = profile_key(flags)
            expected_key = _preparation_key(config, flags)
            existing = prepared[path].get(key)
            if existing is not None and getattr(existing, "preparation_key", None) == expected_key:
                continue

            try:
                if source is None:
                    with open(path, encoding="utf-8", errors="replace") as stream:
                        source = stream.read()
                resolver = IncludeResolver(
                    include_roots=config.include_roots,
                    base_dir=os.path.dirname(os.path.abspath(path)),
                )
                expanded = TUIncludeExpander(
                    resolver=resolver,
                    defined_syms=flags,
                ).expand(source, source_path=path)
                prepared[path][key] = PreparedUnit(
                    source,
                    expanded,
                    None,
                    expected_key,
                    dict(flags or {}),
                    config.engine_mode != AnalysisEngine.REGEX,
                )
            except Exception as exc:
                # Normal file scanning retains its established error reporting
                # and will retry when no compatible prepared unit is available.
                diagnostics.append(
                    f"PROJECT_PREPARATION_FAILED: {path}: {exc}; cross-TU summaries omitted"
                )

    return dict(prepared), tuple(sorted(set(diagnostics)))


def _initialize_preparation_worker(log_queue, level):
    import logging
    from logging.handlers import QueueHandler

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.addHandler(QueueHandler(log_queue) if log_queue is not None else logging.NullHandler())
    root.setLevel(level)


def _prepare_source(path, include_roots, engine_mode, flags, existing, parse):
    """Process entry point; never send rules, callbacks, or parser state."""
    config = SimpleNamespace(include_roots=include_roots, engine_mode=engine_mode)
    profiles = [SimpleNamespace(flags=value) for value in flags]
    prepared, diagnostics = _prepare_units_sequential(
        [path], lambda _: config, profiles, {path: existing},
    )
    diagnostics = list(diagnostics)
    if parse:
        for unit in prepared[path].values():
            try:
                unit.context
            except Exception as exc:
                diagnostics.append(
                    f"PROJECT_PREPARATION_FAILED: {path}: {exc}; cross-TU summaries omitted"
                )
    return prepared[path], diagnostics


def prepare_units(files, config_for_file, profiles=None, prepared_units=None, *, jobs=1):
    """Prepare independent sources with at most one outstanding task per worker.

    Workers own their parser and preprocessor. Completed ASTs cross IPC once,
    before any CFG/session caches exist. The coordinator retains the prepared
    set needed by cross-TU indexing, but never queues an unbounded second set
    of serialized results. Existing compatible units are reused without IPC.
    Multi-worker preparation parses submitted sources eagerly and evaluates each
    unit.context before returning; the sequential path retains lazy parsing.
    """
    if jobs < 0:
        raise ValueError("jobs must be non-negative")
    paths = sorted(set(files))
    workers = min((os.cpu_count() or 1) if jobs == 0 else jobs, len(paths))
    if workers <= 1:
        return _prepare_units_sequential(paths, config_for_file, profiles, prepared_units)

    prepared = {path: dict(units) for path, units in (prepared_units or {}).items()}
    diagnostics = []

    def tasks():
        for path in paths:
            config = config_for_file(path)
            flags = _profile_flags(config, profiles)
            existing = prepared.setdefault(path, {})
            # Only missing/incompatible or not-yet-parsed units need a worker.
            pending = [value for value in flags if (
                (unit := existing.get(profile_key(value))) is None
                or unit.preparation_key != _preparation_key(config, value)
                or (unit.parse_enabled and unit._context is None)
            )]
            if pending:
                reusable = {profile_key(value): existing[profile_key(value)]
                            for value in pending if profile_key(value) in existing}
                yield (path, tuple(config.include_roots), config.engine_mode,
                       pending, reusable, True)

    iterator = iter(tasks())
    # Avoid starting a pool at all when discovery already prepared every TU.
    first = next(iterator, None)
    if first is None:
        return dict(sorted(prepared.items())), ()
    iterator = iter(chain((first,), iterator))
    with multiprocessing_logging_context() as (log_queue, level), ProcessPoolExecutor(
        max_workers=workers,
        initializer=_initialize_preparation_worker,
        initargs=(log_queue, level),
    ) as pool:
        pending = {}
        exhausted = False
        while pending or not exhausted:
            while len(pending) < workers and not exhausted:
                task = next(iterator, None)
                if task is None:
                    exhausted = True
                    break
                try:
                    pending[pool.submit(_prepare_source, *task)] = task
                except Exception:
                    # A broken pool must not prevent unrelated TUs from being
                    # prepared. Fall back to the same isolated source routine.
                    units, errors = _prepare_source(*task)
                    prepared[task[0]].update(units)
                    diagnostics.extend(errors)
            if not pending:
                continue
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                task = pending.pop(future)
                try:
                    units, errors = future.result()
                except Exception:
                    units, errors = _prepare_source(*task)
                prepared[task[0]].update(units)
                diagnostics.extend(errors)
    return dict(sorted(prepared.items())), tuple(sorted(set(diagnostics)))


class ProjectSummaryIndex:
    """One exact preprocessor/include/model configuration; never process-global."""

    def __init__(
        self,
        contexts,
        semantic_models=EMPTY_SEMANTIC_MODELS,
        *,
        max_rounds=64,
        required_domains=None,
    ):
        if max_rounds < 1:
            raise ValueError("max_rounds must be positive")
        self.contexts = dict(sorted(contexts.items()))
        self.semantic_models = semantic_models
        self.max_rounds = max_rounds
        self.required_domains = normalize_project_summary_domains(required_domains)
        self.domain_evaluations = {domain: 0 for domain in DOMAINS}
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
        imports = {}
        for domain in self.required_domains:
            imported = {}
            for name, target in self.bindings[path].items():
                summaries = snapshot.get(target, {}).get(domain, {})
                summary = summaries.get(name)
                if summary is not None and self._exportable(domain, summary):
                    imported[name] = summary
            imports[domain] = imported
        return imports

    def _evaluate(self, path, imports):
        ctx = self.contexts[path]
        ctx.project_summaries = imports
        # Reset summary caches between rounds, retaining the original call graph.
        session = AnalysisSession(ctx, semantic_models=self.semantic_models)
        session._call_graph = self.sessions[path].call_graph
        self.sessions[path] = session
        ctx.analysis_session = session

        outputs = {}
        for domain in self.required_domains:
            self.domain_evaluations[domain] += 1
            if domain == "function":
                outputs[domain] = dict(session.function_summaries)
            elif domain == "ownership":
                outputs[domain] = dict(session.ownership_summaries)
            elif domain == "value":
                outputs[domain] = dict(
                    analyze_value_summaries_detailed(
                        ctx,
                        self.semantic_models,
                        call_graph=session.call_graph,
                    ).summaries
                )
            elif domain == "security":
                outputs[domain] = analyze_security_summaries(ctx, self.semantic_models)
        return outputs

    def build(self):
        if not self.required_domains:
            return self
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


def prepare_project(files, config_for_file, profiles=None, prepared_units=None, *, jobs=1):
    """Build cross-TU summaries from scan-local prepared units."""
    prepared, preparation_diagnostics = prepare_units(
        files,
        config_for_file,
        profiles,
        prepared_units=prepared_units,
        jobs=jobs,
    )
    groups = defaultdict(dict)
    group_requirements = defaultdict(set)
    models = {}
    diagnostics = list(preparation_diagnostics)

    for path in sorted(set(files)):
        config = config_for_file(path)
        if config.engine_mode == AnalysisEngine.REGEX:
            continue

        rules = config.get_rules()
        requirements = required_analysis_for_rules(rules)
        registries = [getattr(rule, "_semantic_models", EMPTY_SEMANTIC_MODELS) for rule in rules]
        registry = next((r for r in registries if r != EMPTY_SEMANTIC_MODELS), EMPTY_SEMANTIC_MODELS)
        if any(r != EMPTY_SEMANTIC_MODELS and r != registry for r in registries):
            diagnostics.append(f"INCOMPATIBLE_MODELS: {path}; cross-TU summaries omitted")
            continue

        # Registry equality, not repr/order or a mutable process-global cache.
        model_id = next((key for key, value in models.items() if value == registry), len(models))
        models[model_id] = registry
        roots = _include_roots_key(config)
        for flags in _profile_flags(config, profiles):
            key = profile_key(flags)
            unit = prepared.get(path, {}).get(key)
            if unit is None:
                continue
            try:
                ctx = unit.context
            except Exception as exc:
                diagnostics.append(
                    f"PROJECT_PREPARATION_FAILED: {path}: {exc}; cross-TU summaries omitted"
                )
                continue
            if ctx is not None and ctx.has_pycparser and ctx.pycparser_ast is not None:
                group_key = (key, roots, model_id)
                groups[group_key][path] = ctx
                group_requirements[group_key].update(requirements)

    for group_key, contexts in groups.items():
        if len(contexts) < 2:
            continue
        _, _, model_id = group_key
        required_domains = project_summary_domains(group_requirements[group_key])
        if not required_domains:
            continue
        try:
            index = ProjectSummaryIndex(
                contexts,
                models[model_id],
                required_domains=required_domains,
            ).build()
            diagnostics.extend(index.diagnostics)
        except Exception as exc:
            # Do not leave partially evaluated safety proofs attached if any
            # existing domain fails on this configuration. The file scan will
            # still report its ordinary rule/parser failures independently.
            for ctx in contexts.values():
                ctx.project_summaries = {}
                ctx.analysis_session = None
            diagnostics.append(f"PROJECT_ANALYSIS_FAILED: {exc}; cross-TU summaries omitted")

    return dict(prepared), tuple(sorted(set(diagnostics)))
