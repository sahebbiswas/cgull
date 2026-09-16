"""Deterministic, bounded project preparation across process counts."""
from concurrent.futures import Future, ProcessPoolExecutor
import multiprocessing

import pytest

from cgull import CGullScanner
from cgull.models import ConfigProfile, ScanConfig, ScanMode
from cgull import project_analysis as project


def _sources(tmp_path):
    sources = {
        'caller.c': 'void release(void *); void caller(void *p) { release(p); }',
        'callee.c': 'void free(void *); void release(void *p) { free(p); }',
        'bad.c': 'this is not valid C syntax !!!',
        'other.c': 'char *gets(char *); void other(void) { char buf[8]; gets(buf); }',
    }
    for name, text in sources.items():
        (tmp_path / name).write_text(text)
    return [str(tmp_path / name) for name in sources]


def _snapshot(units):
    return {path: {key: (unit.expanded.expanded_text, unit.context.parser_status,
                        unit.context.parse_attempts,
                        getattr(unit.context, 'project_summaries', {}))
                   for key, unit in profiles.items()}
            for path, profiles in units.items()}


@pytest.mark.parametrize('jobs', [2, 4, 0])
def test_prepared_summaries_and_degradation_match_sequential(tmp_path, jobs):
    files = _sources(tmp_path) + [str(tmp_path / 'missing.c')]
    config = ScanConfig.create()
    profiles = [ConfigProfile(name='base', flags={}),
                ConfigProfile(name='feature', flags={'FEATURE': None})]
    baseline, errors = project.prepare_project(files, lambda _: config, profiles)
    actual, actual_errors = project.prepare_project(files[::-1], lambda _: config, profiles, jobs=jobs)
    assert actual_errors == errors
    assert any('missing.c' in error for error in errors)
    assert _snapshot(actual) == _snapshot(baseline)
    caller = actual[str(tmp_path / 'caller.c')][()]
    assert caller.context.project_summaries['function']['release'].freed_params == {0}


def test_spawn_preparation_and_reuse(tmp_path, monkeypatch):
    files = _sources(tmp_path)
    config = ScanConfig.create()
    monkeypatch.setattr(project, 'ProcessPoolExecutor',
                        lambda **kw: ProcessPoolExecutor(mp_context=multiprocessing.get_context('spawn'), **kw))
    units, _ = project.prepare_units(files, lambda _: config, jobs=2)
    assert all(unit._context is not None for values in units.values() for unit in values.values())
    monkeypatch.setattr(project, 'ProcessPoolExecutor', lambda **kw: pytest.fail('already prepared'))
    reused, _ = project.prepare_project(files, lambda _: config, prepared_units=units, jobs=2)
    assert all(reused[path][()] is units[path][()] for path in files)


def test_reverse_completion_is_bounded_and_deterministic(tmp_path, monkeypatch):
    files = _sources(tmp_path)
    config = ScanConfig.create()
    baseline, errors = project.prepare_project(files, lambda _: config)
    completions = []
    outstanding = set()

    class Executor:
        def __init__(self, max_workers, **kwargs):
            self.limit = max_workers
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, fn, *args):
            future = Future()
            future.task = (fn, args)
            outstanding.add(future)
            assert len(outstanding) <= self.limit
            return future

    def reverse_wait(pending, **kwargs):
        future = max(pending, key=lambda f: f.task[1][0])
        fn, args = future.task
        completions.append(args[0])
        future.set_result(fn(*args))
        outstanding.remove(future)
        return {future}, set(pending) - {future}

    monkeypatch.setattr(project, 'ProcessPoolExecutor', Executor)
    monkeypatch.setattr(project, 'wait', reverse_wait)
    units, actual_errors = project.prepare_project(files, lambda _: config, jobs=2)
    assert completions != sorted(files)
    assert list(units) == sorted(files)
    assert actual_errors == errors
    assert _snapshot(units) == _snapshot(baseline)


@pytest.mark.parametrize("failure", ["submit", "result"])
def test_broken_pool_retries_healthy_sources(tmp_path, monkeypatch, failure):
    files = _sources(tmp_path)
    config = ScanConfig.create()

    class BrokenExecutor:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, *args):
            if failure == 'submit':
                raise RuntimeError('broken pool')
            future = Future()
            future.set_exception(RuntimeError('broken worker'))
            return future

    monkeypatch.setattr(project, 'ProcessPoolExecutor', BrokenExecutor)
    units, errors = project.prepare_project(files, lambda _: config, jobs=2)
    baseline, baseline_errors = project.prepare_project(files, lambda _: config)
    assert errors == baseline_errors
    assert _snapshot(units) == _snapshot(baseline)


@pytest.mark.parametrize('mode', [ScanMode.FILE, ScanMode.TU])
def test_scan_findings_and_parser_states_match(tmp_path, mode):
    _sources(tmp_path)
    config = ScanConfig.create(mode=mode)
    def scan(jobs):
        result = CGullScanner(config=config).scan_path(str(tmp_path), jobs=jobs, quiet=True)
        return ([(i.rule_id, i.file_path, i.line_number, i.message) for i in result.issues],
                result.analysis_status_counts,
                [(f.file_path, f.parser, f.parse_tier) for f in result.file_summaries])
    assert scan(1) == scan(2) == scan(4) == scan(0)


def test_parse_exception_does_not_drop_healthy_units(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    files = _sources(tmp_path)
    config = ScanConfig.create()
    original = project.CASTParser.parse

    def parse(self, source, *args, **kwargs):
        if 'not valid C' in source:
            raise RuntimeError('injected parser failure')
        return original(self, source, *args, **kwargs)

    # Each task still constructs its own parser; threads keep the injected
    # failure portable without depending on fork inheritance.
    monkeypatch.setattr(project.CASTParser, 'parse', parse)
    monkeypatch.setattr(project, 'ProcessPoolExecutor',
                        lambda max_workers, **kw: ThreadPoolExecutor(max_workers=max_workers))
    units, errors = project.prepare_project(files, lambda _: config, jobs=2)
    _, baseline_errors = project.prepare_project(files, lambda _: config)
    assert errors == baseline_errors
    assert any('injected parser failure' in error for error in errors)
    assert units[str(tmp_path / 'caller.c')][()].context.project_summaries['function']['release'].freed_params == {0}
