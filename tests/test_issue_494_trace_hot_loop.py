"""TRACE must stay useful without disabled per-invocation logging calls."""
import logging
from unittest.mock import patch

import pytest

from cgull.engine import _scan_file_content, logger
from cgull.logging_config import TRACE_LEVEL_NUM
from cgull.models import AnalysisEngine
from cgull.rules import BaseRule


@pytest.mark.parametrize('mode', list(AnalysisEngine))
@pytest.mark.parametrize('level', [logging.WARNING, logging.DEBUG, TRACE_LEVEL_NUM])
def test_rule_trace_calls(mode, level, caplog):
    source = 'int f(void) {\n\nreturn 0;\n}\n'
    rules = [BaseRule(), BaseRule()]
    with caplog.at_level(level, logger=logger.name):
        with patch.object(logger, 'log', wraps=logger.log) as log:
            result = _scan_file_content(source, 'source.c', rules=rules, engine_mode=mode)
    assert result[5] == 'success'
    assert result[0] == []
    regex_count = 6 if mode in (AnalysisEngine.REGEX, AnalysisEngine.HYBRID) else 0
    ast_count = 2 if mode in (AnalysisEngine.AST, AnalysisEngine.HYBRID) else 0
    expected = regex_count + ast_count if level == TRACE_LEVEL_NUM else 0
    assert log.call_count == expected
    messages = [record.getMessage() for record in caplog.records if record.levelno == TRACE_LEVEL_NUM]
    assert len(messages) == expected
    if expected:
        assert sum('Executing regex rule CGULL-000 (Base Rule) on source.c:' in m for m in messages) == regex_count
        assert sum(m == 'Executing AST rule CGULL-000 (Base Rule) on source.c' for m in messages) == ast_count


def test_trace_enablement_is_refreshed_between_files(caplog):
    for level in (logging.WARNING, TRACE_LEVEL_NUM, logging.WARNING):
        with caplog.at_level(level, logger=logger.name):
            with patch.object(logger, 'log', wraps=logger.log) as log:
                _scan_file_content('int x;\n', 'source.c', rules=[BaseRule()], engine_mode=AnalysisEngine.REGEX)
        assert log.call_count == (1 if level == TRACE_LEVEL_NUM else 0)
