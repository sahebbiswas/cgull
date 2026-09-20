"""End-to-end profile selection and non-destructive report grouping."""

import json
from collections import Counter
from dataclasses import replace

from cgull.baseline import apply_baseline
from cgull.cli import main
from cgull.config import CGullConfig
from cgull.engine import CGullScanner
from cgull.finding_profiles import FOCUSED_SKIPS, with_finding_profile
from cgull.models import Severity
from cgull.reporter import ReportGenerator
from cgull.rules import get_all_rules


CODE = '''void f(char *p) {
    {work}
    goto done;
done:
    gets(p);
}
'''.replace('{work}', '\n    '.join(['puts(p);'] * 16))


def test_scan_profiles_preserve_security_and_comprehensive_policy(tmp_path, capsys):
    source = tmp_path / 'sample.c'
    source.write_text(CODE)
    outputs = {}
    for profile in (None, 'focused', 'comprehensive'):
        args = ['scan', str(source), '--no-log', '-q', '--format', 'json',
                '--config-strategy', 'baseline', '-j', '1']
        if profile:
            args += ['--profile', profile]
        assert main(args) == 0
        outputs[profile] = json.loads(capsys.readouterr().out)
    ids = {key: {i['rule_id'] for i in out['issues']} for key, out in outputs.items()}
    assert 'CGULL-018' in ids[None] & ids['comprehensive']
    assert 'CGULL-025' in ids[None] & ids['comprehensive']
    assert not ids['focused'] & FOCUSED_SKIPS.keys()
    assert 'CGULL-001' in ids['focused']
    assert outputs[None]['issues'] == outputs['comprehensive']['issues']
    assert ids['focused'] == ids[None] - FOCUSED_SKIPS.keys()


def test_rules_profile_matches_scan_and_retains_configuration(tmp_path, capsys):
    config = tmp_path / '.cgull.toml'
    config.write_text('[rules.skip]\n"CGULL-014" = "local policy"\n')
    for profile in ('focused', 'comprehensive'):
        assert main(['--no-log', 'rules', '-c', str(config), '--profile', profile]) == 0
        output = capsys.readouterr().out
        rows = {line.split('|')[0].strip(): line for line in output.splitlines() if line.startswith('CGULL-')}
        assert 'SKIPPED' in rows['CGULL-014']
        assert 'ACTIVE' in rows['CGULL-001']
        for rule_id in FOCUSED_SKIPS:
            assert ('SKIPPED' if profile == 'focused' else 'ACTIVE') in rows[rule_id]


def test_focused_exclusions_are_only_low_policy_rules_and_do_not_mutate_config():
    config = CGullConfig(skipped_rules={'CGULL-014': 'local policy'})
    selected = with_finding_profile(config, 'focused')
    assert config.skipped_rules == {'CGULL-014': 'local policy'}
    assert set(selected.skipped_rules) == set(FOCUSED_SKIPS) | {'CGULL-014'}
    rules = get_all_rules()
    assert all(r.impact == Severity.LOW for r in rules if r.rule_id in FOCUSED_SKIPS)
    assert all(r.rule_id not in FOCUSED_SKIPS for r in rules if r.impact in (Severity.HIGH, Severity.MEDIUM))


def test_group_counts_match_across_formats_and_use_reported_issues():
    result = CGullScanner().scan_text(CODE, 'sample.c')
    # Severity overrides must not move a policy rule into the security group.
    policy = replace(next(i for i in result.issues if i.rule_id == 'CGULL-018'), impact=Severity.HIGH)
    security = next(i for i in result.issues if i.rule_id == 'CGULL-001')
    result.issues = [policy, security]
    expected = {'security_correctness': 1, 'policy_quality': 1}
    assert json.loads(ReportGenerator.to_json(result, pretty=False))['summary']['finding_groups'] == expected
    sarif = json.loads(ReportGenerator.to_sarif(result))
    assert sarif['runs'][0]['invocations'][0]['properties']['findingGroups'] == expected
    text = ReportGenerator.to_terminal_text(result)
    assert 'Security/correctness: 1' in text
    assert 'Policy/quality      : 1' in text
    markdown = ReportGenerator.to_markdown(result)
    assert '| Security/correctness | 1 |' in markdown
    assert '| Policy/quality | 1 |' in markdown
    # After baseline filtering (or an empty scan), groups count only remaining rows.
    filtered = apply_baseline(result, Counter(i.fingerprint for i in result.issues))
    assert json.loads(ReportGenerator.to_json(filtered))['summary']['finding_groups'] == {
        'security_correctness': 0, 'policy_quality': 0,
    }


def test_policy_group_does_not_change_fail_on_or_severity_filter(tmp_path, capsys):
    source = tmp_path / 'goto.c'
    source.write_text("void f(void) { goto done; done: return; }\n")
    config = tmp_path / '.cgull.toml'
    config.write_text('[rules.severity]\n"CGULL-018" = "high"\n')
    args = ['scan', str(source), '-c', str(config), '--no-log', '-q', '-j', '1',
            '--config-strategy', 'baseline', '--severity', 'high', '--format', 'json',
            '--fail-on', 'high']
    assert main(args) == 1
    data = json.loads(capsys.readouterr().out)
    assert {i['rule_id'] for i in data['issues']} == {'CGULL-018'}
    assert data['summary']['finding_groups'] == {'security_correctness': 0, 'policy_quality': 1}
