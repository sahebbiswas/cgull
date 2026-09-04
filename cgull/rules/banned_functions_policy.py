"""Explicit CGULL-001 policy boundary and conservative data-dependent refinement."""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Dict, List, Optional, Tuple

from .banned_functions_legacy import BannedFunctionsRule as _LegacyBannedFunctionsRule
from ..models import FixType, Issue


class BannedFunctionPolicy(str, Enum):
    UNCONDITIONAL = "unconditional"
    DATA_DEPENDENT = "data-dependent"


@dataclass(frozen=True)
class BannedFunctionPolicyEntry:
    policy: BannedFunctionPolicy
    reason: str


class BannedFunctionsRule(_LegacyBannedFunctionsRule):
    """CGULL-001 with policy separated from semantic refinement."""

    POLICY: Dict[str, BannedFunctionPolicyEntry] = {
        "gets": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "No call form provides a destination bound."),
        "strcpy": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "No destination-capacity parameter; a currently bounded call remains fragile."),
        "strcat": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "No destination-capacity parameter for the resulting string."),
        "sprintf": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "No output-capacity parameter."),
        "vsprintf": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "No output-capacity parameter."),
        "scanf": BannedFunctionPolicyEntry(BannedFunctionPolicy.DATA_DEPENDENT, "Risk depends on whether the format contains an unbounded %s conversion."),
        "mktemp": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "Temporary-name generation followed by open is intrinsically race-prone."),
        "tmpnam": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "Temporary-name generation followed by open is intrinsically race-prone."),
        "tempnam": BannedFunctionPolicyEntry(BannedFunctionPolicy.UNCONDITIONAL, "Temporary-name generation followed by open is intrinsically race-prone."),
    }

    _STRING_LITERAL = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*$')
    _UNBOUNDED_SCANF_STRING = re.compile(r'%(?:\*)?(?!\d)[^%\s]*s')

    def __init__(self, extra_banned_funcs: Optional[dict] = None):
        super().__init__(extra_banned_funcs=extra_banned_funcs)
        self.policy = dict(self.POLICY)
        for fn_name, details in (extra_banned_funcs or {}).items():
            requested = details.get("policy") if isinstance(details, dict) else None
            kind = (
                BannedFunctionPolicy.DATA_DEPENDENT
                if requested == BannedFunctionPolicy.DATA_DEPENDENT.value
                else BannedFunctionPolicy.UNCONDITIONAL
            )
            self.policy[fn_name] = BannedFunctionPolicyEntry(
                kind,
                "Project-configured ban; unconditional unless configuration explicitly marks it data-dependent.",
            )

    @staticmethod
    def _policy_text(entry: BannedFunctionPolicyEntry, evidence: str) -> str:
        return f"policy={entry.policy.value}; policy_reason={entry.reason}; evidence={evidence}"

    def _annotate(self, issue: Issue, fn_name: str, evidence: str) -> Issue:
        entry = self.policy[fn_name]
        issue.message = f"{issue.message} [{self._policy_text(entry, evidence)}]"
        if entry.policy is BannedFunctionPolicy.UNCONDITIONAL:
            # Dataflow can explain an unconditional finding, never suppress or
            # downgrade the configured policy violation.
            issue.impact = self.impact
        return issue

    @classmethod
    def _literal_scanf_status(cls, expression: str) -> Optional[bool]:
        """True = unsafe, False = proven bounded, None = not a literal."""
        match = cls._STRING_LITERAL.fullmatch(expression.strip())
        if not match:
            return None
        return bool(cls._UNBOUNDED_SCANF_STRING.search(match.group(1)))

    def _local_literal(self, variable: str, line_number: int, source_lines: List[str]) -> Optional[str]:
        assignment = re.compile(
            rf'\b{re.escape(variable)}\s*(?:\[[^\]]*\])?\s*=\s*("(?:[^"\\]|\\.)*")'
        )
        for line in reversed(source_lines[: max(0, line_number - 1)]):
            match = assignment.search(line)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _line_at(source: str, offset: int) -> int:
        return source.count("\n", 0, offset) + 1

    @staticmethod
    def _matching_paren(source: str, open_paren: int) -> Optional[int]:
        depth = 0
        in_string = False
        escaped = False
        for index in range(open_paren, len(source)):
            char = source[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _enclosing_parameter(
        self,
        full_code: str,
        line_number: int,
        variable: str,
    ) -> Optional[Tuple[str, int, bool]]:
        header = re.compile(r'\b([A-Za-z_]\w*)\s*\(([^{};]*)\)\s*\{', re.DOTALL)
        for match in header.finditer(full_code):
            start_line = self._line_at(full_code, match.start())
            if start_line > line_number:
                break
            open_brace = full_code.find('{', match.start(), match.end())
            depth = 0
            end = None
            for index in range(open_brace, len(full_code)):
                if full_code[index] == '{':
                    depth += 1
                elif full_code[index] == '}':
                    depth -= 1
                    if depth == 0:
                        end = index
                        break
            if end is None or line_number > self._line_at(full_code, end):
                continue

            # The helper's linkage is part of the proof boundary. In-file call
            # enumeration is exhaustive only for an internal-linkage function.
            declaration_start = max(
                full_code.rfind(';', 0, match.start()),
                full_code.rfind('{', 0, match.start()),
                full_code.rfind('}', 0, match.start()),
            ) + 1
            declaration_prefix = full_code[declaration_start:match.start()]
            is_static = bool(re.search(r'\bstatic\b', declaration_prefix))

            params = [part.strip() for part in match.group(2).split(',')]
            for param_index, param in enumerate(params):
                if re.search(rf'\b{re.escape(variable)}\b(?:\s*\[[^\]]*\])?\s*$', param):
                    return match.group(1), param_index, is_static
        return None

    def _caller_status(
        self,
        full_code: str,
        function_name: str,
        param_index: int,
        internal_linkage: bool,
    ) -> Tuple[Optional[bool], str]:
        statuses: List[bool] = []
        saw_unknown = False
        for match in re.finditer(rf'\b{re.escape(function_name)}\s*\(', full_code):
            open_paren = full_code.find('(', match.start(), match.end())
            close_paren = self._matching_paren(full_code, open_paren)
            if close_paren is None:
                saw_unknown = True
                continue
            if re.match(r'\s*\{', full_code[close_paren + 1:]):
                continue
            args = self._extract_call_args(full_code, open_paren)
            if not args or param_index >= len(args):
                saw_unknown = True
                continue
            status = self._literal_scanf_status(args[param_index])
            if status is None:
                saw_unknown = True
            else:
                statuses.append(status)
        if any(statuses):
            return True, "at least one caller passes a literal with an unbounded %s conversion"
        if statuses and not saw_unknown and internal_linkage:
            return False, "all observed callers of the static helper pass bounded literal formats"
        if statuses and not saw_unknown:
            return None, "externally visible helper may have callers outside this translation unit; conservative fallback retained"
        return None, "caller format could not be proven bounded; conservative fallback retained"

    def _scanf_status(self, fmt_expr: str, full_code: str, line_number: int, source_lines: List[str]) -> Tuple[Optional[bool], str]:
        direct = self._literal_scanf_status(fmt_expr)
        if direct is not None:
            return direct, (
                "direct literal contains an unbounded %s conversion"
                if direct
                else "direct literal format has no unbounded %s conversion"
            )
        identifier = re.fullmatch(r'\s*([A-Za-z_]\w*)\s*', fmt_expr)
        if not identifier:
            return None, "non-literal format expression is not provably bounded"
        variable = identifier.group(1)
        local = self._local_literal(variable, line_number, source_lines)
        if local is not None:
            status = self._literal_scanf_status(local)
            return status, (
                "local format variable resolves to an unbounded literal"
                if status
                else "local format variable resolves to a bounded literal"
            )
        parameter = self._enclosing_parameter(full_code, line_number, variable)
        if parameter:
            return self._caller_status(full_code, parameter[0], parameter[1], parameter[2])
        return None, "format provenance is unknown; conservative fallback retained"

    @staticmethod
    def _is_scanf_declaration(line_content: str) -> bool:
        return bool(re.match(
            r'^\s*(?!(?:return|if|while|for|switch|else)\b)'
            r'(?:(?:extern|static|inline|const|volatile|unsigned|signed|short|long|char|int|void|double|float|\w+)\s*|\*\s*)+'
            r'\bscanf\s*\([^;{}]*\)\s*;?\s*$',
            line_content,
        ))

    def _callee_for_issue(self, issue: Issue, line_content: str) -> Optional[str]:
        """Resolve the legacy issue using its column in the original source line."""
        call_offset = max(0, issue.column_number - 1)
        for fn_name in self.policy:
            if re.match(rf'{re.escape(fn_name)}\s*\(', line_content[call_offset:]):
                return fn_name
        return None

    def _make_scanf_issue(self, file_path: str, line_number: int, line_content: str, column: int, evidence: str) -> Issue:
        reason, fix = self.banned_funcs["scanf"]
        issue = self.create_issue(
            file_path=file_path,
            line_number=line_number,
            code_snippet=line_content,
            message=f"Insecure function call 'scanf': {reason}",
            column_number=column,
            engine="Regex",
            fix_type=FixType.SUGGESTED_FIX,
            suggested_fix_replacement=fix,
        )
        return self._annotate(issue, "scanf", evidence)

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        if line_content.lstrip().startswith('#'):
            return []
        inherited = super().scan_line(file_path, line_number, line_content, full_code, source_lines, masked_line_content)
        issues: List[Issue] = []
        for issue in inherited:
            fn_name = self._callee_for_issue(issue, line_content)
            if fn_name is None:
                issues.append(issue)
            elif fn_name != "scanf":
                issues.append(self._annotate(issue, fn_name, "semantic facts are descriptive only for an unconditional policy ban"))

        target = masked_line_content or line_content
        match = re.search(r'\bscanf\s*\(', target)
        if not match or "scanf" not in self.banned_funcs or self._is_scanf_declaration(line_content):
            return issues
        args = self._extract_call_args(line_content, match.end() - 1)
        if not args:
            issues.append(self._make_scanf_issue(file_path, line_number, line_content, match.start() + 1, "arguments could not be parsed; conservative fallback retained"))
            return issues
        status, evidence = self._scanf_status(args[0], full_code, line_number, source_lines)
        if status is not False:
            issues.append(self._make_scanf_issue(file_path, line_number, line_content, match.start() + 1, evidence))
        return issues
