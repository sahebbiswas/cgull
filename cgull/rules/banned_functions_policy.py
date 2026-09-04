"""Explicit CGULL-001 policy boundary and conservative data-dependent refinement."""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Dict, List, Optional, Tuple

from .banned_functions import BannedFunctionsRule as _LegacyBannedFunctionsRule
from ..models import FixType, Issue, Severity


class BannedFunctionPolicy(str, Enum):
    """Policy class for a CGULL-001 function entry."""

    UNCONDITIONAL = "unconditional"
    DATA_DEPENDENT = "data-dependent"


@dataclass(frozen=True)
class BannedFunctionPolicyEntry:
    policy: BannedFunctionPolicy
    reason: str


class BannedFunctionsRule(_LegacyBannedFunctionsRule):
    """CGULL-001 with an explicit policy/dataflow boundary.

    Unconditional bans are always reported and semantic evidence may only
    describe the finding; it cannot suppress or downgrade it. Data-dependent
    entries may use semantic evidence to refine whether a finding is emitted.
    """

    POLICY: Dict[str, BannedFunctionPolicyEntry] = {
        "gets": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "No call form provides a destination bound.",
        ),
        "strcpy": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "The API has no destination-capacity parameter and remains fragile even when one call is currently bounded.",
        ),
        "strcat": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "The API has no destination-capacity parameter for the resulting string.",
        ),
        "sprintf": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "The API provides no output bound.",
        ),
        "vsprintf": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "The API provides no output bound.",
        ),
        "scanf": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.DATA_DEPENDENT,
            "String-input risk depends on whether the format contains an unbounded %s conversion.",
        ),
        "mktemp": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "Name generation and later open are intrinsically race-prone.",
        ),
        "tmpnam": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "Name generation and later open are intrinsically race-prone.",
        ),
        "tempnam": BannedFunctionPolicyEntry(
            BannedFunctionPolicy.UNCONDITIONAL,
            "Name generation and later open are intrinsically race-prone.",
        ),
    }

    _UNBOUNDED_SCANF_STRING = re.compile(r'%(?:\*)?(?!\d)[^%\s]*s')
    _STRING_LITERAL = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*$')

    def __init__(self, extra_banned_funcs: Optional[dict] = None):
        super().__init__(extra_banned_funcs=extra_banned_funcs)
        self.policy = dict(self.POLICY)
        if extra_banned_funcs:
            for fn_name, details in extra_banned_funcs.items():
                requested = None
                if isinstance(details, dict):
                    requested = details.get("policy")
                policy = BannedFunctionPolicy.UNCONDITIONAL
                if requested == BannedFunctionPolicy.DATA_DEPENDENT.value:
                    policy = BannedFunctionPolicy.DATA_DEPENDENT
                self.policy[fn_name] = BannedFunctionPolicyEntry(
                    policy,
                    "Project-configured ban; unconditional unless configuration explicitly marks it data-dependent.",
                )

    @staticmethod
    def _call_name(issue: Issue, known_names) -> Optional[str]:
        snippet = issue.code_snippet or ""
        for name in known_names:
            if re.search(rf'\b{re.escape(name)}\s*\(', snippet):
                return name
        return None

    @staticmethod
    def _policy_evidence(entry: BannedFunctionPolicyEntry, evidence: str) -> str:
        return f"policy={entry.policy.value}; policy_reason={entry.reason}; evidence={evidence}"

    def _annotate_issue(self, issue: Issue, fn_name: str, evidence: str) -> Issue:
        entry = self.policy[fn_name]
        issue.message = f"{issue.message} [{self._policy_evidence(entry, evidence)}]"
        if entry.policy is BannedFunctionPolicy.UNCONDITIONAL:
            # Semantic evidence must never make an unconditional policy ban
            # appear safe or lower priority.
            issue.impact = self.impact
        return issue

    @classmethod
    def _literal_scanf_status(cls, expr: str) -> Optional[bool]:
        """Return True for unbounded %s, False for proven-safe literal, None if unknown."""
        match = cls._STRING_LITERAL.fullmatch(expr.strip())
        if not match:
            return None
        content = match.group(1)
        return bool(cls._UNBOUNDED_SCANF_STRING.search(content))

    @staticmethod
    def _line_for_offset(source: str, offset: int) -> int:
        return source.count("\n", 0, offset) + 1

    @staticmethod
    def _matching_paren(source: str, open_paren: int) -> Optional[int]:
        depth = 0
        in_string = False
        escaped = False
        for idx in range(open_paren, len(source)):
            ch = source[idx]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return idx
        return None

    def _local_format_literal(
        self,
        variable: str,
        line_number: int,
        source_lines: List[str],
    ) -> Optional[str]:
        assign = re.compile(
            rf'\b{re.escape(variable)}\s*(?:\[[^\]]*\])?\s*=\s*("(?:[^"\\]|\\.)*")'
        )
        for line in reversed(source_lines[: max(0, line_number - 1)]):
            match = assign.search(line)
            if match:
                return match.group(1)
        return None

    def _enclosing_function_parameter(
        self,
        full_code: str,
        line_number: int,
        variable: str,
    ) -> Optional[Tuple[str, int]]:
        header = re.compile(
            r'\b([A-Za-z_]\w*)\s*\(([^{};]*)\)\s*\{',
            re.DOTALL,
        )
        best = None
        for match in header.finditer(full_code):
            start_line = self._line_for_offset(full_code, match.start())
            if start_line > line_number:
                break
            open_brace = full_code.find('{', match.start(), match.end())
            if open_brace < 0:
                continue
            depth = 0
            end = None
            for idx in range(open_brace, len(full_code)):
                if full_code[idx] == '{':
                    depth += 1
                elif full_code[idx] == '}':
                    depth -= 1
                    if depth == 0:
                        end = idx
                        break
            if end is None or line_number > self._line_for_offset(full_code, end):
                continue
            params = [part.strip() for part in match.group(2).split(',')]
            for param_index, param in enumerate(params):
                if re.search(rf'\b{re.escape(variable)}\b(?:\s*\[[^\]]*\])?\s*$', param):
                    best = (match.group(1), param_index)
                    break
        return best

    def _caller_format_status(
        self,
        full_code: str,
        function_name: str,
        param_index: int,
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
                # Function definition, not a call site.
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
        if statuses and not saw_unknown:
            return False, "all observed callers pass bounded literal formats across the helper boundary"
        return None, "caller format could not be proven bounded; conservative fallback retained"

    def _scanf_status(
        self,
        fmt_expr: str,
        full_code: str,
        line_number: int,
        source_lines: List[str],
    ) -> Tuple[Optional[bool], str]:
        direct = self._literal_scanf_status(fmt_expr)
        if direct is not None:
            if direct:
                return True, "direct literal contains an unbounded %s conversion"
            return False, "direct literal format has no unbounded %s conversion"

        identifier = re.fullmatch(r'\s*([A-Za-z_]\w*)\s*', fmt_expr)
        if not identifier:
            return None, "non-literal format expression is not provably bounded"
        variable = identifier.group(1)

        local_literal = self._local_format_literal(variable, line_number, source_lines)
        if local_literal is not None:
            status = self._literal_scanf_status(local_literal)
            if status:
                return True, "local format variable resolves to a literal with unbounded %s"
            return False, "local format variable resolves to a bounded literal"

        parameter = self._enclosing_function_parameter(full_code, line_number, variable)
        if parameter is not None:
            return self._caller_format_status(full_code, parameter[0], parameter[1])
        return None, "format provenance is unknown; conservative fallback retained"

    def _scanf_issue(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        column_number: int,
        evidence: str,
    ) -> Issue:
        reason, fix = self.banned_funcs["scanf"]
        issue = self.create_issue(
            file_path=file_path,
            line_number=line_number,
            code_snippet=line_content,
            message=f"Insecure function call 'scanf': {reason}",
            column_number=column_number,
            engine="Regex",
            fix_type=FixType.SUGGESTED_FIX,
            suggested_fix_replacement=fix,
        )
        return self._annotate_issue(issue, "scanf", evidence)

    def scan_line(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        full_code: str,
        source_lines: List[str],
        masked_line_content: str = "",
    ) -> List[Issue]:
        if line_content.lstrip().startswith('#'):
            return []

        inherited = super().scan_line(
            file_path,
            line_number,
            line_content,
            full_code,
            source_lines,
            masked_line_content,
        )

        annotated: List[Issue] = []
        for issue in inherited:
            fn_name = self._call_name(issue, self.policy)
            if fn_name is None:
                annotated.append(issue)
                continue
            if fn_name == "scanf":
                # Re-evaluate scanf below so direct, local, and interprocedural
                # evidence use one conservative data-dependent path.
                continue
            annotated.append(
                self._annotate_issue(
                    issue,
                    fn_name,
                    "semantic facts are descriptive only for an unconditional policy ban",
                )
            )

        match_target = masked_line_content or line_content
        scanf_match = re.search(r'\bscanf\s*\(', match_target)
        if not scanf_match or "scanf" not in self.banned_funcs:
            return annotated

        args = self._extract_call_args(line_content, scanf_match.end() - 1)
        if not args:
            annotated.append(
                self._scanf_issue(
                    file_path,
                    line_number,
                    line_content,
                    scanf_match.start() + 1,
                    "arguments could not be parsed; conservative fallback retained",
                )
            )
            return annotated

        status, evidence = self._scanf_status(args[0], full_code, line_number, source_lines)
        if status is False:
            return annotated

        annotated.append(
            self._scanf_issue(
                file_path,
                line_number,
                line_content,
                scanf_match.start() + 1,
                evidence,
            )
        )
        return annotated
