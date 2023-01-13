from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict, Tuple, Pattern, List, Union
import re

class PowerShellBackend(TextQueryBackend):
    name: ClassVar[str] = "PowerShell backend"
    formats: Dict[str, str] = { 
        "default": "plain PowerShell queries",
        "script": "a PowerShell script",
        "xml": "XML documents",
        "xpath": "XML strings",
        "subscription": "Windows event subscriptions" 
    }
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"
    token_separator: str = " "
    or_token: ClassVar[str] = "-or"
    and_token: ClassVar[str] = "-and"
    not_token: ClassVar[str] = "-not"
    eq_token: ClassVar[str] = " -eq "
    field_quote: ClassVar[str] = ""
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")
    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = False
    field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {True: "$true", False:"$false"}
    startswith_expression: ClassVar[str] = "{field} -like {value}*"
    endswith_expression: ClassVar[str] = "endswith"
    contains_expression: ClassVar[str] = "{field} -contains {value}"
    wildcard_match_expression: ClassVar[str] = "{field} -match {value}"
    re_expression: ClassVar[str] = "{field} =~ {regex}"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ()
    cidr_wildcard: ClassVar[str] = "*"
    cidr_expression: ClassVar[str] = "cidrmatch({field}, {value})"
    cidr_in_list_expression: ClassVar[str] = "{field} -in ({value})"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "-lt",
        SigmaCompareExpression.CompareOperators.LTE: "-le",
        SigmaCompareExpression.CompareOperators.GT: "-gt",
        SigmaCompareExpression.CompareOperators.GTE: "-ge",
    }
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    deferred_start: ClassVar[str] = "\n| "
    deferred_separator: ClassVar[str] = "\n| "
    deferred_only_query: ClassVar[str] = "*"

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        if arg.__class__ in self.precedence:
            return self.not_token + self.token_separator + self.convert_condition_group(arg, state)
        else:
            expr = self.convert_condition(arg, state)
            if isinstance(expr, DeferredQueryExpression):
                return expr.negate()
            else:
                return f'{arg.field} -ne "{arg.value}"'

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        if hasattr(rule, "eventid"): 
            query_prefix = f'Get-WinEvent -FilterHashTable @{{LogName = "{rule.logsource.service}"; Id = {rule.eventid}}} | Read-WinEvent | '
        else:
            query_prefix = f'Get-WinEvent -LogName "{rule.logsource.service}" | Read-WinEvent | '
        return query_prefix + f"Where-Object {{{query}}}"

    def finalize_output_default(self, queries: List[str]) -> str:
        return list(queries)