from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.conversion.base import TextQueryBackend, SpecialChars
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict, Tuple, Pattern, List, Union
from re import compile

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
    parenthesize: bool = True # put parentheses around all expressions since PowerShell is not strict about field precedence
    token_separator: ClassVar[str] = " "
    or_token: ClassVar[str] = "-or"
    and_token: ClassVar[str] = "-and"
    not_token: ClassVar[str] = "-not"
    eq_token: ClassVar[str] = " -eq "
    field_quote: ClassVar[str] = ""
    field_quote_pattern: ClassVar[Pattern] = compile("^\\w+$")
    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = False
    field_escape_pattern: ClassVar[Pattern] = compile("\\s")
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {True: "$true", False:"$false"}
    startswith_expression: ClassVar[str] = "{field} -like {value}"
    endswith_expression: ClassVar[str] = "{field} -like {value}"
    contains_expression: ClassVar[str] = "{field} -contains {value}"
    wildcard_match_expression: ClassVar[str] = "{field} -match {value}"
    re_expression: ClassVar[str] = '{field} -match "{regex}"'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ()
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

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (
                self.startswith_expression is not None
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[:-1].contains_special()
                ):
                expr = self.startswith_expression
                value = cond.value # this was originally "value = cond.value[:-1]"
            elif (
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
                ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
                ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (
                self.wildcard_match_expression is not None
                and cond.value.contains_special()
                ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr =  "{field}" + self.eq_token + "{value}"
                value = cond.value
            return expr.format(field=self.escape_and_quote_field(cond.field), value=self.convert_value_str(value, state))
        except TypeError:
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the backend.")

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
            filter = f'-FilterHashTable @{{LogName = "{rule.logsource.service}"; Id = {rule.eventid}}} | '
        else:
            filter = f'-LogName "{rule.logsource.service}" | '
        return "Get-WinEvent " + filter + f"Read-WinEvent | Where-Object {{{query}}}"

    def finalize_output_default(self, queries: List[str]) -> str:
        return list(queries)