from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.conversion.base import TextQueryBackend, SpecialChars
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict, Tuple, Pattern, List, Union
from re import compile

class PowerShellBackend(TextQueryBackend):
    """PowerShell backend."""
    name: ClassVar[str] = "PowerShell backend"
    formats: Dict[str, str] = { 
        "default": "plain PowerShell queries",
        "script": "a PowerShell script",
        "xml": "XML documents",
        "xpath": "XML strings",
        "subscription": "Windows event subscriptions" 
    }
    requires_pipeline: bool = False
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True 

    # Generated query tokens
    token_separator: ClassVar[str] = " " # separator inserted between all boolean operators
    or_token: ClassVar[str] = "-or"
    and_token: ClassVar[str] = "-and"
    not_token: ClassVar[str] = "-not"
    eq_token: ClassVar[str] = " -eq " # token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = ""
    field_quote_pattern: ClassVar[Pattern] = compile("^\\w+$")
    field_quote_pattern_negation : ClassVar[bool] = True # NEW

    ### Escaping
    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = False
    field_escape_pattern: ClassVar[Pattern] = compile("\\s")

    ## Values
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {True: "$true", False:"$false"}

    # String matching operators. if None is appropriate, eq_token is used.
    startswith_expression: ClassVar[str] = "{field} -like {value}"
    endswith_expression: ClassVar[str] = "{field} -like {value}"
    contains_expression: ClassVar[str] = "{field} -contains {value}"
    wildcard_match_expression: ClassVar[str] = "{field} -like {value}"

    # Regular expressions
    re_expression: ClassVar[str] = '{field} -match "{regex}"'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ()

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*" # Character used as single wildcard
    # cidr_expression: ClassVar[str] = "cidrmatch({field}, {value})" # CIDR expression query as format string with placeholders {field} = {value}
    # cidr_in_list_expression: ClassVar[str] = "{field} in ({value})" # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "-lt",
        SigmaCompareExpression.CompareOperators.LTE: "-le",
        SigmaCompareExpression.CompareOperators.GT: "-gt",
        SigmaCompareExpression.CompareOperators.GTE: "-ge",
    }

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} is null"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = True # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = False # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator: ClassVar[str] = "-in" # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator: ClassVar[str] = "contains-all" # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'   # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = '_=~{value}'    # Expression for regular expression not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
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