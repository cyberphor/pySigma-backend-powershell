import re
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict, Tuple, Pattern, List, Union

class PowerShellBackend(TextQueryBackend):
    """Powershell backend."""
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "powershell backend"
    formats : Dict[str, str] = {
        "default": "Plain powershell queries"
    }
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    
    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "-or"
    and_token : ClassVar[str] = "-and"
    not_token : ClassVar[str] = "-not"
    eq_token : ClassVar[str] = " = "  # Token inserted between field and value (without separator)
    
    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = False         # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    
    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.
    
    ## Values
    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }
    
    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "startswith"
    endswith_expression   : ClassVar[str] = "endswith"
    contains_expression   : ClassVar[str] = "contains"
    wildcard_match_expression : ClassVar[str] = "match"      # Special expression if wildcards can't be matched with the eq_token operator
    
    # Regular expressions
    re_expression : ClassVar[str] = "{field}=~{regex}"  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    
    # cidr expressions
    cidr_wildcard : ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression : ClassVar[str] = "cidrmatch({field}, {value})"    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:        # group if AND or OR condition is negated
                return self.not_token + self.token_separator + self.convert_condition_group(arg, state)
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                    return expr.negate()
                else:                                             # convert negated expression to string
                    return '{field} -ne "{value}"'.format(field=arg.field, value=arg.value)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")
       
    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        try:
            service = windows_logsource_mapping[rule.logsource.service]
            query_prefix = f"Get-WinEvent -FilterHashTable @{{LogName='{service}'; Id=}} | Read-WinEvent | "
            #print(rule.to_dict().__getitem__("selection"))
            return ""#query_prefix + f"Where-Object {{ {query} }}"
        except:
            return f"Missing or invalid logsource: '{rule.logsource.service}'"

    def finalize_output_default(self, queries: List[str]) -> str:
        return list(queries)