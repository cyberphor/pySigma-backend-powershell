import re
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.pipelines.common import windows_logsource_mapping
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict, Tuple, Pattern, List, Union

class PowerShellBackend(TextQueryBackend):
    name : ClassVar[str] = "PowerShell backend"
    formats : Dict[str, str] = { 
        "default": "plain PowerShell queries",
        "script": "a PowerShell script",
        "xml": "XML documents",
        "xpath": "XML strings",
        "subscription": "Windows event subscriptions" 
    }
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    
    # Generated query tokens
    token_separator : str = " "
    or_token : ClassVar[str] = "-or"
    and_token : ClassVar[str] = "-and"
    not_token : ClassVar[str] = "-not"
    eq_token : ClassVar[str] = " = "
    
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
    bool_values     : ClassVar[Dict[bool, str]] = {True: "true", False:"false"}
    
    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "{field} -like {value}*"
    endswith_expression   : ClassVar[str] = "endswith"
    contains_expression   : ClassVar[str] = "{field} -contains {value}"
    wildcard_match_expression : ClassVar[str] = "match"      # Special expression if wildcards can't be matched with the eq_token operator
    
    # Regular expressions
    re_expression : ClassVar[str] = "{field} =~ {regex}"  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    
    # cidr expressions
    cidr_wildcard : ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression : ClassVar[str] = "cidrmatch({field}, {value})"    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "     # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| " # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"   # String used as query if final query only contains deferred expression

    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
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
        detections = rule.detection.detections
        for k in detections.keys():
            if k == "selection":
                for i in detections[k].detection_items:
                    if i.field == "$_.EventID":
                        id = i.value[0]
        return f"Get-WinEvent @{{Logname={rule.logsource.service};Id={id}}} | Read-WinEvent | Where-Object {{{' '.join(query.split()[4:])}}}" 
        
    def finalize_output_default(self, queries: List[str]) -> str:
        return list(queries)