from collections import defaultdict
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.pipelines.powershell import powershell_pipeline
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaRegularExpressionFlag
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional
from re import compile

class PowerShellBackend(TextQueryBackend):
    """PowerShell backend."""
    name: ClassVar[str] = "PowerShell backend"
    formats: Dict[str, str] = { 
        "default": "PowerShell sentences",
        "script": "PowerShell scripts",
    }
    requires_pipeline: bool = False
    processing_pipeline: powershell_pipeline
    last_processing_pipeline: powershell_pipeline
    output_format_processing_pipeline: ClassVar[Dict[str, ProcessingPipeline]] = defaultdict(
        ProcessingPipeline
    )

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
    field_quote_pattern_negation: ClassVar[bool] = True

    ### Escaping
    field_escape: ClassVar[str] = "\\"                # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote: ClassVar[bool] = False        # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char: ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped: ClassVar[str] = ""    # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""      # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "$true",
        False: "$false",
    }

    # String matching operators. if None is appropriate, eq_token is used.
    startswith_expression: ClassVar[str] = "{field}.StartsWith({value})"
    endswith_expression: ClassVar[str] = "{field}.EndsWith({value})"
    contains_expression: ClassVar[str] = "{field}.Contains({value})"
    wildcard_match_expression: ClassVar[str] = "{field} -like {value}"      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    re_expression: ClassVar[str] = '{field} -match "{regex}"'
    re_escape_char: ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    re_escape_escape_char: bool = True                 # If True, the escape character is also escaped
    re_flag_prefix: bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE : "m",
        SigmaRegularExpressionFlag.DOTALL    : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression: ClassVar[str] = "{field} casematch {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression: ClassVar[str] = "{field} casematch_startswith {value}"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} casematch_endswith {value}"
    case_sensitive_contains_expression: ClassVar[str] = "{field} casematch_contains {value}"

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"    # Character used as single wildcard
    # cidr_expression: ClassVar[str] = "cidrmatch({field}, {value})" # CIDR expression query as format string with placeholders {field} = {value}
    # cidr_in_list_expression: ClassVar[str] = "{field} in ({value})" # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}" # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "-lt",
        SigmaCompareExpression.CompareOperators.LTE: "-le",
        SigmaCompareExpression.CompareOperators.GT: "-gt",
        SigmaCompareExpression.CompareOperators.GTE: "-ge",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[str] = "{field} -is null"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression: ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = True                    # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = False      # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator: ClassVar[str] = "-in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator: ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator: ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression: ClassVar[str] = '_=~{value}'  # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[str] = "*"             # String used as query if final query only contains deferred expression

    def finalize_query_default(self, rule: SigmaRule, query: Any, index: int, state: ConversionState) -> Any:
        if hasattr(rule, "eventid"): 
            filter = f'-FilterHashTable @{{LogName = "{rule.logsource.service}"; Id = {rule.eventid}}} | '
        else:
            filter = f'-LogName "{rule.logsource.service}" | '
        return "Get-WinEvent " + filter + f"Read-WinEvent | Where-Object {{{query}}}"

    def finalize_output_default(self, queries: List[str]) -> Any:
        return queries