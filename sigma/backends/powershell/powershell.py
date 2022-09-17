from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern

class PowerShellBackend(TextQueryBackend):
    """PowerShell backend."""
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   
    token_separator : str = " "     
    or_token : ClassVar[str] = "-or"
    and_token : ClassVar[str] = "-and"
    not_token : ClassVar[str] = "-not"
    eq_token : ClassVar[str] = " = "  
    field_quote : ClassVar[str] = None                               
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")
    field_quote_pattern_negation : ClassVar[bool] = True
    field_escape : ClassVar[str] = "\\"
    field_escape_quote : ClassVar[bool] = True
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")
    str_quote       : ClassVar[str] = '"'
    escape_char     : ClassVar[str] = "\\"
    wildcard_multi  : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "*"
    add_escaped     : ClassVar[str] = "\\"
    filter_chars    : ClassVar[str] = ""
    bool_values     : ClassVar[Dict[bool, str]] = {
        True: "$true",
        False: "$false",
    }
    startswith_expression : ClassVar[str] = "startswith"
    endswith_expression   : ClassVar[str] = "endswith"
    contains_expression   : ClassVar[str] = "-contains"
    wildcard_match_expression : ClassVar[str] = "-match"
    re_expression : ClassVar[str] = "{field}=~{regex}"
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ()
    cidr_wildcard : ClassVar[str] = "*"
    cidr_expression : ClassVar[str] = "cidrmatch({field}, {value})"
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }
    field_null_expression : ClassVar[str] = "{field} -is $null"
    convert_or_as_in : ClassVar[bool] = True
    convert_and_as_in : ClassVar[bool] = True
    in_expressions_allow_wildcards : ClassVar[bool] = True
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"
    or_in_operator : ClassVar[str] = " -in "
    and_in_operator : ClassVar[str] = "contains-all"
    list_separator : ClassVar[str] = ", "
    unbound_value_str_expression : ClassVar[str] = '"{value}"'
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '_=~{value}'
    deferred_start : ClassVar[str] = "\n| "
    deferred_separator : ClassVar[str] = "\n| "
    deferred_only_query : ClassVar[str] = "*"

    def generate_query_prefix(self, processed_rule) -> list[str]:
        logname = processed_rule.split("LogName=")[1].split(" ")[0]
        if "Id" in processed_rule:
            event_id = processed_rule.split("Id = ")[1].split(" ")[0]
            prefix = 'Get-WinEvent -FilterHashTable @{LogName=%s;Id=%s} | Read-WinEvent | Where-Object { ' % (logname, event_id)
        else:
            event_id = False
            prefix = 'Get-WinEvent -LogName "%s" | Read-WinEvent | Where-Object { ' % (logname)
        return logname, event_id, prefix

    def generate_query_body(self, logname, event_id, processed_rule) -> str:
        logname = "LogName = " + logname + " -and "
        body = processed_rule.replace(logname,"")
        if event_id:
            event_id = "Id = " + event_id + " -and "
            body = body.replace(event_id,"")
        return body

    def generate_query_suffix(self, rule) -> str:
        event_properties = ['']
        for detection_item in rule.detection.detections["filter"].detection_items:
            event_property = detection_item.field.replace("$_.","")
            event_properties.append(event_property)
        for detection_item in rule.detection.detections["selection"].detection_items:
            if detection_item.field != "Id":
                event_property = detection_item.field.replace("$_.","")
                event_properties.append(event_property)
        suffix = " } | Select-Object -Property TimeCreated" + ", ".join(event_properties)
        return suffix

    def finalize_query_default(self, rule: SigmaRule, processed_rule: str, index: int, state: ConversionState) -> str:
        if rule.logsource.service != None:
            logname, event_id, prefix = self.generate_query_prefix(processed_rule)
            body = self.generate_query_body(logname, event_id, processed_rule)
            suffix = self.generate_query_suffix(rule)
            query = prefix + body + suffix
            return query
        # TODO: replace "logsource.service" with "logsource.service OR logsource.category"
        # ensure backend generates a query even if no logname is specified (for situations where a log file will be analyzed)
        return "Error: please specify a logsource (e.g., service: security)."

    def finalize_output_default(self, queries: list[str]) -> str:
        return queries