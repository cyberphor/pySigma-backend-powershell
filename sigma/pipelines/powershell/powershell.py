from dataclasses import dataclass
from sigma.pipelines.common import logsource_windows, logsource_windows_network_connection, windows_logsource_mapping 
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, ChangeLogsourceTransformation, DetectionItemFailureTransformation, DropDetectionItemTransformation, FieldMappingTransformation, RuleFailureTransformation, SetStateTransformation, Transformation
from sigma.rule import SigmaRule

@dataclass
class PromoteDetectionItemTransformation(Transformation):
    """Promote a detection item to the rule component level."""
    field: str
    def apply(self, pipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        for detection in rule.detection.detections.values():
            for detection_item in detection.detection_items:
                if detection_item.field == self.field:
                    # TODO: address situations where the detection item has more than one value
                    setattr(rule, self.field.lower(), detection_item.value[0])

def powershell_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name = "PowerShell pipeline",
        items = [
            ProcessingItem(
                rule_condition_negation = True,
                rule_conditions = [LogsourceCondition(product = "windows")],
                transformation = RuleFailureTransformation(message = "Invalid logsource product.")
            )
        ] + [
            ProcessingItem(
                rule_conditions = [logsource_windows(logsource)], # if rule matches what is returned by logsource_windows func (e.g., product = windows, service = security)
                transformation = ChangeLogsourceTransformation(service = channel) # change service value (e.g., sysmon) to channel value (e.g., Microsoft-Windows-Sysmon/Operational)
            )
            for logsource, channel in windows_logsource_mapping.items() # returns multiple kv pairs (service:channel mappings)
        ] + [
            ProcessingItem(
                rule_conditions = [logsource_windows_network_connection()], # TODO: scale this so all sysmon event categories are covered
                transformation = ChangeLogsourceTransformation(service = windows_logsource_mapping['sysmon']) 
            )
        ] + [
            ProcessingItem(
                # field name conditions are evaluated against fields in detection items and in the component-level field list of a rule
                field_name_conditions = [IncludeFieldCondition(
                    fields = ["[eE][vV][eE][nN][tT][iI][dD]"],
                    type = "re"
                )],
                # TODO: change logic to automatically grab the same field specified for IncludeFieldCondition
                transformation = PromoteDetectionItemTransformation(field = "EventID")
            )
        ] + [
            ProcessingItem(
                # field name conditions are evaluated against fields in detection items and in the component-level field list of a rule
                field_name_conditions = [IncludeFieldCondition(
                    fields = ["[eE][vV][eE][nN][tT][iI][dD]"],
                    type = "re"
                )],
                transformation = DropDetectionItemTransformation()
            )
        ] + [
            ProcessingItem(
                transformation = AddFieldnamePrefixTransformation(prefix = "$_.")
            )
        ]
    )