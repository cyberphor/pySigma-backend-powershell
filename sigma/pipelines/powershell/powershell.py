import re
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddFieldnamePrefixTransformation, ChangeLogsourceTransformation, DropDetectionItemTransformation, RuleFailureTransformation, Transformation
from sigma.rule import SigmaRule

class AddEventIdFieldTransformation(Transformation):
    def apply(self, pipeline, rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        for search_identifier, search in rule.detection.detections.items():
            if re.search("selection", search_identifier, re.IGNORECASE): 
                for search_property in search.detection_items:
                    if re.search("EventID", search_property.field, re.IGNORECASE):
                        rule.event_id = search_property.value[0]

def powershell_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name = "PowerShell pipeline",
        items = [
            ProcessingItem(
                rule_condition_negation = True,
                rule_conditions = [LogsourceCondition(product = "windows")],
                transformation = RuleFailureTransformation("Product not supported.")
            )
        ] + [
            ProcessingItem(
                rule_conditions = [logsource_windows(logsource)],
                transformation = ChangeLogsourceTransformation(service = channel)
            )
            for logsource, channel in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(
                field_name_conditions = [IncludeFieldCondition(fields = "EventID")],
                transformation = AddEventIdFieldTransformation()
            )
        ] + [
            ProcessingItem(
                field_name_conditions = [
                    IncludeFieldCondition(
                        fields = re.compile("EventID", re.IGNORECASE).pattern, 
                        type = "re"
                    )
                ],
                transformation = DropDetectionItemTransformation()
            )
        ] + [
            ProcessingItem(
                transformation = AddFieldnamePrefixTransformation("$_.")
            )
        ]
    )