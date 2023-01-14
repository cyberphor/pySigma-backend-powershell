from dataclasses import dataclass, field
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition, RuleContainsDetectionItemCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddFieldnamePrefixTransformation, ChangeLogsourceTransformation, DetectionItemFailureTransformation, DropDetectionItemTransformation, RuleFailureTransformation, Transformation
from sigma.rule import SigmaRule
import re

@dataclass
class PromoteFieldToRuleComponentTransformation(Transformation):
    """Promote a field from the rule detection item level to the rule component level."""
    field: str = field(default = None)
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
                # Field name conditions are evaluated against fields in detection items and in the component-level field list of a rule
                field_name_conditions = [IncludeFieldCondition(
                    fields = [re.compile(pattern = "EventID", flags = re.IGNORECASE)],
                    type = "re"
                )],
                transformation = PromoteFieldToRuleComponentTransformation(field = "EventID")
            )
        ] + [
            ProcessingItem(
                # Field name conditions are evaluated against fields in detection items and in the component-level field list of a rule
                rule_conditions = [RuleContainsDetectionItemCondition(
                    field = re.compile(pattern = "EventID", flags = re.IGNORECASE),
                    value = re.compile(pattern = ".*", flags = re.IGNORECASE)
                )],
                transformation = DropDetectionItemTransformation()
            )
        ] + [
            ProcessingItem(
                transformation = AddFieldnamePrefixTransformation("$_.")
            )
        ]
    )