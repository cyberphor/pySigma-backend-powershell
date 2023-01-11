from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, RuleFailureTransformation

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
                rule_condition_negation = True,
                rule_conditions = [LogsourceCondition(service = logsource)],
                transformation = RuleFailureTransformation("Service not supported.")
            )
            for logsource, channel in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(
                transformation = AddFieldnamePrefixTransformation("$_.")
            )
        ]
    )