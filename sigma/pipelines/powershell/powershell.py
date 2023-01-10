from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddFieldnamePrefixTransformation, RuleFailureTransformation

def powershell_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name = "PowerShell pipeline",
        items = [
            ProcessingItem(
                transformation = AddFieldnamePrefixTransformation("$_."),
            )
        ] + [
            ProcessingItem(
                rule_condition_linking = any,
                rule_condition_negation = True,
                rule_conditions = [
                    LogsourceCondition(product = "windows"),
                    logsource_windows(service)
                ],
                transformation = RuleFailureTransformation("Rule not supported."),
            )
            for service, source in windows_logsource_mapping.items()
        ]
    )