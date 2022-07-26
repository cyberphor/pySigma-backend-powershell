from sigma.pipelines.common import logsource_windows
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

windows_logsource_mapping = {
    "security": "Security",
    "application": "Application",
    "system": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
}

def powershell_pipeline():
    return ProcessingPipeline(
        name="PowerShell pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"powershell_windows_{service}",
                transformation=AddConditionTransformation({
                    'LogName': "Get-WinEvent -LogName '" + source + "' | Where-Object {"
                }),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(
                identifier="powershell_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "Id",
                })
            )
        ] + [
            ProcessingItem(
                identifier="powershell_field_name_prefix",
                transformation=AddFieldnamePrefixTransformation(
                    "$_."
                ),
                detection_item_conditions=[
                    ExcludeFieldCondition(
                        fields = "LogName"
                    )
                ]
            )
        ],
    )