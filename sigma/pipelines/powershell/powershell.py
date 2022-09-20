from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, DropDetectionItemTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

windows_logsource_mapping = {
    "security": "Security",
    "application": "Application",
    "system": "System",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "sysmon": "Microsoft-Windows-Sysmon/Operational"
}

def powershell_pipeline() -> ProcessingPipeline: 
    return ProcessingPipeline(
        name="PowerShell pipeline",
        priority=20,
        items=[
            ProcessingItem(     
                identifier=f"powershell_windows_{service}",
                transformation=AddConditionTransformation({"source": source}),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(
                identifier="powershell_drop_source_and_EventID_fields",
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["source","EventID"]
                    )
                ]
            )
        ] + [
            ProcessingItem(
                identifier="powershell_field_name_prefix",
                transformation=AddFieldnamePrefixTransformation("$_.")
            )
        ],
    )