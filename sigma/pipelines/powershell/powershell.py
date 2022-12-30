from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, DropDetectionItemTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def powershell_pipeline() -> ProcessingPipeline: 
    return ProcessingPipeline(
        name = "PowerShell pipeline",
        priority = 20,
        items = [
            ProcessingItem(
                identifier = f"powershell_windows_{service}",
                rule_conditions = [logsource_windows(service)],
                transformation = AddConditionTransformation({"LogName": source})
            )
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(
                identifier = "powershell_field_mapping",
                transformation = FieldMappingTransformation({"EventID": "Id"})
            )
        ] + [
            ProcessingItem(
                identifier = "powershell_field_name_prefix",
                field_name_conditions = [ExcludeFieldCondition(fields = ["LogName","Id"])],
                transformation = AddFieldnamePrefixTransformation("$_.")  
            )
        ],
    )