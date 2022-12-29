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
<<<<<<< Updated upstream
        name="PowerShell pipeline",
        priority=20,
        items=[
            ProcessingItem(     
                identifier=f"powershell_windows_{service}",
                transformation=AddConditionTransformation({"source": source}),
                rule_conditions=[logsource_windows(service)],
=======
        name = "PowerShell pipeline",
        priority = 20,
        items = [
            ProcessingItem(
                rule_conditions = [
                    LogsourceCondition(product = "windows"), 
                ],
                rule_condition_negation = True,
                transformation = RuleFailureTransformation("Invalid logsource")
>>>>>>> Stashed changes
            )
        ] + [
            ProcessingItem(
                # the 'identifer' field uses string formatting
                identifier = f"powershell_windows_{service}",
                rule_conditions = [
                    logsource_windows(service)
                ],
                transformation = AddConditionTransformation(
                    { "LogName": source }
                )
            )
            # windows_logsource_mapping.items() returns "security" (TO) and "Security" (FROM)
            # if the rule says "Security" it'll be transformed TO "security" and used for the string formatting above
            for service, source in windows_logsource_mapping.items()
        ] + [
            ProcessingItem(
<<<<<<< Updated upstream
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
=======
                identifier = "powershell_field_mapping",
                transformation = FieldMappingTransformation(
                    { "EventID": "Id" },
                )
            )
        ] + [
            ProcessingItem(
                identifier = "powershell_field_name_prefix",
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields = [ "LogName", "Id" ]
                    )
                ],
                transformation = AddFieldnamePrefixTransformation("$_.")  
>>>>>>> Stashed changes
            )
        ],
    )