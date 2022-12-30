from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, DropDetectionItemTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import IncludeFieldCondition, ExcludeFieldCondition, MatchStringCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def powershell_pipeline() -> ProcessingPipeline: 
    return ProcessingPipeline(
        name = "PowerShell pipeline",
        priority = 20,
        items = [
            ProcessingItem(
                identifier = "drop_logsource_field",
                field_name_conditions = [
                    IncludeFieldCondition(fields = ["LogName"], type = "plain")
                ],
                transformation = DropDetectionItemTransformation()  
            )
        ] + [
            ProcessingItem(
                identifier = "drop_id_field",
                field_name_conditions = [
                    IncludeFieldCondition(
                        fields = ["([(e|E)][(v|V)][(e|E)][(n|N)][(t|T)][][(i|I)][(d|D)])|([(e|E)][(v|V)][(e|E)][(n|N)][(t|T)][(-|_)][(i|I)][(d|D)])"],
                        type = "re"
                    )
                ],
                transformation = DropDetectionItemTransformation()  
            )
        ] + [
            ProcessingItem(
                identifier = "add_prefix__to_field_names",
                transformation = AddFieldnamePrefixTransformation("$_.")  
            )
        ]
    )