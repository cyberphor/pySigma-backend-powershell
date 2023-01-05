from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, AddFieldnamePrefixTransformation, DropDetectionItemTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import IncludeFieldCondition, ExcludeFieldCondition, MatchStringCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def powershell_pipeline() -> ProcessingPipeline:
    drop_logsource_field = ProcessingItem(
        transformation = DropDetectionItemTransformation(),
        field_name_conditions = [
            IncludeFieldCondition(
                fields = ["LogName"], 
                type = "plain"
            )
        ]
    )

    drop_id_field = ProcessingItem(
        transformation = DropDetectionItemTransformation(),
        field_name_conditions = [
            IncludeFieldCondition(
                fields = ["([(e|E)][(v|V)][(e|E)][(n|N)][(t|T)][][(i|I)][(d|D)])|([(e|E)][(v|V)][(e|E)][(n|N)][(t|T)][(-|_)][(i|I)][(d|D)])"],
                type = "re"
            )
        ]
    )

    add_prefix_to_field_names = ProcessingItem(
        transformation = AddFieldnamePrefixTransformation("$_.")
    )

    pipeline = ProcessingPipeline()
    pipeline.name = "PowerShell Pipeline"
    pipeline.priority = 20
    pipeline.items.append(drop_logsource_field)
    pipeline.items.append(drop_id_field)
    pipeline.items.append(add_prefix_to_field_names)
    return pipeline