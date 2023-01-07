from sigma.processing.conditions import IncludeFieldCondition, ExcludeFieldCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddFieldnamePrefixTransformation, DropDetectionItemTransformation, FieldMappingTransformation

def powershell_pipeline() -> ProcessingPipeline:
    drop_logsource_field = ProcessingItem(
        transformation = DropDetectionItemTransformation(),
        field_name_conditions = [
            IncludeFieldCondition(["LogName"])
        ]
    )

    rename_eventid_field = ProcessingItem(
        transformation = FieldMappingTransformation(
            mapping = {
                "eventid": "Id",
                "eventId": "Id",
                "eventID": "Id",
                "Eventid": "Id",
                "EventId": "Id",
                "EventID": "Id"
            }
        )
    )

    add_prefix = ProcessingItem(
        transformation = AddFieldnamePrefixTransformation("$_."),
        field_name_conditions = [
            ExcludeFieldCondition(["Id"])
        ]
    )

    pipeline = ProcessingPipeline()
    pipeline.items.append(drop_logsource_field)
    pipeline.items.append(rename_eventid_field)
    pipeline.items.append(add_prefix)
    return pipeline