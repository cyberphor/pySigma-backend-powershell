from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddFieldnamePrefixTransformation, RuleFailureTransformation

def powershell_pipeline() -> ProcessingPipeline:
    add_prefix = ProcessingItem(
        transformation = AddFieldnamePrefixTransformation("$_."),
    )
    
    handle_rule_failures = ProcessingItem(
        rule_condition_linking = any,
        rule_condition_negation = True,
        rule_conditions = [
            LogsourceCondition(product = "windows"),
        ],
        transformation = RuleFailureTransformation("Missing or invalid logsource"),
    )

    pipeline = ProcessingPipeline()
    pipeline.items.append(add_prefix)
    pipeline.items.append(handle_rule_failures)
    return pipeline