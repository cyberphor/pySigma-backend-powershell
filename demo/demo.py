import sigma
import powershell_backend
import powershell_pipeline

pipeline = powershell_pipeline.powershell_pipeline()
backend = powershell_backend.PowerShellBackend(pipeline)
rules = sigma.collection.SigmaCollection.load_ruleset([''])
print("\n".join(backend.convert(rules,"1"))) # 1 references the finalize_query_1 function