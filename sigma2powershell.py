import argparse
from sigma.collection import SigmaCollection
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

def Sigma2PowerShell(path):
    rules = SigmaCollection.load_ruleset(inputs = [path])
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(processing_pipeline = pipeline, collect_errors = True)
    return backend.convert(rule_collection = rules, output_format = "default")

if "__main__" == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", type = str, help = "path to Sigma rule(s)")
    parser.add_argument("-o", type = str, help = "output format")
    args = parser.parse_args()
    queries = Sigma2PowerShell(args.p)
    print("\n".join(queries))