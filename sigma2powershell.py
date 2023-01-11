import argparse
from sigma.collection import SigmaCollection
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

def Sigma2PowerShell(path: str, show_errors: bool):
    rules = SigmaCollection.load_ruleset(inputs = [path])
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(processing_pipeline = pipeline, collect_errors = show_errors)
    return backend.convert(rule_collection = rules, output_format = "default")

if "__main__" == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", type = str, help = "path to Sigma rule(s)")
    parser.add_argument("-o", "--output", type = str, help = "output format")
    parser.add_argument("--show-errors", default = True, action = "store_false", help = "show rule errors")
    args = parser.parse_args()
    queries = Sigma2PowerShell(args.path, args.show_errors)
    print("\n".join(queries))