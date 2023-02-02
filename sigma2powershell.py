from sigma.collection import SigmaCollection
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend, output_formats
import argparse

def Sigma2PowerShell(path: str, show_errors: bool):
    rules = SigmaCollection.load_ruleset(inputs = [path])
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(processing_pipeline = pipeline, collect_errors = show_errors)
    return backend.convert(rule_collection = rules, output_format = "default")

if "__main__" == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", help = "path to Sigma rule(s)", type = str)
    parser.add_argument("-o", "--output", choices = output_formats, default = "default", help = "output format", type = str)
    parser.add_argument("-e", "--show-errors", action = "store_false", default = True,  help = "show rule errors")
    args = parser.parse_args()
    queries = Sigma2PowerShell(args.path, args.show_errors)
    if None not in queries:
        print("\n".join(queries))