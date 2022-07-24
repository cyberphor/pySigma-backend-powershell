import argparse
import sigma
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

parser = argparse.ArgumentParser()
parser.add_argument('--rule-file', type = str, help = 'path to Sigma rule file')
args = parser.parse_args()

def sigma2powershell(rulefile: str):
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(pipeline)
    rules = sigma.collection.SigmaCollection.load_ruleset([rulefile])
    queries = "\n".join(backend.convert(rules))
    print(queries)
    return

if __name__ == "__main__":
    if args.rule_file:
        sigma2powershell(args.rule_file)
    else:
        parser.print_help()