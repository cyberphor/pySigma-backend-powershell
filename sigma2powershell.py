import argparse
import sigma
from typing import List
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

parser = argparse.ArgumentParser()
parser.add_argument('--rule-set', type = str, help = 'path to Sigma rule set')
args = parser.parse_args()

def sigma2powershell(ruleset: List[str]):
    rules = sigma.collection.SigmaCollection.load_ruleset(ruleset)
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(pipeline)
    queries = backend.convert(rules)
    for query in queries:
        print(query)
    return

if __name__ == "__main__":
    if args.rule_set:
        sigma2powershell([args.rule_set])
    else:
        parser.print_help()