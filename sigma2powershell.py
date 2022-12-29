import argparse
import sigma
from typing import List
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

pipeline = powershell_pipeline()
backend = PowerShellBackend(pipeline)

def convert(rule):
    try:
        print(backend.convert(rule))
    except Exception as error:
        print(error)

def main():  
    parser = argparse.ArgumentParser()
    parser.add_argument('--rule', type = str, help = 'path to Sigma rule file')
    parser.add_argument('--rules', type = str, help = 'path to Sigma rule file')
    args = parser.parse_args()
    if args.rule:
        rule = sigma.collection.SigmaCollection.from_yaml(args.rule)
        convert(rule)
    elif args.rules:
        rules = sigma.collection.SigmaCollection.load_ruleset([args.rules])
        convert(rules)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()