import argparse
import sigma
from typing import List
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

pipeline = powershell_pipeline()
backend = PowerShellBackend(pipeline)

def main():  
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", type = str, help = "path to Sigma rule file")
    args = parser.parse_args()
    if args.p:
        rules = sigma.collection.SigmaCollection.load_ruleset([args.p])
        print("\n".join(backend.convert(rules)))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()