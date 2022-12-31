import argparse
from sigma.collection import SigmaCollection
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

pipeline = powershell_pipeline()
backend = PowerShellBackend(pipeline)

def main():  
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", type = str, help = "path to Sigma rule(s)")
    args = parser.parse_args()
    if args.p:
        rules = SigmaCollection.load_ruleset([args.p])
        queries = backend.convert(rules)
        if None not in queries:
            print("\n".join(queries))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()