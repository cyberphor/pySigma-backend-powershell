from argparse import ArgumentParser
from sigma.collection import SigmaCollection
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

def Sigma2PowerShell(path: str, show_errors: bool, foo: str):
    rules = SigmaCollection.load_ruleset(inputs=[path])
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(processing_pipeline=pipeline, collect_errors=show_errors)
    return backend.convert(rule_collection=rules, output_format=foo)

if "__main__" == __name__:
    parser = ArgumentParser()
    parser.add_argument("-p", help="path to Sigma rule(s)", type=str)
    parser.add_argument("-o", choices=["default", "script"], default="default", help="output format", type=str)
    parser.add_argument("-e", action="store_false", default=True,  help="show rule errors")
    args = parser.parse_args()
    queries = Sigma2PowerShell(args.p, args.e, args.o)
    if None not in queries:
        print("\n".join(queries))