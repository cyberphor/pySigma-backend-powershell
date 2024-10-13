from argparse import ArgumentParser
from sigma.collection import SigmaCollection
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend


def Sigma2PowerShell(path: str, output: str, show_errors: bool):
    rule_collection = SigmaCollection.load_ruleset(inputs=[path])
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(
        processing_pipeline=pipeline, collect_errors=show_errors
    )
    return backend.convert(rule_collection)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "-r",
        "--rules",
        type=str,
        required=True,
        help="path to Sigma rule(s)",
        metavar="<PATH_TO_RULESET>",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="default",
        type=str,
        choices=["default", "script"],
        help="output format",
    )
    parser.add_argument(
        "-e",
        "--show-rule-errors",
        action="store_false",
        default=True,
        help="show rule errors",
    )
    args = parser.parse_args()
    print(Sigma2PowerShell(args.rules, args.output, args.show_rule_errors))
