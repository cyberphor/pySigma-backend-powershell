import argparse
import sigma
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend

parser = argparse.ArgumentParser()
parser.add_argument('--rule-file', type = str, help = 'path to Sigma rule file')
args = parser.parse_args()

event_parser = """
filter Read-WinEvent {
    $WinEvent = [ordered]@{} 
    $XmlData = [xml]$_.ToXml()
    $SystemData = $XmlData.Event.System
    $SystemData | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
    ForEach-Object {
        $Field = $_
        if ($Field -eq 'TimeCreated') {
            $WinEvent.$Field = Get-Date -Format 'yyyy-MM-dd hh:mm:ss' $SystemData[$Field].SystemTime
        } elseif ($SystemData[$Field].'#text') {
            $WinEvent.$Field = $SystemData[$Field].'#text'
        } else {
            $SystemData[$Field] | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
            ForEach-Object { 
                $WinEvent.$Field = @{}
                $WinEvent.$Field.$_ = $SystemData[$Field].$_
            }
        }
    }
    $XmlData.Event.EventData.Data | ForEach-Object { WinEvent.$($_.Name) = $_.'#text' }
    return New-Object -TypeName PSObject -Property $WinEvent
}
"""

def sigma2powershell(rulefile: str):
    rules = sigma.collection.SigmaCollection.load_ruleset([rulefile])
    pipeline = powershell_pipeline()
    backend = PowerShellBackend(pipeline)
    queries = backend.convert(rules)
    print(queries)
    return

if __name__ == "__main__":
    if args.rule_file:
        print(event_parser)
        sigma2powershell(args.rule_file)
    else:
        parser.print_help()