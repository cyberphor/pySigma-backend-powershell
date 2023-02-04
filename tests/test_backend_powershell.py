import pytest
from sigma.pipelines.powershell import powershell_pipeline
from sigma.backends.powershell import PowerShellBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def powershell_backend():
    pipeline = powershell_pipeline()
    return PowerShellBackend(pipeline)

def test_powershell_and_expression(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                selection:
                    EventID: 4688
                    field: value
                condition: selection
        """)
    ) == ['Get-WinEvent -FilterHashTable @{LogName = "Security"; Id = 4688} | Read-WinEvent | Where-Object {$_.field -eq "value"}']

def test_powershell_or_expression(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                selection1:
                    EventID: 4688
                selection2:
                    fieldA: valueA
                selection3:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['Get-WinEvent -FilterHashTable @{LogName = "Security"; Id = 4688} | Read-WinEvent | Where-Object {$_.fieldA -eq "valueA" -or $_.fieldB -eq "valueB"}']

def test_powershell_and_or_expression(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['Get-WinEvent -LogName "Security" | Read-WinEvent | Where-Object {($_.fieldA -eq "valueA1" -or $_.fieldA -eq "valueA2") -and ($_.fieldB -eq "valueB1" -or $_.fieldB -eq "valueB2")}']

def test_powershell_or_and_expression(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['Get-WinEvent -LogName "Security" | Read-WinEvent | Where-Object {($_.fieldA -eq "valueA1" -and $_.fieldB -eq "valueB1") -or ($_.fieldA -eq "valueA2" -and $_.fieldB -eq "valueB2")}']

def test_powershell_in_expression(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['Get-WinEvent -LogName "Security" | Read-WinEvent | Where-Object {$_.fieldA -eq "valueA" -or $_.fieldA -eq "valueB" -or $_.fieldA -like "valueC*"}']

def test_powershell_regex_query(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['Get-WinEvent -LogName "Security" | Read-WinEvent | Where-Object {$_.fieldA -match "foo.*bar" -and $_.fieldB -eq "foo"}']

def test_powershell_cidr_query(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['Get-WinEvent -LogName "Security" | Read-WinEvent | Where-Object {}']

def test_powershell_field_name_with_whitespace(powershell_backend: PowerShellBackend):
    assert powershell_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                service: security
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == [ValueError]

def test_powershell_format1_output(powershell_backend: PowerShellBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format
    pass

def test_powershell_format2_output(powershell_backend: PowerShellBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format
    pass
