![Tests](https://github.com/cyberphor/pySigma-backend-powershell/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/cyberphor/d3f7db7182e7819f3748e64a2ab2d126/raw/cyberphor-pySigma-backend-powershell.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma PowerShell Backend
The pySigma PowerShell backend uses [pySigma](https://github.com/SigmaHQ/pySigma) to convert [Sigma rules](https://github.com/SigmaHQ/sigma) into PowerShell queries. It was designed to be used in conjunction with the [Soap](https://github.com/cyberphor/Soap) PowerShell module (i.e., the `Read-WinEvent` function). 

## Overview
The pySigma PowerShell backend includes two Python packages:
* `sigma.pipelines.powershell`: normalizes Sigma rules for PowerShell.
* `sigma.backends.powershell`: declares the `PowerShellBackend` class and multiple output methods.

It currently supports the following output formats:
- [x] default: plain PowerShell queries
- [ ] script: a PowerShell script
- [ ] xml: XML documents
- [ ] xpath: XML strings
- [ ] subscription: Windows event subscriptions 

## Usage
```bash
poetry run python sigma2powershell.py -p rules/
```

## Testing
```python
python -m pip install --user pytest
python -m pytest                                                                  # test all functions
python -m pytest tests/test_backend_powershell.py::test_powershell_and_expression # test a specific function
```

## Updating to the Latest Version of pySigma
```python
python -m poetry add pysigma@latest
```

## References
* [Understanding XML and XPath by the Microsoft Scripting Guy, Ed Wilson](https://devblogs.microsoft.com/scripting/understanding-xml-and-xpath/)
