# pySigma PowerShell Backend
Uses pySigma to convert Sigma rules into PowerShell queries.

## Overview
pySigma-backend-powershell provides two Python packages:
* `sigma.pipelines.powershell`: normalizes Sigma rules for PowerShell.
* `sigma.backends.powershell`: declares the `PowerShellBackend` class and multiple output methods.

It currently supports the following output formats:
- [x] default: plain PowerShell queries
- [ ] script: a PowerShell script
- [ ] xml: XML documents
- [ ] xpath: XML strings
- [ ] subscription: Windows event subscriptions 

## Testing
```python
python -m pip install --user pytest
python -m pytest
```

## References
* [Understanding XML and XPath by the Microsoft Scripting Guy, Ed Wilson](https://devblogs.microsoft.com/scripting/understanding-xml-and-xpath/)