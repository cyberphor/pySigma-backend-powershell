![Tests](https://github.com/cyberphor/pySigma-backend-powershell/actions/workflows/test.yml/badge.svg) ![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma PowerShell Backend

This is the PowerShell backend for pySigma. It provides the package `sigma.backends.powershell` with the `PowerShellBackend` class. 
Further, it contains the following processing pipelines in `sigma.pipelines.powershell`:

* pipeline1: purpose
* pipeline2: purpose

It supports the following output formats:

* default: plain PowerShell queries
* format_1: purpose
* format_2: purpose

This backend is currently maintained by:

* [Victor Fernandez III](https://github.com/cyberphor/)

## Testing
```python
python -m pip install --user pytest
python -m pytest
```