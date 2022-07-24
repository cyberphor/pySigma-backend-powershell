![License](https://img.shields.io/github/license/cyberphor/pySigma-backend-powershell?color=Green)
![Status](https://img.shields.io/badge/Status-pre--release-orange)
![Tests](https://github.com/cyberphor/pySigma-backend-powershell/actions/workflows/test.yml/badge.svg)

# pySigma PowerShell Backend
This is the PowerShell backend for pySigma. It provides the package `sigma.backends.powershell` with the `PowerShellBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.powershell`:

* powershell_pipeline: map Sigma rules to PowerShell cmdlets, Windows Event fields, etc. 

It supports the following output formats:

* format_1: plain PowerShell queries. 

This backend is currently maintained by:

* [Victor Fernandez III](https://github.com/cyberphor/)

## Usage
For now, run `sigma2powershell.py` to convert Sigma rules into PowerShell queries using the backend and pipeline provided by this GitHub repository. See below for an example. 
```
python sigma2powershell.py --rule-file ./suspicious_local_account_activity.yml
```