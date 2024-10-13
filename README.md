# pySigma Powershell Backend
![Status](https://img.shields.io/badge/Status-pre--release-orange)  

The pySigma PowerShell Backend converts Sigma rules into PowerShell-based queries. It was designed to be used in conjunction with the the [`Read-WinEvent`](/scripts/Read-WinEvent.ps1) filter. 

## Usage
**Step 1.** After downloading this repository, install this Python-based project using `poetry`.
```bash
poetry install
```

**Step 2.** Next, use the provided PowerShell script to import the `Read-WinEvent` filter. You will need to do this everytime you start a new PowerShell session (pro-tip: add this filter to your PowerShell profile).
```bash
./scripts/Read-WinEvent.ps1
```

**Step 3** Convert whatever Sigma rules you have to PowerShell queries.
```bash
sigma2powershell -r rules/demo.yml
```

## Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).