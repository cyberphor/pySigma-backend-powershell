from .powershell import PowerShellBackend

# TODO: add all backend classes that should be exposed to the user of your backend in the import statement above.

backends = {  # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "powershell": PowerShellBackend,
}
