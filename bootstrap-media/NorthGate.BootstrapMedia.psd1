@{
    RootModule = 'NorthGate.BootstrapMedia.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'c44006e4-e90d-46bb-84ce-ae364b3d3c6b'
    Author = 'NorthGate VM Factory'
    Description = 'No-secret, hash-pinned bootstrap bundle renderer for NorthGate canary and fleet media.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-NorthGateBootstrapSourceCatalog',
        'Get-NorthGateBootstrapFleetMap',
        'Import-NorthGateBootstrapRequest',
        'Get-NorthGateAuthorizedPublicKey',
        'Assert-NorthGateBootstrapSourceArtifact',
        'New-NorthGateBootstrapBundle'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
