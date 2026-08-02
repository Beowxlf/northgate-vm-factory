@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyRelease.psm1'
    ModuleVersion = '0.1.0'
    GUID = '5e7a64cf-b57d-4ab9-b73b-78094ad8017c'
    Author = 'NorthGate VM Factory'
    Description = 'Hard-disabled privileged core scaffold for the NorthGate fixed-fleet create-only release candidate.'
    PowerShellVersion = '5.1'
    RequiredModules = @()
    FunctionsToExport = @(
        'Get-NorthGateCreateOnlyFixedCatalog',
        'Invoke-NorthGateCreateOnlyServiceRequest'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('NorthGate','HyperV','CreateOnly','ReleaseCandidate') } }
}
