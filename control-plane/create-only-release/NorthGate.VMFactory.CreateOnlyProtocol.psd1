@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyProtocol.psm1'
    ModuleVersion = '0.1.0'
    GUID = '4cbed0ac-89fd-4e4c-8c24-bdb3f8d90874'
    Author = 'NorthGate VM Factory'
    Description = 'Unprivileged strict protocol parser for the NorthGate create-only forced-command release candidate.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'ConvertFrom-NorthGateCreateOnlyCommand',
        'ConvertFrom-NorthGateCreateOnlyPlanRequestBytes',
        'ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes',
        'ConvertTo-NorthGateCreateOnlyCanonicalJson'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('NorthGate','HyperV','CreateOnly','Protocol') } }
}
