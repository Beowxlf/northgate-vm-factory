@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyOperator.psm1'
    ModuleVersion = '0.1.0'
    GUID = '1fcd1b1c-fb55-4df7-b205-48566e165cab'
    Author = 'NorthGate'
    CompanyName = 'NorthGate'
    Copyright = '(c) NorthGate. All rights reserved.'
    Description = 'Hard-disabled local candidate for an exact 12-asset create-only VM Factory operator.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-NorthGateCreateOnlyOperatorStatus',
        'Register-NorthGateCreateOnlyOperatorPlan',
        'Invoke-NorthGateCreateOnlyOperatorApply',
        'Get-NorthGateCreateOnlyOperatorReceipt'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NorthGate', 'Hyper-V', 'CreateOnly', 'HardDisabled', 'LocalCandidate')
            ProjectUri = 'https://github.com/Beowxlf/northgate-vm-factory'
            ReleaseNotes = 'Local-only candidate. Plan registration is test-only and production apply is unconditionally disabled.'
        }
    }
}
