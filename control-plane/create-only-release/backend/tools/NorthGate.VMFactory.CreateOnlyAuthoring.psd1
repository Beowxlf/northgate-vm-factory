@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyAuthoring.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'e59cfe74-18da-47e1-a42e-6e518c40aa21'
    Author = 'NorthGate'
    CompanyName = 'NorthGate'
    Copyright = '(c) NorthGate. All rights reserved.'
    Description = 'Fail-closed authoring tools for signed create-only data, policy, and one-use approval artifacts.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop','Core')
    FunctionsToExport = @(
        'New-NorthGateCreateOnlyDataBundle',
        'New-NorthGateCreateOnlyBackendPolicyArtifact',
        'New-NorthGateCreateOnlyPlanApprovalArtifact'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NorthGate','Hyper-V','CreateOnly','CMS','Authoring')
            ProjectUri = 'https://github.com/Beowxlf/northgate-vm-factory'
        }
    }
}
