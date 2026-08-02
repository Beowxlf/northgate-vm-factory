@{
    RootModule = 'NorthGate.VMFactory.HostAdapter.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'b80af6a7-df19-4c0f-af10-f89ec7ee9174'
    Author = 'NorthGate'
    CompanyName = 'NorthGate'
    Copyright = '(c) NorthGate. All rights reserved.'
    Description = 'Undeployed, hard-disabled fixed create-only host-adapter candidate with an inert test backend.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-NorthGateVmFactoryHostAdapterState'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NorthGate', 'PlanOnly', 'HostAdapter', 'CreateOnly', 'InertTest')
            ProjectUri = 'https://github.com/Beowxlf/northgate-vm-factory'
        }
    }
}
