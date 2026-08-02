@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyService.psm1'
    ModuleVersion = '1.0.0'
    GUID = '893d64d8-0f2c-45c0-b43f-d5093bd038ca'
    Author = 'NorthGate VM Factory'
    Description = 'Identity-aware service dispatcher for the NorthGate create-only backend.'
    PowerShellVersion = '5.1'
    RequiredModules = @()
    FunctionsToExport = @('Invoke-NorthGateCreateOnlyBackendServiceRequest')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
