@{
    RootModule = 'NorthGate.VMFactory.PromotionCandidate.psm1'
    ModuleVersion = '0.1.0'
    GUID = '96e3f677-0b6f-49cc-9be4-b42545821ed8'
    Author = 'NorthGate VM Factory'
    CompanyName = 'NorthGate Lab'
    Copyright = '(c) 2026 NorthGate Lab. All rights reserved.'
    Description = 'Local-only, fail-closed verifier candidate for signed install-only control-plane promotion envelopes.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Test-NorthGatePromotionEnvelope')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NorthGate', 'Hyper-V', 'Promotion', 'FailClosed')
            ProjectUri = 'https://github.com/Beowxlf/northgate-vm-factory'
            ReleaseNotes = 'Proposed local-only verifier. No installer and no apply capability.'
        }
    }
}
