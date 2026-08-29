@{
    RootModule = 'NorthGate.VMFactory.CreateOnlyBackend.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'cd43ffac-8e98-41df-a5e5-bd667d93d50c'
    Author = 'NorthGate VM Factory'
    Description = 'Transaction-owned, fail-closed Generation 2 Hyper-V create-only planner and apply backend.'
    PowerShellVersion = '5.1'
    RequiredModules = @()
    FunctionsToExport = @(
        'New-NorthGateCreateOnlyBackendContext',
        'Get-NorthGateCreateOnlyBackendState',
        'New-NorthGateCreateOnlyHostPlan',
        'Get-NorthGateCreateOnlyHostPlan',
        'Get-NorthGateCreateOnlyRolloutPromotionContext',
        'Register-NorthGateCreateOnlyRolloutPromotion',
        'Register-NorthGateCreateOnlyApproval',
        'Invoke-NorthGateCreateOnlyApply',
        'Invoke-NorthGateCreateOnlyReceiptReconciliation',
        'Get-NorthGateCreateOnlyReceipt',
        'Invoke-NorthGateCreateOnlyCrashRecovery'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('NorthGate','HyperV','CreateOnly','Planner','Transaction') } }
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAIM5BOb7fsSjDo
# MbZvAiRa8Kj4Dais/lfbILSE2VcMZ6CCBF0wggRZMIICwaADAgECAhAvazDvs9z4
# sEhN7njmUsaSMA0GCSqGSIb3DQEBCwUAMDwxOjA4BgNVBAMMMU5vcnRoR2F0ZSBW
# TSBGYWN0b3J5IFJlbGVhc2UgU2lnbmVyIDIwMjYtMDgtMjEgdjIwHhcNMjYwODIx
# MDI0ODM5WhcNMjgwODIxMDc1ODM5WjA8MTowOAYDVQQDDDFOb3J0aEdhdGUgVk0g
# RmFjdG9yeSBSZWxlYXNlIFNpZ25lciAyMDI2LTA4LTIxIHYyMIIBojANBgkqhkiG
# 9w0BAQEFAAOCAY8AMIIBigKCAYEAuK2RPh+kwyLvYhpQmiHvsROwEKzmIdyEc6WV
# b1N80dzFqV4o16F7MTsoC1Xbo3VdbDurlCWifItnM+UTZ7B6xP8TLmPGRys7sGa/
# QQOm77wKKQ7OdjJlqSSXz4+efiUwoMEkhyP3YkL8G7VvS7EcKCVaspPX8ghvtCYe
# rOQQYWVFOV9EuvajfvnFPna0Y4Y4qMJAxZZEtfMVKtLejdftGHra9pZm/Vi3OiIx
# At/lfqeqK1vYu96Uyh4LhSoxSaev2EOpsznHtTIwY3KNC9dpwlogX2FYa0l1zH1k
# Kk0n/AjTYgR0mxQXMP89640xScVCb+rmY8SNG5w/YZB9uQnkTY5Zkh8z5dfHH8HM
# Fvibww5+B8nEBiMe/1RrUzpf1qOyuwyCphrAMRl2NbWR/yzdjCvUBaLbbmkVW20f
# U3X2CTd144vt2iLfCco+WEIuXaRy6g1vQxu1bYtOHuO5GwobWUCN4CVvhILf+VVt
# hPvyDnvdRZEyaJ2wmI3xWE0+QJY9AgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRb
# WaTBPZZW7QhHiKCc/W2Z3DB9oTANBgkqhkiG9w0BAQsFAAOCAYEAaNP8lBhUC94L
# AUcORggLbH+yuwZ92dK4vhUVrqukaQKL0CpTouv88GOJtrocGo09vyZ1Y7T+ieZ2
# SKKMwmM+efwt+cDQ0b4HDIWYfswSQdfd/HATQX5PNSmC6uEYi6cf/yd31aHkySrN
# W2gfy82zjixp/SP/k9KmpbE+I5f8wppCZ4+ePk5/g+f7gb7a9+g66Ywua2apF76N
# gQB0LPaz0SXwWZ4QS4w/X4TUSDnluz9uHzX2NZ4oNAzT1tR7tBF7Ntu+8mEw2mot
# BcI7pQEu6CDLNGl1rSwPswnZDUWOcnImdqW3IDab4XUmN5my5pB3iLmojG2UOVXr
# SWVYZkiHWI5RGHNDBmdnbDXxK2Xy4uJMLiVEqws8QosKSTUTSAL5B3KM1/HWwQzv
# X2fiwRK2cIfTIJ34Dtlp0lewhzvauoSuVZkYxQ/43QfYxed20zWo44UnRTrScDdC
# 9UmREbQDcZjjpb04T4zAXLHmS9e0k1IwA7vXMRcs4x7Uiq5diaQdMYICgjCCAn4C
# AQEwUDA8MTowOAYDVQQDDDFOb3J0aEdhdGUgVk0gRmFjdG9yeSBSZWxlYXNlIFNp
# Z25lciAyMDI2LTA4LTIxIHYyAhAvazDvs9z4sEhN7njmUsaSMA0GCWCGSAFlAwQC
# AQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZI
# hvcNAQkEMSIEIL+inQD31lfyHodEp8zz3dn2ka0pnX2Xcls+DnejeSKeMA0GCSqG
# SIb3DQEBAQUABIIBgK50dGN5DKhbJg42fAgG4nk+N3l8aBuO/WKorZFl+Pu2PriB
# ayiVCMBP9E0r+cCPmWMKF+9JMLvtRvSDeUn9WMt9f26Mk6Amfg3swa1fv5SroPCF
# G26ZadZnCFb1g+QwvOxoHjMY1a9KppOspoFyKLWIrBRcIgAlC1Otq+P3lrDiVjFY
# iP8mTHAIaEJROtcD/1tl+bxe7S2DNpH1mGM7vIGDEYsnJjgeOAmFe4aLQb3SxRLS
# QL2T8+SWpA4DMmJYCDpo/oX+Bj83R9HLLfmb8hH1LNWLz1QX58XHr3sGrtIKwCE0
# 7FYOzLWpmEZCmIY0kuBXLoTjWeBMM6PFC/LTjkGuZ25NiO0uHNByWovYTUXo64TO
# PauLVUSy2m1TAECLZ+Wethq/6ewJE7panAbyfzTZRZ0q9SaZDRIb+CMNB0xW63f+
# 00f8TMyh845ASYbSd9/vzyE0L0P2dlAR+aTIDwe29M9R8Dj9ppEVARJZMeHOTOPo
# gCE7P73kqCWxC4sYTA==
# SIG # End signature block
