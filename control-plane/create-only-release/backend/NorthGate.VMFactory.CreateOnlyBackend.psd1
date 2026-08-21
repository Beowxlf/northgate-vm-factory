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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBJDYqbLgS42czC
# P1xhmfyMPB9S6pMR9QPFXyIWkzqSqaCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIC9dmFwIA6mc8vQBzfXlBR78fHxSHpxyU87U5PFv+XMIMA0GCSqG
# SIb3DQEBAQUABIIBgHEVQyg+rRhRpID6GcJdeqptskKNs+C2Gb9vWVAeFJxyo4ak
# YRAPsVKqqajooh/CB7/DbyojaPMmlFor8qnb9fKqlfcHzBpHETwy4NGlnn9orYyL
# oEYAEePLYLGoRGuX4B2lHsIHcO9eai3S7OfMuZw5vdjxm5kXuPCxP53EjAoqrnSz
# FXiJOiRaS0yU7AZzTVNK5XdhjvtD3EhkiXXXgyB721Nl9sLM0HoT6uaOxMm0VSHl
# 0dyvaebJqXWzX5vX9IL7W+SUvBTSEDhKfySko+GySMXeeBVc5YwEBHthrMdOpxJV
# ka9byomCa6oHxtlo8uCy2wNzCvbVExISqpPTt70plXocJz9iihxwWzsZ1+QWL9Lb
# frrP6MHo9qavlV+qpIbAsfkOHuyTSBg0Z5UzJCMrbFEBAXxn9EDuiFqS9UADdeoa
# ijTU1uy45vWyDzYAuE2pbuumoFcFfxfQA9YgeBgOHCJZqx/zFDiYJy8x3cjofC8v
# nDgUmSaaxmCdWpQEhA==
# SIG # End signature block
