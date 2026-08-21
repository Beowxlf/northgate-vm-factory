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
        'ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes',
        'ConvertTo-NorthGateCreateOnlyCanonicalJson'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('NorthGate','HyperV','CreateOnly','Protocol') } }
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDPbhhTAYCZqvQU
# aYDo/HBuvktc0Zb2pDxfFTJ3F/ZvKaCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIA8Wpy0tOrAPeunvKUnmu1N60XFm4pipmcT2VQZyaLIfMA0GCSqG
# SIb3DQEBAQUABIIBgB9Ti/+YzllENjq6lAWTalPEOP84SKvTPzny9+1UWoypER1w
# GIfuHSH7MuZo42BDjS0BTVybS7g21/gT2kBs8WBOJzigyMWj0a7chGl5Wb+Q/+GC
# CVMFXUyaETu2dAa/CpSY8sjPxizqRhXZe2eE8/iB24gCUcIFqSy178fYjn+2CAUJ
# w1zsnReZNd0YOjmpIDxhkNpoQz2sxgbDFEYJiuRCUK4MlbSdbAKZ4Hi+zdsgU3dp
# 1JdDUykUsmgnF1S6EqrzzEX2vDXpHVoukvinGQWbnJtthbZ132fQboOGnIKwhleb
# Ub8GKKG3xIOS6wwVDyiWTRO1mIJrY4DRoBRRUYPkgHZH2RJtlAr6KdvXPGFxKR2n
# JIcASMoDfNAjroMBEORHjkR8q7+dPe2EzTqxNpKIoD59u9GhJoAcS96OPw8RgvRV
# RFq6Gw1bvGoF/y8rQ8bkXnmF5ptZUQqwXvGPBfXttnwRkWkPXewiSdW3iyigaKL9
# 5bGUmB3Wr4DuE0toQw==
# SIG # End signature block
