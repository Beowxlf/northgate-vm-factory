[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [string]$ExpectedSignerCertificateSha256 = '00d58a5185b436f208a9d8b1209ede658d0b8754524fbfa2478061e2181744ef',
    [switch]$RequireTrusted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Split-Path -Parent $PSScriptRoot }
$releaseRoot = Join-Path $RepositoryRoot 'control-plane\create-only-release'
$files = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
    'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psm1',
    'Build-NorthGateCreateOnlyServiceHost.ps1',
    'NorthGate.VMFactory.CreateOnlyService.psd1',
    'NorthGate.VMFactory.CreateOnlyService.psm1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psd1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psm1',
    'Invoke-NorthGateCreateOnlyForcedCommand.ps1',
    'Start-NorthGateCreateOnlyPipeService.ps1',
    'Install-NorthGateCreateOnlyRelease.ps1',
    'Enable-NorthGateCreateOnlyInitialActivation.ps1',
    'New-NorthGateCreateOnlyApproval.ps1',
    'New-NorthGateCreateOnlyRolloutPromotion.ps1',
    'Rollback-NorthGateCreateOnlyRelease.ps1',
    'Test-NorthGateCreateOnlyHostAuthorization.ps1'
)

$sha = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($relative in $files) {
        $path = Join-Path $releaseRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "NGCOR-AUTHENTICODE-FILE-INVALID:$relative"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($null -eq $signature.SignerCertificate -or
            $signature.Status -in @(
                [Management.Automation.SignatureStatus]::NotSigned,
                [Management.Automation.SignatureStatus]::HashMismatch,
                [Management.Automation.SignatureStatus]::NotSupportedFileFormat,
                [Management.Automation.SignatureStatus]::Incompatible
            )) {
            throw "NGCOR-AUTHENTICODE-SIGNATURE-INVALID:${relative}:$($signature.Status)"
        }
        if ($RequireTrusted -and $signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            throw "NGCOR-AUTHENTICODE-SIGNER-NOT-TRUSTED:${relative}:$($signature.Status)"
        }
        $pin = (($sha.ComputeHash($signature.SignerCertificate.RawData) |
            ForEach-Object { $_.ToString('x2') }) -join '')
        if ($pin -cne $ExpectedSignerCertificateSha256) {
            throw "NGCOR-AUTHENTICODE-SIGNER-PIN-MISMATCH:$relative"
        }
        $gitPath = 'control-plane/create-only-release/' + $relative.Replace('\','/')
        $attribute = @(& git -C $RepositoryRoot check-attr text -- $gitPath 2>&1)
        if ($LASTEXITCODE -ne 0 -or (@($attribute | ForEach-Object { [string]$_ }) -join "`n") `
                -cnotmatch ': text: unset$') {
            throw "NGCOR-AUTHENTICODE-GIT-NORMALIZATION-ENABLED:$relative"
        }
    }
}
finally { $sha.Dispose() }

[pscustomobject][ordered]@{
    status = 'authenticode-verified'
    fileCount = $files.Count
    signerCertificateSha256 = $ExpectedSignerCertificateSha256
    trustRequired = [bool]$RequireTrusted
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAYwFrLoLLKl9o3
# VuZk5BOZkecefxjCHm4CQAobMQpP76CCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIDjnnTAdXuxiO2q0qzq5NMdN22ulsddufqvsCPRpwr72MA0GCSqG
# SIb3DQEBAQUABIIBgH7OB3R/FnzbaX04Grb2+yIntrI8WxJW8LESm0druMfBXCnq
# MBYvtEXvw6MQKwxIal66n/uFtKb7MGNhrXY/BATagNZfYDkd0U9sasVMI3taKa48
# KO+arQsyeq0H96IwtI0qzfZL9nQSnj9T7ATFZWfvTq/UUkDRxK04wqtwWjwT1suS
# J3StMFOz6rAOkgiH/5VjoMGGljgik5G08KXeJcOFVDpKkQ5gAw3ci+hediI3I43U
# fk8TQPFIOsPzUMUHNRlBu2fUWfuOA4MiLbxJ70kWpQ8RpO/01rWQhMxh1K7kQ0L2
# lg5SxYniZ/a6O3D9EEe7zzcMJnmtm5qy75hMjh0n6Xtf1PDME3MTWGPvu4mNcQCt
# /0k+qLULBPmn/AawMQUgn7v8Q2Tk5fizjWNlEevPeS1COYBN5FwUIAz2Z4izr0P/
# clY2fbGOv9JvkK0SFH4JhEfdEP1ov/S05CRdWhk279lNe1DhLcsx6kwCOkrQ0kqv
# MO7lbDJUwA3NJHbF4w==
# SIG # End signature block
