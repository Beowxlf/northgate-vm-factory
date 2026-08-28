[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$maximumPlanBytes = 32768
$maximumResponseBytes = 65536

function Stop-NgcorForcedCommand {
    param([string]$Code, [int]$ExitCode = 1)
    if ($Code -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') { $Code = 'NGCOR-REQUEST-REJECTED' }
    $safe = '{"error":"' + $Code + '","status":"rejected"}'
    [Console]::Out.Write($safe)
    exit $ExitCode
}

function Get-NgcorForcedSafeErrorCode {
    param([System.Exception]$Exception)
    if ($null -eq $Exception) { return 'NGCOR-REQUEST-REJECTED' }
    $match = [regex]::Match(
        ([string]$Exception.Message), '\bNGCOR-[A-Z0-9-]{1,96}\b',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($match.Success) { return [string]$match.Value }
    'NGCOR-REQUEST-REJECTED'
}

function Assert-NgcorInstalledLocation {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
    $resolvedRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
    $cursor = $resolvedRoot
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and (Test-Path -LiteralPath $cursor)) {
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'NGCOR-INSTALLED-RELEASE-REPARSE-FORBIDDEN'
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    if (-not $resolvedRoot.StartsWith($requiredPrefix + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath (Join-Path $resolvedRoot 'installed-release.json') -PathType Leaf)) {
        throw 'NGCOR-CHECKOUT-EXECUTION-FORBIDDEN'
    }
    $resolvedRoot
}

function Get-NgcorForcedFileSha256 {
    param([string]$Path)
    $stream = New-Object System.IO.FileStream(
        $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::SequentialScan
    )
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($stream) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgcorCertificateSha256 {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Certificate.RawData) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgcorPinnedLeafCertificate {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$ExpectedPin)
    if ($null -eq $Certificate -or (Get-NgcorCertificateSha256 $Certificate) -cne $ExpectedPin) {
        throw 'NGCOR-PIPE-SERVER-SIGNER-MISMATCH'
    }
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        throw 'NGCOR-PIPE-SERVER-SIGNER-INVALID'
    }
    $leaf = $false; $eku = $false; $digitalSignature = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $leaf = -not $extension.CertificateAuthority
        }
        elseif ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $eku = $true }
            }
        }
        elseif ($extension -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $digitalSignature = [bool]($extension.KeyUsages -band
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)
            if ($extension.KeyUsages -band (
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign)) {
                throw 'NGCOR-PIPE-SERVER-SIGNER-INVALID'
            }
        }
    }
    if (-not $leaf -or -not $eku -or -not $digitalSignature) {
        throw 'NGCOR-PIPE-SERVER-SIGNER-INVALID'
    }
}

function Test-NgcorDetachedCms {
    param([byte[]]$ContentBytes, [string]$SignaturePath, [string]$ExpectedPin)
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    try {
        $signatureBytes = [IO.File]::ReadAllBytes($SignaturePath)
        $content = New-Object Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
        $cms.Decode($signatureBytes)
        if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1 -or
            $cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            throw 'NGCOR-PIPE-SERVER-CMS-INVALID'
        }
        $cms.CheckSignature($true)
        Test-NgcorPinnedLeafCertificate $cms.SignerInfos[0].Certificate $ExpectedPin
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        throw 'NGCOR-PIPE-SERVER-CMS-INVALID'
    }
}

function Assert-NgcorPipeServerIdentity {
    param(
        [System.IO.Pipes.NamedPipeClientStream]$Pipe, [object]$Installed,
        [object]$Manifest, [string]$InstalledRoot
    )
    $expectedPath = Join-Path $InstalledRoot ([string]$Installed.serviceHostFileName)
    $records = @($Manifest.files | Where-Object {
        $_.artifactKind -ceq 'derived-signed-artifact' -and $_.path -ceq $Installed.serviceHostFileName
    })
    if ($records.Count -ne 1 -or (Get-NgcorForcedFileSha256 $expectedPath) -cne $records[0].sha256 -or
        $records[0].detachedCms.signerCertificateSha256 -cne
            [string]$Installed.releaseSignerCertificateSha256) {
        throw 'NGCOR-PIPE-SERVER-SIGNATURE-INVALID'
    }
    $cmsPath = Join-Path $InstalledRoot ([string]$records[0].detachedCms.path)
    if ((Get-NgcorForcedFileSha256 $cmsPath) -cne $records[0].detachedCms.sha256 -or
        (Get-Item -LiteralPath $cmsPath).Length -ne [int64]$records[0].detachedCms.sizeBytes) {
        throw 'NGCOR-PIPE-SERVER-CMS-INVALID'
    }
    Test-NgcorDetachedCms ([IO.File]::ReadAllBytes($expectedPath)) $cmsPath `
        ([string]$Installed.releaseSignerCertificateSha256)
    $verifier = 'NorthGate.VMFactory.CreateOnly.PipeServerIdentityVerifier' -as [type]
    if ($null -eq $verifier) {
        try {
            $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($expectedPath))
            $verifier = $assembly.GetType(
                'NorthGate.VMFactory.CreateOnly.PipeServerIdentityVerifier', $true, $false
            )
        }
        catch { throw 'NGCOR-PIPE-SERVER-VERIFIER-INVALID' }
    }
    try {
        $pipeArguments = New-Object object[] 1
        $pipeArguments[0] = $Pipe.SafePipeHandle.PSObject.BaseObject
        $pipeProcessId = [uint32]$verifier.GetMethod('GetPipeServerProcessId').Invoke($null,$pipeArguments)
    }
    catch { throw 'NGCOR-PIPE-SERVER-PID-UNAVAILABLE' }
    try {
        $serviceArguments = New-Object object[] 1
        $serviceArguments[0] = [string]$Installed.serviceName
        $serviceProcessId = [uint32]$verifier.GetMethod('GetServiceProcessId').Invoke($null,$serviceArguments)
    }
    catch { throw 'NGCOR-PIPE-SERVER-SERVICE-UNAVAILABLE' }
    if ($pipeProcessId -ne $serviceProcessId) {
        throw 'NGCOR-PIPE-SERVER-PROCESS-MISMATCH'
    }
}

function Read-NgcorStandardInput {
    param([int]$MaximumBytes, [int]$TimeoutMilliseconds)
    $stream = [Console]::OpenStandardInput()
    $memory = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 4096
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    try {
        while ($true) {
            $remaining = [int][Math]::Max(1, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
            $task = $stream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $task.Wait($remaining)) { throw 'NGCOR-STDIN-TIMEOUT' }
            $count = $task.Result
            if ($count -eq 0) { break }
            if ($memory.Length + $count -gt $MaximumBytes) { throw 'NGCOR-STDIN-SIZE-EXCEEDED' }
            $memory.Write($buffer, 0, $count)
        }
        $bytes = $memory.ToArray()
        return ,$bytes
    }
    finally { $memory.Dispose() }
}

function Read-NgcorPipeExact {
    param([System.IO.Stream]$Stream, [int]$Count, [int]$TimeoutMilliseconds)
    $buffer = New-Object byte[] $Count
    $offset = 0
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($offset -lt $Count) {
        $remaining = [int][Math]::Max(1, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        $task = $Stream.ReadAsync($buffer, $offset, $Count - $offset)
        if (-not $task.Wait($remaining)) { throw 'NGCOR-PIPE-READ-TIMEOUT' }
        if ($task.Result -le 0) { throw 'NGCOR-PIPE-CLOSED' }
        $offset += $task.Result
    }
    $buffer
}

try {
    $installedRoot = Assert-NgcorInstalledLocation
    $protocolPath = Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
    Import-Module $protocolPath -Force -ErrorAction Stop

    $installedPath = Join-Path $installedRoot 'installed-release.json'
    $manifestPath = Join-Path $installedRoot 'release-manifest.json'
    try {
        $installedBytes = [IO.File]::ReadAllBytes($installedPath)
        $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
        $installed = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $installedBytes -MaximumBytes 1048576).Value
        $manifest = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $manifestBytes -MaximumBytes 1048576).Value
    }
    catch { throw 'NGCOR-INSTALLED-EVIDENCE-INVALID' }
    if ($installed.schema -cne 'northgate/create-only-installed-release/v1' -or
        $installed.serviceName -cne 'NorthGateCreateOnly' -or
        $manifest.releaseId -cne $installed.releaseId -or
        (Get-NgcorForcedFileSha256 $manifestPath) -cne $installed.releaseManifestSha256) {
        throw 'NGCOR-INSTALLED-EVIDENCE-BINDING-MISMATCH'
    }
    $ownRecord = @($manifest.files | Where-Object { $_.path -ceq 'Invoke-NorthGateCreateOnlyForcedCommand.ps1' })
    if ($ownRecord.Count -ne 1 -or (Get-NgcorForcedFileSha256 $PSCommandPath) -cne $ownRecord[0].sha256) {
        throw 'NGCOR-FORCED-HANDLER-INTEGRITY-FAILED'
    }

    $originalCommand = [Environment]::GetEnvironmentVariable('SSH_ORIGINAL_COMMAND', 'Process')
    if ($null -eq $originalCommand) { throw 'NGCOR-COMMAND-MISSING' }
    $parsedCommand = ConvertFrom-NorthGateCreateOnlyCommand $originalCommand

    if ($parsedCommand.operation -ceq 'plan') {
        $requestBytes = Read-NgcorStandardInput ($maximumPlanBytes + 1) 5000
        $parsedRequest = ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $requestBytes
        $body = $parsedRequest.CanonicalJson
    }
    else {
        $requestBytes = Read-NgcorStandardInput 1 2000
        if ($requestBytes.Length -ne 0) { throw 'NGCOR-STDIN-NOT-EMPTY' }
        $body = ''
    }

    $envelope = [pscustomobject][ordered]@{ version = 1; command = $originalCommand; body = $body }
    $payload = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope)
    )
    if ($payload.Length -gt 65536) { throw 'NGCOR-ENVELOPE-SIZE-INVALID' }

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation
    )
    try {
        $pipe.Connect(3000)
        Assert-NgcorPipeServerIdentity $pipe $installed $manifest $installedRoot
        $lengthBytes = [BitConverter]::GetBytes([int]$payload.Length)
        $pipe.Write($lengthBytes, 0, 4)
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()
        $responseLengthBytes = Read-NgcorPipeExact $pipe 4 10000
        $responseLength = [BitConverter]::ToInt32($responseLengthBytes, 0)
        if ($responseLength -le 0 -or $responseLength -gt $maximumResponseBytes) {
            throw 'NGCOR-PIPE-RESPONSE-SIZE-INVALID'
        }
        $responseBytes = Read-NgcorPipeExact $pipe $responseLength 10000
        try {
            $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
            $response = $strictUtf8.GetString($responseBytes)
        }
        catch { throw 'NGCOR-PIPE-RESPONSE-UTF8-INVALID' }
        try {
            $parsedResponse = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
                -Bytes $responseBytes -MaximumBytes $maximumResponseBytes).Value
        }
        catch { throw 'NGCOR-PIPE-RESPONSE-NONCANONICAL' }
        $properties = @($parsedResponse.PSObject.Properties.Name | Sort-Object)
        if ($parsedResponse.status -ceq 'ok') {
            if (($properties -join '|') -cne 'result|status') { throw 'NGCOR-PIPE-RESPONSE-CONTRACT-INVALID' }
            $exitCode = 0
        }
        elseif ($parsedResponse.status -ceq 'rejected') {
            if (($properties -join '|') -cne 'error|status' -or
                $parsedResponse.error -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') {
                throw 'NGCOR-PIPE-RESPONSE-CONTRACT-INVALID'
            }
            $exitCode = 1
        }
        else { throw 'NGCOR-PIPE-RESPONSE-CONTRACT-INVALID' }
        [Console]::Out.Write((ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $parsedResponse))
        exit $exitCode
    }
    finally { $pipe.Dispose() }
}
catch {
    $code = Get-NgcorForcedSafeErrorCode $_.Exception
    Stop-NgcorForcedCommand $code 1
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/6PTl9nlBuA8o
# Jll9cH5977jg62r3cjFDUZId46nxQ6CCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIG4l6j7d8gJGhND6QsN42Lgm3vvcHTRZomgtjoXLO+ckMA0GCSqG
# SIb3DQEBAQUABIIBgIUYCKzgdGFoojseL7/gQSicy7qlejK7WpENREAj/6cyT3gc
# iPF4THYeskinCHbhLM5MYXzn9+9bsqhq9/ooGN4CrNxuq6h5sYkg7W8DIaNTBDJ/
# 49gPAQVl38HSOAizbpYSCY+XWhrWNlqGHJmn18GSLCE2us//f1UPe0E3FGuYm8c4
# lntVp/gTTAGwDhnvsW2f+0GLxAhwP70cXKXiYsnaIFF8eJlx+Mu4y9qFEvKhAdzK
# +RwrqrWrq5aqE3UljEQpe/fysi8drtIJGccF75MxnxHrcL/RFo8QkEgYqAs21TMF
# f/9fERgleunb/X4CoX0P16F6VPQASzpaIiPVmqXlLLNCLw+dd5957xvfBiV8XP0Z
# sGCMTMxnsj5I7dZgdb4LKlkTM5aulwE811//btE4+Xy2ptB4Fy251YuPYZJ2Bw9B
# UrAJSbXLqVACFrerKK2S9mw3Ap7HPR/E8BwCdzKnzLZx4YDPb/b60eO4NZuQavo1
# wWt3aOF+NeZ6gkMrmQ==
# SIG # End signature block
