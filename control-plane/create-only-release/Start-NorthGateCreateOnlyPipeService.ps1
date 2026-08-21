[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$maximumFrameBytes = 65536
if ($null -eq (Get-Variable -Name NorthGateServiceStopEvent -ErrorAction SilentlyContinue) -or
    $NorthGateServiceStopEvent -isnot [System.Threading.ManualResetEvent]) {
    throw 'NGCOR-SERVICE-HOST-CONTROL-MISSING'
}
$serviceStopEvent = $NorthGateServiceStopEvent

function Get-NgcorFileSha256Hex {
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

function Assert-NgcorNoReparsePath {
    param([string]$Path, [string]$Code)
    $cursor = [System.IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $cursor) -and -not [string]::IsNullOrWhiteSpace($cursor)) {
        $cursor = Split-Path -Parent $cursor
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and (Test-Path -LiteralPath $cursor)) {
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw $Code
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-NgcorServiceInstalled {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
    $root = [System.IO.Path]::GetFullPath($PSScriptRoot)
    Assert-NgcorNoReparsePath $root 'NGCOR-INSTALLED-RELEASE-REPARSE-FORBIDDEN'
    if (-not $root.StartsWith($requiredPrefix + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath (Join-Path $root 'installed-release.json') -PathType Leaf)) {
        throw 'NGCOR-CHECKOUT-EXECUTION-FORBIDDEN'
    }
    $root
}

function Read-NgcorExact {
    param([System.IO.Stream]$Stream, [int]$Count, [int]$TimeoutMilliseconds)
    $bytes = New-Object byte[] $Count
    $offset = 0
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($offset -lt $Count) {
        $remaining = [int][Math]::Max(1, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        $task = $Stream.ReadAsync($bytes, $offset, $Count - $offset)
        if (-not $task.Wait($remaining)) { throw 'NGCOR-PIPE-READ-TIMEOUT' }
        if ($task.Result -le 0) { throw 'NGCOR-PIPE-CLOSED' }
        $offset += $task.Result
    }
    $bytes
}

function Write-NgcorResponse {
    param([System.IO.Stream]$Stream, [object]$Response)
    $json = ConvertTo-NorthGateCreateOnlyCanonicalJson $Response
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt $maximumFrameBytes) { throw 'NGCOR-RESPONSE-SIZE-EXCEEDED' }
    $length = [BitConverter]::GetBytes([int]$bytes.Length)
    $Stream.Write($length, 0, 4)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function ConvertFrom-NgcorServiceJsonText {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

$installedRoot = Assert-NgcorServiceInstalled
Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force
$deployment = Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyDeployment.psd1') `
    -Force -PassThru
Import-Module (Join-Path $installedRoot 'backend\NorthGate.VMFactory.CreateOnlyBackend.psd1') -Force
Import-Module (Join-Path $installedRoot 'NorthGate.VMFactory.CreateOnlyService.psd1') -Force

$installedPath = Join-Path $installedRoot 'installed-release.json'
$manifestPath = Join-Path $installedRoot 'release-manifest.json'
$authorizationPath = Join-Path $installedRoot 'deployment-authorization.json'
$manifestSignaturePath = Join-Path $installedRoot 'release-manifest.p7s'
$authorizationSignaturePath = Join-Path $installedRoot 'deployment-authorization.p7s'
$backendPolicyPath = Join-Path $installedRoot 'backend-policy.json'
$backendPolicySignaturePath = Join-Path $installedRoot 'backend-policy.p7s'
$dataBundlePath = Join-Path $installedRoot 'backend-data\bundle.json'
$dataBundleSignaturePath = Join-Path $installedRoot 'backend-data\bundle.p7s'
foreach ($path in @(
        $installedPath,$manifestPath,$authorizationPath,$manifestSignaturePath,
        $authorizationSignaturePath,$backendPolicyPath,$backendPolicySignaturePath,
        $dataBundlePath,$dataBundleSignaturePath
    )) {
    Assert-NgcorNoReparsePath $path 'NGCOR-INSTALLED-EVIDENCE-REPARSE-FORBIDDEN'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'NGCOR-INSTALLED-EVIDENCE-MISSING' }
}
try {
    $installedRaw = [IO.File]::ReadAllText($installedPath)
    $manifestRaw = [IO.File]::ReadAllText($manifestPath)
    $authorizationRaw = [IO.File]::ReadAllText($authorizationPath)
    $installed = ConvertFrom-NgcorServiceJsonText $installedRaw
    $manifest = ConvertFrom-NgcorServiceJsonText $manifestRaw
    $authorization = ConvertFrom-NgcorServiceJsonText $authorizationRaw
}
catch { throw 'NGCOR-INSTALLED-EVIDENCE-INVALID' }
if ((ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $installed) -cne $installedRaw -or
    (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $manifest) -cne $manifestRaw -or
    (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $authorization) -cne $authorizationRaw -or
    $installed.schema -cne 'northgate/create-only-installed-release/v1' -or
    $manifest.releaseId -cne $installed.releaseId -or
    $authorization.repository.releaseId -cne $installed.releaseId -or
    (Get-NgcorFileSha256Hex $manifestPath) -cne $installed.releaseManifestSha256 -or
    (Get-NgcorFileSha256Hex $authorizationPath) -cne $installed.deploymentAuthorizationSha256 -or
    (Get-NgcorFileSha256Hex $backendPolicyPath) -cne $installed.backendPolicySha256 -or
    (Get-NgcorFileSha256Hex $dataBundlePath) -cne $installed.dataBundleSha256) {
    throw 'NGCOR-INSTALLED-EVIDENCE-BINDING-MISMATCH'
}
$runtimeContext = & $deployment { param($Authorization) Get-NgcdRuntimeContext $Authorization } $authorization
$runtimeStatus = Test-NorthGateCreateOnlyInstalledRelease -Context $runtimeContext `
    -Manifest $manifest -Authorization $authorization `
    -AuthorizationSha256 ([string]$installed.deploymentAuthorizationSha256)
if ($runtimeStatus.status -cne 'verified') { throw 'NGCOR-INSTALLED-RELEASE-NOT-VERIFIED' }

$commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$policyPath = Join-Path $commonData 'NorthGate\VMFactory\CreateOnly\policy\installed-policy.json'
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw 'NGCOR-INSTALLED-POLICY-MISSING' }
if ((Get-Item -LiteralPath $policyPath -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw 'NGCOR-INSTALLED-POLICY-REPARSE-FORBIDDEN'
}

$policyRaw = [System.IO.File]::ReadAllText($policyPath)
try { $policy = ConvertFrom-NgcorServiceJsonText $policyRaw }
catch { throw 'NGCOR-INSTALLED-POLICY-INVALID' }
if ((ConvertTo-NorthGateCreateOnlyCanonicalJson $policy) -cne $policyRaw -or
    $policy.schema -cne 'northgate/create-only-installed-policy/v1' -or
    $policy.releaseId -cne $installed.releaseId -or
    $policy.releaseManifestSha256 -cne $installed.releaseManifestSha256 -or
    $policy.pipeName -cne $pipeName -or
    $policy.sshIdentitySid -cne $installed.sshIdentitySid -or
    $policy.serviceIdentitySid -cne $installed.serviceIdentitySid -or
    $policy.serviceName -cne 'NorthGateCreateOnly' -or
    $policy.serviceHostSignerCertificateSha256 -cne $installed.releaseSignerCertificateSha256 -or
    $policy.backendPolicySha256 -cne $installed.backendPolicySha256 -or
    $policy.dataBundleSha256 -cne $installed.dataBundleSha256 -or
    $policy.applyEnabled -ne [bool]$authorization.initialPolicy.applyEnabled -or
    (@($policy.executableActions) -join '|') -cne (@($authorization.initialPolicy.executableActions) -join '|') -or
    $policy.canaryStage -cne [string]$authorization.initialPolicy.canaryStage) {
    throw 'NGCOR-INSTALLED-POLICY-INVALID'
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSids = @([string]$currentIdentity.User.Value) + @($currentIdentity.Groups | ForEach-Object { [string]$_.Value })
if ($policy.serviceIdentitySid -notin $currentSids) { throw 'NGCOR-SERVICE-IDENTITY-MISMATCH' }
$serviceHostPath = Join-Path $installedRoot ([string]$installed.serviceHostFileName)
$serviceHostRecords = @($manifest.files | Where-Object {
    $_.artifactKind -ceq 'derived-signed-artifact' -and $_.path -ceq $installed.serviceHostFileName
})
if ($serviceHostRecords.Count -ne 1 -or
    $serviceHostRecords[0].detachedCms.signerCertificateSha256 -cne
        $installed.releaseSignerCertificateSha256) {
    throw 'NGCOR-SERVICE-HOST-SIGNATURE-INVALID'
}
$serviceHostBytes = [IO.File]::ReadAllBytes($serviceHostPath)
$serviceHostCmsPath = Join-Path $installedRoot ([string]$serviceHostRecords[0].detachedCms.path)
$null = & $deployment {
    param($Bytes,$SignaturePath,$Pin)
    Test-NgcdDetachedCms $Bytes $SignaturePath $Pin
} $serviceHostBytes $serviceHostCmsPath ([string]$installed.releaseSignerCertificateSha256)
$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='NorthGateCreateOnly'" -ErrorAction Stop
$expectedServicePath = '"' + $serviceHostPath + '" --script "' +
    (Join-Path $installedRoot 'Start-NorthGateCreateOnlyPipeService.ps1') + '"'
if ($service.PathName -cne $expectedServicePath -or $service.StartMode -cne 'Auto' -or
    $service.StartName -cne 'NT SERVICE\NorthGateCreateOnly') {
    throw 'NGCOR-SERVICE-REGISTRATION-MISMATCH'
}

$backendContext = New-NorthGateCreateOnlyBackendContext `
    -StateRoot ([string]$installed.backendStateRoot) `
    -DataRoot ([string]$installed.backendDataRoot) `
    -StateKeyPath ([string]$installed.backendStateKeyPath) `
    -ReleaseManifestPath $manifestPath `
    -ReleaseManifestSignaturePath $manifestSignaturePath `
    -ExpectedReleaseManifestSha256 ([string]$installed.releaseManifestSha256) `
    -ExpectedReleaseSignerCertificateSha256 ([string]$installed.releaseSignerCertificateSha256) `
    -HostAuthorizationPath $authorizationPath `
    -HostAuthorizationSignaturePath $authorizationSignaturePath `
    -ExpectedHostAuthorizationSha256 ([string]$installed.deploymentAuthorizationSha256) `
    -ExpectedHostAuthorizationSignerCertificateSha256 `
        ([string]$installed.deploymentAuthorizationSignerCertificateSha256) `
    -BackendPolicyPath $backendPolicyPath `
    -BackendPolicySignaturePath $backendPolicySignaturePath `
    -ExpectedBackendPolicySha256 ([string]$installed.backendPolicySha256) `
    -DataBundlePath $dataBundlePath `
    -DataBundleSignaturePath $dataBundleSignaturePath `
    -ExpectedDataBundleSha256 ([string]$installed.dataBundleSha256)

$sshSid = New-Object System.Security.Principal.SecurityIdentifier([string]$policy.sshIdentitySid)
$systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$security = New-Object System.IO.Pipes.PipeSecurity
$security.SetAccessRuleProtection($true, $false)
$sshRule = New-Object System.IO.Pipes.PipeAccessRule(
    $sshSid, [System.IO.Pipes.PipeAccessRights]::ReadWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$systemRule = New-Object System.IO.Pipes.PipeAccessRule(
    $systemSid, [System.IO.Pipes.PipeAccessRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$security.AddAccessRule($sshRule)
$security.AddAccessRule($systemRule)
$administratorRule = New-Object System.IO.Pipes.PipeAccessRule(
    $administratorsSid, [System.IO.Pipes.PipeAccessRights]::ReadWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$security.AddAccessRule($administratorRule)

while (-not $serviceStopEvent.WaitOne(0)) {
    $options = [System.IO.Pipes.PipeOptions]::Asynchronous -bor [System.IO.Pipes.PipeOptions]::WriteThrough
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
        $pipeName, [System.IO.Pipes.PipeDirection]::InOut, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, $options,
        $maximumFrameBytes, $maximumFrameBytes, $security
    )
    try {
        $connectionTask = $pipe.WaitForConnectionAsync()
        while (-not $connectionTask.Wait(250)) {
            if ($serviceStopEvent.WaitOne(0)) { break }
        }
        if ($serviceStopEvent.WaitOne(0)) { break }
        $connectionTask.GetAwaiter().GetResult()
        $identityBox = New-Object 'System.Collections.Generic.List[object]'
        $pipe.RunAsClient([System.Action]{
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent($true)
            $groupSids = @($identity.Groups | ForEach-Object { [string]$_.Value })
            $identityBox.Add([pscustomobject]@{
                Sid = [string]$identity.User.Value
                IsAdministrator = ('S-1-5-32-544' -in $groupSids)
            })
        })
        if ($identityBox.Count -ne 1 -or
            ($identityBox[0].Sid -cne $policy.sshIdentitySid -and -not $identityBox[0].IsAdministrator)) {
            throw 'NGCOR-PIPE-CLIENT-IDENTITY-MISMATCH'
        }
        $lengthBytes = Read-NgcorExact $pipe 4 3000
        $length = [BitConverter]::ToInt32($lengthBytes, 0)
        if ($length -le 0 -or $length -gt $maximumFrameBytes) { throw 'NGCOR-ENVELOPE-SIZE-INVALID' }
        $requestBytes = Read-NgcorExact $pipe $length 5000
        $envelope = ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes $requestBytes
        try {
            if (-not [bool]$policy.applyEnabled) {
                if ($envelope.Operation -cne 'status') { throw 'NGCOR-INSTALLED-POLICY-DISABLED' }
                $result = [pscustomobject][ordered]@{
                    status = 'installed-disabled'
                    releaseId = [string]$policy.releaseId
                    applyEnabled = $false
                    executableActions = [object[]]@()
                    canaryStage = 'disabled'
                }
            }
            else {
                $result = Invoke-NorthGateCreateOnlyBackendServiceRequest `
                    -Context $backendContext -Operation $envelope.Operation -PlanId $envelope.PlanId `
                    -BodyBytes $envelope.BodyBytes -ActorSid ([string]$identityBox[0].Sid) `
                    -ActorIsAdministrator ([bool]$identityBox[0].IsAdministrator) `
                    -SshIdentitySid ([string]$policy.sshIdentitySid) `
                    -ServiceIdentitySid ([string]$policy.serviceIdentitySid)
            }
            Write-NgcorResponse $pipe ([pscustomobject][ordered]@{ status = 'ok'; result = $result })
        }
        catch {
            $code = [string]$_.Exception.Message
            if ($code -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') { $code = 'NGCOR-SERVICE-FAILURE' }
            Write-NgcorResponse $pipe ([pscustomobject][ordered]@{ status = 'rejected'; error = $code })
        }
    }
    catch {
        if ($pipe.IsConnected) {
            try {
                $code = [string]$_.Exception.Message
                if ($code -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') { $code = 'NGCOR-SERVICE-FAILURE' }
                Write-NgcorResponse $pipe ([pscustomobject][ordered]@{ status = 'rejected'; error = $code })
            } catch { }
        }
    }
    finally { $pipe.Dispose() }
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBiNYhuu4KTybeG
# 2SJ/7eojLCm6Zhf8Lq4vibS3zhIElqCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIFyzmSdhYCFJ2YFCRZ8ooIglXqn42zjNvKqoFH3Yah+LMA0GCSqG
# SIb3DQEBAQUABIIBgJva+r83cSLlb8pR3lYq+4hnCAuZIX4hAH/FoJIv0eLZwEFy
# herB8YLwHoWXT4Ni5nss4ZlVbVrl5+P38qCgivuvkaJSdw5uftxzujVxdVbrrgAk
# Kb/t1IjXrBs4oD4dfv+bTSDrG11Mx+v3QHeY/h6sgDpp7sX+KouEVVJr/u5qdNno
# h682MzO/Jj++X68rEKVuCtqc35uFU/ywnldxY6BwlPmlecJaPIa85JW1ls04BQCe
# bU5wyMLPTFf4rOjEIVoBMyx+1Dj8TKUu1WW3PU4+WflCrsYwkDoqwIL79fjulxo/
# 2dhGfCzDiJAEZ+lyb2ZY5mDcplBqJboLs8sIuiph0IupmboVdgP8twxYPuqCV396
# jEwQyQA+zXQVaLpyY8xfCUILfqjQAuLHifPaj55SRwWMzu55y0k3l4712XMj9AW4
# A6TdYh4xSqEGulkfvc2SbcB8qYutB+lZcNsOr0T+zp3FhnK3r/2EBD2OpskVWwBW
# nLQ5Cx3W+UM7hPTvTQ==
# SIG # End signature block
