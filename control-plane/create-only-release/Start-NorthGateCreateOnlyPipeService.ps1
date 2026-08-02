[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$maximumFrameBytes = 65536

function Assert-NgcorServiceInstalled {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
    $root = [System.IO.Path]::GetFullPath($PSScriptRoot)
    if (-not $root.StartsWith($requiredPrefix + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath (Join-Path $root 'installed-release.json') -PathType Leaf)) {
        throw 'NGCOR-CHECKOUT-EXECUTION-FORBIDDEN'
    }
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

Assert-NgcorServiceInstalled
$commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$policyPath = Join-Path $commonData 'NorthGate\VMFactory\CreateOnly\policy\installed-policy.json'
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw 'NGCOR-INSTALLED-POLICY-MISSING' }
if ((Get-Item -LiteralPath $policyPath -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw 'NGCOR-INSTALLED-POLICY-REPARSE-FORBIDDEN'
}

Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force
Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyRelease.psd1') -Force
$policyRaw = [System.IO.File]::ReadAllText($policyPath)
try { $policy = $policyRaw | ConvertFrom-Json }
catch { throw 'NGCOR-INSTALLED-POLICY-INVALID' }
if ((ConvertTo-NorthGateCreateOnlyCanonicalJson $policy) -cne $policyRaw -or
    $policy.schema -cne 'northgate/create-only-installed-policy/v1' -or
    $policy.pipeName -cne $pipeName -or
    $policy.sshIdentitySid -cnotmatch '^S-1-[0-9-]+$' -or
    $policy.applyEnabled -ne $false -or @($policy.executableActions).Count -ne 0 -or
    $policy.canaryStage -cne 'disabled') {
    throw 'NGCOR-INSTALLED-POLICY-INVALID'
}

$sshSid = New-Object System.Security.Principal.SecurityIdentifier([string]$policy.sshIdentitySid)
$systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
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

while ($true) {
    $options = [System.IO.Pipes.PipeOptions]::Asynchronous -bor [System.IO.Pipes.PipeOptions]::WriteThrough
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
        $pipeName, [System.IO.Pipes.PipeDirection]::InOut, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, $options,
        $maximumFrameBytes, $maximumFrameBytes, $security
    )
    try {
        $pipe.WaitForConnection()
        $identityBox = New-Object 'System.Collections.Generic.List[string]'
        $pipe.RunAsClient([System.Action]{
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent($true)
            $identityBox.Add($identity.User.Value)
        })
        if ($identityBox.Count -ne 1 -or $identityBox[0] -cne $policy.sshIdentitySid) {
            throw 'NGCOR-PIPE-CLIENT-IDENTITY-MISMATCH'
        }
        $lengthBytes = Read-NgcorExact $pipe 4 3000
        $length = [BitConverter]::ToInt32($lengthBytes, 0)
        if ($length -le 0 -or $length -gt $maximumFrameBytes) { throw 'NGCOR-ENVELOPE-SIZE-INVALID' }
        $requestBytes = Read-NgcorExact $pipe $length 5000
        $envelope = ConvertFrom-NorthGateCreateOnlyServiceEnvelopeBytes $requestBytes
        try {
            $result = Invoke-NorthGateCreateOnlyServiceRequest `
                -Command $envelope.Command -RequestBytes $envelope.BodyBytes -ActorSid $identityBox[0]
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
