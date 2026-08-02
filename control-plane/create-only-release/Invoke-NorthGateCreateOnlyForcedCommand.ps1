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
    if ($null -eq ('NorthGateCreateOnlyPipeIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class NorthGateCreateOnlyPipeIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    public static string GetServerImagePath(SafePipeHandle pipe) {
        uint pid;
        if (!GetNamedPipeServerProcessId(pipe, out pid)) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr process = OpenProcess(0x1000, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            StringBuilder path = new StringBuilder(32768);
            uint size = (uint)path.Capacity;
            if (!QueryFullProcessImageName(process, 0, path, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return path.ToString();
        }
        finally { CloseHandle(process); }
    }
}
'@
    }
    try { $actualPath = [NorthGateCreateOnlyPipeIdentity]::GetServerImagePath($Pipe.SafePipeHandle) }
    catch { throw 'NGCOR-PIPE-SERVER-IDENTITY-UNVERIFIABLE' }
    $expectedPath = Join-Path $InstalledRoot ([string]$Installed.serviceHostFileName)
    if ([IO.Path]::GetFullPath($actualPath) -cne [IO.Path]::GetFullPath($expectedPath)) {
        throw 'NGCOR-PIPE-SERVER-IMAGE-MISMATCH'
    }
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
        $memory.ToArray()
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
        [System.Security.Principal.TokenImpersonationLevel]::Identification
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
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') { $code = 'NGCOR-REQUEST-REJECTED' }
    Stop-NgcorForcedCommand $code 1
}
