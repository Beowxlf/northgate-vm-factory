[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$SourceRoot,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidatePattern('^ngcor-[a-z0-9][a-z0-9.-]{7,63}$')][string]$ReleaseId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [Parameter(Mandatory)][ValidatePattern('^ngallow-[a-z0-9-]{8,64}$')][string]$HostAllowlistId,
    [Parameter(Mandatory)][ValidatePattern('^NG-GOV-[0-9]{8}-[A-Z0-9-]{3,32}$')][string]$GovernanceExceptionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryIdentity = 'Beowxlf/northgate-vm-factory'
$files = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
    'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyRelease.psd1',
    'NorthGate.VMFactory.CreateOnlyRelease.psm1',
    'Invoke-NorthGateCreateOnlyForcedCommand.ps1',
    'Start-NorthGateCreateOnlyPipeService.ps1',
    'Install-NorthGateCreateOnlyRelease.ps1',
    'New-NorthGateCreateOnlyApproval.ps1',
    'Rollback-NorthGateCreateOnlyRelease.ps1',
    'host-deployment-authorization.schema.json',
    'sshd_config.create-only.example',
    'README.md'
)

function Get-NgcorFileHashFromOpenStream {
    param([System.IO.FileStream]$Stream)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        $hash = $algorithm.ComputeHash($Stream)
        (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $algorithm.Dispose() }
}

function Test-NgcorPathHasGitAncestor {
    param([string]$Path)
    $item = New-Object System.IO.DirectoryInfo([System.IO.Path]::GetFullPath($Path))
    while ($null -ne $item) {
        if (Test-Path -LiteralPath (Join-Path $item.FullName '.git')) { return $true }
        $item = $item.Parent
    }
    $false
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-NgcorPathHasGitAncestor $source)) { throw 'NGCOR-PACKAGE-SOURCE-NOT-REPOSITORY' }
if ($output.StartsWith($source + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase) -or
    (Test-NgcorPathHasGitAncestor (Split-Path -Parent $output))) {
    throw 'NGCOR-PACKAGE-OUTPUT-IN-REPOSITORY'
}
if (Test-Path -LiteralPath $output) { throw 'NGCOR-PACKAGE-OUTPUT-EXISTS' }

try {
    $null = New-Item -ItemType Directory -Path $output -ErrorAction Stop
    $fileRecords = @()
    foreach ($relative in $files) {
        $sourcePath = Join-Path $source $relative
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw 'NGCOR-PACKAGE-SOURCE-FILE-MISSING'
        }
        $sourceItem = Get-Item -LiteralPath $sourcePath -Force
        if ($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'NGCOR-PACKAGE-SOURCE-REPARSE-FORBIDDEN'
        }
        $destinationPath = Join-Path $output $relative
        $sourceStream = New-Object System.IO.FileStream(
            $sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
        )
        try {
            $destinationStream = New-Object System.IO.FileStream(
                $destinationPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::WriteThrough
            )
            try { $sourceStream.CopyTo($destinationStream); $destinationStream.Flush($true) }
            finally { $destinationStream.Dispose() }
            $sourceHash = Get-NgcorFileHashFromOpenStream $sourceStream
        }
        finally { $sourceStream.Dispose() }
        $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceHash -cne $destinationHash) { throw 'NGCOR-PACKAGE-COPY-HASH-MISMATCH' }
        $fileRecords += [pscustomobject][ordered]@{
            path = $relative.Replace('\','/')
            sizeBytes = [int64](Get-Item -LiteralPath $destinationPath).Length
            sha256 = $destinationHash
        }
    }
    $manifest = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-release-manifest/v1'
        releaseId = $ReleaseId
        repository = [pscustomobject][ordered]@{
            identity = $repositoryIdentity; commit = $Commit; tree = $Tree
            hostAllowlistId = $HostAllowlistId; governanceExceptionId = $GovernanceExceptionId
        }
        packageSemantics = [pscustomobject][ordered]@{
            sourceExecutableOnHost = $false
            installInitiallyEnabled = $false
            liveApplyImplemented = $false
            allowedProtocolCommands = @('status','plan','apply','receipt')
        }
        files = $fileRecords
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 16 -Compress
    $manifestPath = Join-Path $output 'release-manifest.json'
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson, (New-Object System.Text.UTF8Encoding($false)))
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        (Join-Path $output 'release-manifest.sha256'),
        ($manifestHash + '  release-manifest.json' + [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false))
    )
    [pscustomobject][ordered]@{
        status = 'package-generated-unsigned'
        releaseId = $ReleaseId
        packageRoot = $output
        releaseManifestSha256 = $manifestHash
        installable = $false
        nextGate = 'separate-signed-host-deployment-authorization'
    }
}
catch {
    # Preserve any partial output for forensic review. Never recursively delete a
    # caller-selected path, even when this process created the directory.
    throw
}
