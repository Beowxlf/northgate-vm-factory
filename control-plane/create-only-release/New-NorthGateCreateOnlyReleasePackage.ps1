[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$SourceRoot,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidatePattern('^ngcor-[a-z0-9][a-z0-9.-]{7,63}$')][string]$ReleaseId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [Parameter(Mandatory)][ValidatePattern('^ngallow-[a-z0-9-]{8,64}$')][string]$HostAllowlistId,
    [Parameter(Mandatory)][ValidatePattern('^NG-GOV-[0-9]{8}-[A-Z0-9-]{3,32}$')][string]$GovernanceExceptionId,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$UnsignedServiceHostPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ServiceHostBuildProvenancePath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$SignedServiceHostPath,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ServiceHostDetachedCmsPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedReleaseSignerCertificateSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryIdentity = 'Beowxlf/northgate-vm-factory'
$repositoryRelativeSourceRoot = 'control-plane/create-only-release'
$acceptedOriginUrls = @(
    'https://github.com/Beowxlf/northgate-vm-factory',
    'https://github.com/Beowxlf/northgate-vm-factory.git',
    'git@github.com:Beowxlf/northgate-vm-factory.git',
    'ssh://git@github.com/Beowxlf/northgate-vm-factory.git'
)
$files = @(
    'NorthGate.VMFactory.CreateOnlyProtocol.psd1',
    'NorthGate.VMFactory.CreateOnlyProtocol.psm1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psd1',
    'NorthGate.VMFactory.CreateOnlyDeployment.psm1',
    'NorthGate.CreateOnly.ServiceHost.cs',
    'Build-NorthGateCreateOnlyServiceHost.ps1',
    'NorthGate.VMFactory.CreateOnlyService.psd1',
    'NorthGate.VMFactory.CreateOnlyService.psm1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psd1',
    'backend\NorthGate.VMFactory.CreateOnlyBackend.psm1',
    'backend\schemas\create-only-backend-policy.schema.json',
    'backend\schemas\create-only-data-bundle.schema.json',
    'backend\schemas\create-only-host-plan.schema.json',
    'backend\schemas\create-only-journal-event.schema.json',
    'backend\schemas\create-only-plan-approval.schema.json',
    'backend\schemas\create-only-rollout-promotion.schema.json',
    'backend\schemas\create-only-signed-receipt.schema.json',
    'Invoke-NorthGateCreateOnlyForcedCommand.ps1',
    'Start-NorthGateCreateOnlyPipeService.ps1',
    'Install-NorthGateCreateOnlyRelease.ps1',
    'New-NorthGateCreateOnlyApproval.ps1',
    'New-NorthGateCreateOnlyRolloutPromotion.ps1',
    'Rollback-NorthGateCreateOnlyRelease.ps1',
    'Test-NorthGateCreateOnlyHostAuthorization.ps1',
    'host-deployment-authorization.schema.json',
    'release-manifest.schema.json',
    'sshd_config.create-only.example',
    'README.md'
)
$serviceHostPath = 'NorthGate.CreateOnly.ServiceHost.exe'
$serviceHostDetachedCmsPackagePath = 'NorthGate.CreateOnly.ServiceHost.exe.p7s'
$packageInventoryPaths = @($files) + @($serviceHostPath,$serviceHostDetachedCmsPackagePath)
function Get-NgcorSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

$fixedAllowlistSha256 = Get-NgcorSha256Hex ([System.Text.Encoding]::UTF8.GetBytes(
    (@($packageInventoryPaths | ForEach-Object { $_.Replace('\','/') }) -join "`n")
))

function Get-NgcorFileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    $stream = New-Object System.IO.FileStream(
        $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
    )
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($stream) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgcorAuthenticodeFile {
    param([string]$Path, [string]$ExpectedPin)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($signature.Status -in @(
            [System.Management.Automation.SignatureStatus]::NotSigned,
            [System.Management.Automation.SignatureStatus]::HashMismatch,
            [System.Management.Automation.SignatureStatus]::NotSupportedFileFormat,
            [System.Management.Automation.SignatureStatus]::Incompatible
        ) -or $null -eq $signature.SignerCertificate -or
        (Get-NgcorSha256Hex $signature.SignerCertificate.RawData) -cne $ExpectedPin) {
        throw 'NGCOR-PACKAGE-AUTHENTICODE-INVALID'
    }
}

function Get-NgcorGitBlobRecordFromOpenStream {
    param([Parameter(Mandatory)][System.IO.FileStream]$Stream)
    if ($Stream.Length -le 0 -or $Stream.Length -gt 1048576) {
        throw 'NGCOR-PACKAGE-BLOB-SIZE-INVALID'
    }
    $memory = New-Object System.IO.MemoryStream
    try {
        $Stream.Position = 0
        $Stream.CopyTo($memory)
        $bytes = $memory.ToArray()
    }
    finally { $memory.Dispose() }
    $sha256 = Get-NgcorSha256Hex $bytes
    $header = [System.Text.Encoding]::ASCII.GetBytes('blob ' + $bytes.Length + [char]0)
    $gitObject = New-Object byte[] ($header.Length + $bytes.Length)
    [System.Buffer]::BlockCopy($header, 0, $gitObject, 0, $header.Length)
    [System.Buffer]::BlockCopy($bytes, 0, $gitObject, $header.Length, $bytes.Length)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $gitHash = $sha1.ComputeHash($gitObject) }
    finally { $sha1.Dispose() }
    [pscustomobject][ordered]@{
        sizeBytes = [int64]$bytes.Length
        sha256 = $sha256
        gitBlobOid = (($gitHash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
}

function ConvertTo-NgcorPackageJsonString {
    param([AllowEmptyString()][string]$Value)
    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $point = [int][char]$character
        switch ($point) {
            8 { $null = $builder.Append('\b'); break }
            9 { $null = $builder.Append('\t'); break }
            10 { $null = $builder.Append('\n'); break }
            12 { $null = $builder.Append('\f'); break }
            13 { $null = $builder.Append('\r'); break }
            34 { $null = $builder.Append('\"'); break }
            92 { $null = $builder.Append('\\'); break }
            default {
                if ($point -lt 32) { $null = $builder.Append(('\u{0:x4}' -f $point)) }
                else { $null = $builder.Append($character) }
            }
        }
    }
    $null = $builder.Append('"')
    $builder.ToString()
}

function ConvertTo-NgcorPackageCanonicalJson {
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)
    if ($null -eq $InputObject) { throw 'NGCOR-PACKAGE-CANONICAL-NULL-FORBIDDEN' }
    if ($InputObject -is [string]) { return ConvertTo-NgcorPackageJsonString ([string]$InputObject) }
    if ($InputObject -is [bool]) { if ($InputObject) { return 'true' } else { return 'false' } }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or
        $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int32] -or $InputObject -is [uint32] -or
        $InputObject -is [int64]) {
        return [System.Convert]::ToString($InputObject, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [System.Collections.IDictionary] -and
        $InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        $items = @()
        foreach ($item in $InputObject) { $items += ConvertTo-NgcorPackageCanonicalJson $item }
        return '[' + ($items -join ',') + ']'
    }
    $names = if ($InputObject -is [System.Collections.IDictionary]) {
        @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    else { @($InputObject.PSObject.Properties.Name) }
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    $properties = @()
    foreach ($name in $names) {
        $value = $null
        if ($InputObject -is [System.Collections.IDictionary]) { $value = $InputObject[$name] }
        else { $value = $InputObject.PSObject.Properties[$name].Value }
        $properties += (ConvertTo-NgcorPackageJsonString $name) + ':' +
            (ConvertTo-NgcorPackageCanonicalJson -InputObject $value)
    }
    '{' + ($properties -join ',') + '}'
}

function Assert-NgcorPackageExactProperties {
    param([object]$Value, [string[]]$Names, [string]$Code)
    if ($null -eq $Value) { throw $Code }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count) { throw $Code }
    foreach ($name in $Names) { if ($name -cnotin $actual) { throw $Code } }
}

function Read-NgcorPackageBytes {
    param([string]$Path, [int64]$MaximumBytes, [string]$Code)
    $full = [System.IO.Path]::GetFullPath($Path)
    Assert-NgcorNoReparseAncestor $full $Code
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw $Code }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) { throw $Code }
    $stream = New-Object System.IO.FileStream(
        $full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
    )
    try {
        $memory = New-Object System.IO.MemoryStream
        try { $stream.CopyTo($memory); $memory.ToArray() }
        finally { $memory.Dispose() }
    }
    finally { $stream.Dispose() }
}

function ConvertFrom-NgcorPackageJsonText {
    param([string]$Text)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Text -DateKind String
    }
    Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Text
}

function Get-NgcorCertificateSha256 {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if ($null -eq $Certificate) { throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNER-INVALID' }
    Get-NgcorSha256Hex $Certificate.RawData
}

function Assert-NgcorArtifactSigner {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$ExpectedPin)
    if ($null -eq $Certificate -or (Get-NgcorCertificateSha256 $Certificate) -cne $ExpectedPin) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNER-MISMATCH'
    }
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNER-INVALID'
    }
    $hasLeafConstraint = $false
    $hasCodeSigningEku = $false
    $hasDigitalSignatureUsage = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $hasLeafConstraint = $true
            if ($extension.CertificateAuthority) { throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNER-INVALID' }
        }
        elseif ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $hasCodeSigningEku = $true }
            }
        }
        elseif ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $hasDigitalSignatureUsage = [bool]($extension.KeyUsages -band
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)
            if ($extension.KeyUsages -band (
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign)) {
                throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNER-INVALID'
            }
        }
    }
    if (-not $hasLeafConstraint -or -not $hasCodeSigningEku -or -not $hasDigitalSignatureUsage) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNER-INVALID'
    }
}

function Test-NgcorArtifactDetachedCms {
    param([byte[]]$ContentBytes, [byte[]]$SignatureBytes, [string]$ExpectedPin)
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    try {
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($content, $true)
        $cms.Decode($SignatureBytes)
        if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1) {
            throw 'NGCOR-PACKAGE-SERVICE-HOST-CMS-INVALID'
        }
        if ($cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            throw 'NGCOR-PACKAGE-SERVICE-HOST-CMS-INVALID'
        }
        $cms.CheckSignature($true)
        Assert-NgcorArtifactSigner $cms.SignerInfos[0].Certificate $ExpectedPin
        $true
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        throw 'NGCOR-PACKAGE-SERVICE-HOST-CMS-INVALID'
    }
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

function Assert-NgcorNoReparseAncestor {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Code)
    $item = Get-Item -LiteralPath ([System.IO.Path]::GetFullPath($Path)) -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw $Code }
        $parent = [System.IO.Directory]::GetParent($item.FullName)
        if ($null -eq $parent) { break }
        $item = Get-Item -LiteralPath $parent.FullName -Force
    }
}

function Invoke-NgcorGitText {
    param([Parameter(Mandatory)][string]$RepositoryRoot, [Parameter(Mandatory)][string[]]$Arguments)
    $output = @(& git.exe --no-replace-objects -C $RepositoryRoot @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'NGCOR-PACKAGE-GIT-COMMAND-FAILED' }
    (@($output | ForEach-Object { [string]$_ }) -join "`n").TrimEnd("`r", "`n")
}

function Copy-NgcorGitBlob {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40,64}$')][string]$BlobOid,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = 'git.exe'
    $start.Arguments = '--no-replace-objects cat-file blob ' + $BlobOid
    $start.WorkingDirectory = $RepositoryRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    $destination = $null
    try {
        if (-not $process.Start()) { throw 'NGCOR-PACKAGE-GIT-CAT-FILE-FAILED' }
        $destination = New-Object System.IO.FileStream(
            $DestinationPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::WriteThrough
        )
        $process.StandardOutput.BaseStream.CopyTo($destination)
        $destination.Flush($true)
        $destination.Dispose()
        $destination = $null
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($errorText)) {
            throw 'NGCOR-PACKAGE-GIT-CAT-FILE-FAILED'
        }
    }
    finally {
        if ($null -ne $destination) { $destination.Dispose() }
        $process.Dispose()
    }
}

$dangerousGitEnvironmentNames = @(
    'GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_REPLACE_REF_BASE','GIT_INDEX_FILE',
    'GIT_CONFIG','GIT_CONFIG_GLOBAL','GIT_CONFIG_SYSTEM','GIT_CONFIG_COUNT','GIT_EXEC_PATH'
)
foreach ($variable in @([System.Environment]::GetEnvironmentVariables().Keys)) {
    $name = [string]$variable
    if ($name -in $dangerousGitEnvironmentNames -or $name -match '^GIT_CONFIG_(?:KEY|VALUE)_[0-9]+$') {
        throw 'NGCOR-PACKAGE-GIT-ENVIRONMENT-FORBIDDEN'
    }
}
if ($null -eq (Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue)) {
    throw 'NGCOR-PACKAGE-GIT-UNAVAILABLE'
}

$source = [System.IO.Path]::GetFullPath($SourceRoot).TrimEnd('\', '/')
$output = [System.IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$repositoryRoot = Invoke-NgcorGitText $source @('rev-parse','--show-toplevel')
$repositoryRoot = [System.IO.Path]::GetFullPath($repositoryRoot).TrimEnd('\', '/')
$expectedSource = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot $repositoryRelativeSourceRoot.Replace('/', '\'))
).TrimEnd('\', '/')
if ($source -cne $expectedSource) { throw 'NGCOR-PACKAGE-SOURCE-ROOT-INVALID' }
Assert-NgcorNoReparseAncestor $source 'NGCOR-PACKAGE-SOURCE-REPARSE-FORBIDDEN'
$executedBuilder = [System.IO.Path]::GetFullPath($PSCommandPath)
$expectedBuilder = [System.IO.Path]::GetFullPath((Join-Path $source 'New-NorthGateCreateOnlyReleasePackage.ps1'))
if ($executedBuilder -cne $expectedBuilder) { throw 'NGCOR-PACKAGE-BUILDER-LOCATION-INVALID' }

$origin = Invoke-NgcorGitText $repositoryRoot @('remote','get-url','origin')
if ($origin -cnotin $acceptedOriginUrls) { throw 'NGCOR-PACKAGE-REPOSITORY-IDENTITY-MISMATCH' }
if ((Invoke-NgcorGitText $repositoryRoot @('rev-parse','--show-object-format')) -cne 'sha1') {
    throw 'NGCOR-PACKAGE-GIT-OBJECT-FORMAT-UNSUPPORTED'
}
if (-not [string]::IsNullOrEmpty((Invoke-NgcorGitText $repositoryRoot @('for-each-ref','--format=%(refname)','refs/replace/')))) {
    throw 'NGCOR-PACKAGE-REPLACE-REF-FORBIDDEN'
}
$head = Invoke-NgcorGitText $repositoryRoot @('rev-parse','--verify','HEAD')
if ($head -cne $Commit) { throw 'NGCOR-PACKAGE-HEAD-COMMIT-MISMATCH' }
$resolvedCommit = Invoke-NgcorGitText $repositoryRoot @('rev-parse','--verify',($Commit + '^{commit}'))
if ($resolvedCommit -cne $Commit) { throw 'NGCOR-PACKAGE-COMMIT-INVALID' }
$derivedTree = Invoke-NgcorGitText $repositoryRoot @('rev-parse',($Commit + '^{tree}'))
if ($derivedTree -cne $Tree) { throw 'NGCOR-PACKAGE-COMMIT-TREE-MISMATCH' }
if (-not [string]::IsNullOrEmpty((Invoke-NgcorGitText $repositoryRoot @('status','--porcelain=v1','--untracked-files=all')))) {
    throw 'NGCOR-PACKAGE-WORKTREE-NOT-CLEAN'
}
if (-not [string]::IsNullOrEmpty((Invoke-NgcorGitText $repositoryRoot @('ls-tree','-r','--full-tree',$Commit,'--','.gitmodules')))) {
    throw 'NGCOR-PACKAGE-SUBMODULE-METADATA-FORBIDDEN'
}
$releaseTree = @((Invoke-NgcorGitText $repositoryRoot @(
    'ls-tree','-r','--full-tree',$Commit,'--',$repositoryRelativeSourceRoot
)) -split "`n")
foreach ($entry in $releaseTree) {
    if ([string]::IsNullOrWhiteSpace($entry)) { continue }
    if ($entry -notmatch '^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[a-f0-9]{40,64})\t') {
        throw 'NGCOR-PACKAGE-GIT-TREE-INVALID'
    }
    if ($Matches.mode -in @('120000','160000') -or $Matches.type -ne 'blob') {
        throw 'NGCOR-PACKAGE-GIT-SPECIAL-ENTRY-FORBIDDEN'
    }
}

$outputParent = Split-Path -Parent $output
if ([string]::IsNullOrWhiteSpace($outputParent) -or -not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw 'NGCOR-PACKAGE-OUTPUT-PARENT-MISSING'
}
Assert-NgcorNoReparseAncestor $outputParent 'NGCOR-PACKAGE-OUTPUT-REPARSE-FORBIDDEN'
if ($output.StartsWith($repositoryRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase) -or
    (Test-NgcorPathHasGitAncestor $outputParent)) {
    throw 'NGCOR-PACKAGE-OUTPUT-IN-REPOSITORY'
}
if (Test-Path -LiteralPath $output) { throw 'NGCOR-PACKAGE-OUTPUT-EXISTS' }

$lockedPackageStreams = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
try {
    $null = New-Item -ItemType Directory -Path $output -ErrorAction Stop
    $fileRecords = @()
    foreach ($relative in $files) {
        $gitPath = $repositoryRelativeSourceRoot + '/' + $relative.Replace('\','/')
        $treeEntry = Invoke-NgcorGitText $repositoryRoot @('ls-tree','--full-tree',$Commit,'--',$gitPath)
        if ($treeEntry -notmatch '^100644 blob (?<oid>[a-f0-9]{40,64})\t(?<path>.+)$' -or
            $Matches.path -cne $gitPath) {
            throw 'NGCOR-PACKAGE-SOURCE-BLOB-INVALID'
        }
        $blobOid = $Matches.oid
        $filterState = Invoke-NgcorGitText $repositoryRoot @('check-attr','filter','--',$gitPath)
        if ($filterState -notmatch ': filter: (?:unspecified|unset)$') {
            throw 'NGCOR-PACKAGE-CONTENT-FILTER-FORBIDDEN'
        }
        $destinationPath = Join-Path $output $relative
        $destinationParent = Split-Path -Parent $destinationPath
        if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
            $null = [IO.Directory]::CreateDirectory($destinationParent)
        }
        Copy-NgcorGitBlob -RepositoryRoot $repositoryRoot -BlobOid $blobOid -DestinationPath $destinationPath
        $destinationItem = Get-Item -LiteralPath $destinationPath -Force
        if ($destinationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'NGCOR-PACKAGE-DESTINATION-REPARSE-FORBIDDEN'
        }
        if ([IO.Path]::GetExtension($relative) -cin @('.ps1','.psm1','.psd1')) {
            Test-NgcorAuthenticodeFile $destinationPath $ExpectedReleaseSignerCertificateSha256
        }
        $lockedStream = New-Object System.IO.FileStream(
            $destinationPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
        )
        $lockedPackageStreams.Add($lockedStream)
        $blobRecord = Get-NgcorGitBlobRecordFromOpenStream $lockedStream
        if ($blobRecord.gitBlobOid -cne $blobOid) { throw 'NGCOR-PACKAGE-GIT-BLOB-HASH-MISMATCH' }
        $fileRecords += [pscustomobject][ordered]@{
            artifactKind = 'raw-git-blob'
            path = $relative.Replace('\','/')
            gitMode = '100644'
            gitBlobOid = $blobOid
            sizeBytes = $blobRecord.sizeBytes
            sha256 = $blobRecord.sha256
        }
    }

    $externalArtifactPaths = @(
        [IO.Path]::GetFullPath($UnsignedServiceHostPath),
        [IO.Path]::GetFullPath($ServiceHostBuildProvenancePath),
        [IO.Path]::GetFullPath($SignedServiceHostPath),
        [IO.Path]::GetFullPath($ServiceHostDetachedCmsPath)
    )
    if (@($externalArtifactPaths | Sort-Object -Unique).Count -ne 4) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-INPUT-COLLISION'
    }
    foreach ($artifactInput in $externalArtifactPaths) {
        Assert-NgcorNoReparseAncestor $artifactInput 'NGCOR-PACKAGE-SERVICE-HOST-INPUT-INVALID'
        if ($artifactInput.StartsWith($repositoryRoot + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase) -or
            $artifactInput.StartsWith($output + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'NGCOR-PACKAGE-SERVICE-HOST-INPUT-INVALID'
        }
    }

    $provenanceBytes = Read-NgcorPackageBytes $ServiceHostBuildProvenancePath 1048576 `
        'NGCOR-PACKAGE-SERVICE-HOST-PROVENANCE-INVALID'
    try {
        $provenanceText = (New-Object Text.UTF8Encoding($false,$true)).GetString($provenanceBytes)
        $buildProvenanceInput = ConvertFrom-NgcorPackageJsonText $provenanceText
    }
    catch { throw 'NGCOR-PACKAGE-SERVICE-HOST-PROVENANCE-INVALID' }
    if ((ConvertTo-NgcorPackageCanonicalJson $buildProvenanceInput) -cne $provenanceText) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-PROVENANCE-NONCANONICAL'
    }
    Assert-NgcorPackageExactProperties $buildProvenanceInput @(
        'schema','sourcePath','sourceSha256','buildScriptPath','buildScriptSha256',
        'compilerPath','compilerSha256','compilerVersion','deterministic','unsignedSha256','references'
    ) 'NGCOR-PACKAGE-SERVICE-HOST-PROVENANCE-INVALID'
    if ($buildProvenanceInput.schema -cne 'northgate/create-only-service-host-build-provenance/v1' -or
        $buildProvenanceInput.sourcePath -cne 'NorthGate.CreateOnly.ServiceHost.cs' -or
        $buildProvenanceInput.buildScriptPath -cne 'Build-NorthGateCreateOnlyServiceHost.ps1' -or
        $buildProvenanceInput.deterministic -ne $true -or
        $buildProvenanceInput.sourceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $buildProvenanceInput.buildScriptSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $buildProvenanceInput.compilerSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $buildProvenanceInput.unsignedSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$buildProvenanceInput.compilerPath) -or
        [string]::IsNullOrWhiteSpace([string]$buildProvenanceInput.compilerVersion)) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-PROVENANCE-INVALID'
    }
    $sourceRecord = @($fileRecords | Where-Object { $_.path -ceq $buildProvenanceInput.sourcePath })
    $buildRecord = @($fileRecords | Where-Object { $_.path -ceq $buildProvenanceInput.buildScriptPath })
    if ($sourceRecord.Count -ne 1 -or $buildRecord.Count -ne 1 -or
        $sourceRecord[0].sha256 -cne $buildProvenanceInput.sourceSha256 -or
        $buildRecord[0].sha256 -cne $buildProvenanceInput.buildScriptSha256) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-SOURCE-BINDING-MISMATCH'
    }

    $referenceRecords = @($buildProvenanceInput.references)
    $requiredReferenceNames = @(
        'mscorlib.dll','System.dll','System.Core.dll',
        'System.Management.Automation.dll','System.ServiceProcess.dll'
    )
    $seenReferenceNames = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $referenceByName = @{}
    if ($referenceRecords.Count -ne $requiredReferenceNames.Count) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-REFERENCES-INVALID'
    }
    foreach ($reference in $referenceRecords) {
        Assert-NgcorPackageExactProperties $reference @('path','sha256','fileVersion') `
            'NGCOR-PACKAGE-SERVICE-HOST-REFERENCES-INVALID'
        $referencePath = [IO.Path]::GetFullPath([string]$reference.path)
        $referenceName = [IO.Path]::GetFileName($referencePath)
        if ($referenceName -cnotin $requiredReferenceNames -or -not $seenReferenceNames.Add($referenceName) -or
            $reference.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            [string]::IsNullOrWhiteSpace([string]$reference.fileVersion)) {
            throw 'NGCOR-PACKAGE-SERVICE-HOST-REFERENCES-INVALID'
        }
        $referenceBytes = Read-NgcorPackageBytes $referencePath 67108864 `
            'NGCOR-PACKAGE-SERVICE-HOST-REFERENCE-INVALID'
        if ((Get-NgcorSha256Hex $referenceBytes) -cne $reference.sha256 -or
            [Diagnostics.FileVersionInfo]::GetVersionInfo($referencePath).FileVersion -cne
                [string]$reference.fileVersion) {
            throw 'NGCOR-PACKAGE-SERVICE-HOST-REFERENCE-MISMATCH'
        }
        $referenceByName[$referenceName] = $reference
    }
    $compilerInputPath = [IO.Path]::GetFullPath([string]$buildProvenanceInput.compilerPath)
    $compilerBytes = Read-NgcorPackageBytes $compilerInputPath 67108864 `
        'NGCOR-PACKAGE-SERVICE-HOST-COMPILER-INVALID'
    if ((Get-NgcorSha256Hex $compilerBytes) -cne $buildProvenanceInput.compilerSha256 -or
        [Diagnostics.FileVersionInfo]::GetVersionInfo($compilerInputPath).ProductVersion -cne
            [string]$buildProvenanceInput.compilerVersion) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-COMPILER-MISMATCH'
    }

    $unsignedBytes = Read-NgcorPackageBytes $UnsignedServiceHostPath 67108864 `
        'NGCOR-PACKAGE-SERVICE-HOST-UNSIGNED-INVALID'
    if ((Get-NgcorSha256Hex $unsignedBytes) -cne $buildProvenanceInput.unsignedSha256) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-UNSIGNED-MISMATCH'
    }

    $rebuildRoot = Join-Path $output ('service-host-rebuild-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($rebuildRoot)
    $rebuiltExecutable = Join-Path $rebuildRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $rebuiltProvenance = Join-Path $rebuildRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    try {
        $rebuildResult = & (Join-Path $output 'Build-NorthGateCreateOnlyServiceHost.ps1') `
            -OutputPath $rebuiltExecutable -ProvenancePath $rebuiltProvenance `
            -CompilerPath $compilerInputPath `
            -ExpectedSourceSha256 ([string]$buildProvenanceInput.sourceSha256) `
            -ExpectedCompilerSha256 ([string]$buildProvenanceInput.compilerSha256) `
            -ExpectedMscorlibAssemblySha256 ([string]$referenceByName['mscorlib.dll'].sha256) `
            -ExpectedSystemAssemblySha256 ([string]$referenceByName['System.dll'].sha256) `
            -ExpectedSystemCoreAssemblySha256 ([string]$referenceByName['System.Core.dll'].sha256) `
            -ExpectedAutomationAssemblySha256 ([string]$referenceByName['System.Management.Automation.dll'].sha256) `
            -ExpectedServiceProcessAssemblySha256 ([string]$referenceByName['System.ServiceProcess.dll'].sha256)
        if ($rebuildResult.outputSha256 -cne $buildProvenanceInput.unsignedSha256 -or
            (Get-NgcorFileSha256Hex $rebuiltExecutable) -cne $buildProvenanceInput.unsignedSha256 -or
            (Get-NgcorFileSha256Hex $rebuiltProvenance) -cne (Get-NgcorSha256Hex $provenanceBytes)) {
            throw 'NGCOR-PACKAGE-SERVICE-HOST-REBUILD-MISMATCH'
        }
    }
    finally {
        if (Test-Path -LiteralPath $rebuiltExecutable -PathType Leaf) { [IO.File]::Delete($rebuiltExecutable) }
        if (Test-Path -LiteralPath $rebuiltProvenance -PathType Leaf) { [IO.File]::Delete($rebuiltProvenance) }
        if ((Test-Path -LiteralPath $rebuildRoot -PathType Container) -and
            @([IO.Directory]::EnumerateFileSystemEntries($rebuildRoot)).Count -eq 0) {
            [IO.Directory]::Delete($rebuildRoot, $false)
        }
    }

    $signedBytes = Read-NgcorPackageBytes $SignedServiceHostPath 67108864 `
        'NGCOR-PACKAGE-SERVICE-HOST-SIGNED-INVALID'
    if ((Get-NgcorSha256Hex $signedBytes) -cne $buildProvenanceInput.unsignedSha256) {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-SIGNED-INVALID'
    }
    try {
        $assembly = [Reflection.AssemblyName]::GetAssemblyName([IO.Path]::GetFullPath($SignedServiceHostPath))
    }
    catch { throw 'NGCOR-PACKAGE-SERVICE-HOST-ASSEMBLY-INVALID' }
    if ($assembly.Name -cne 'NorthGate.CreateOnly.ServiceHost' -or $assembly.Version.ToString() -cne '1.0.0.0') {
        throw 'NGCOR-PACKAGE-SERVICE-HOST-ASSEMBLY-INVALID'
    }
    $cmsBytes = Read-NgcorPackageBytes $ServiceHostDetachedCmsPath 1048576 `
        'NGCOR-PACKAGE-SERVICE-HOST-CMS-INVALID'
    $null = Test-NgcorArtifactDetachedCms $signedBytes $cmsBytes $ExpectedReleaseSignerCertificateSha256

    $signedDestination = Join-Path $output $serviceHostPath
    $cmsDestination = Join-Path $output $serviceHostDetachedCmsPackagePath
    [IO.File]::WriteAllBytes($signedDestination, $signedBytes)
    [IO.File]::WriteAllBytes($cmsDestination, $cmsBytes)
    foreach ($artifactPath in @($signedDestination,$cmsDestination)) {
        Assert-NgcorNoReparseAncestor $artifactPath 'NGCOR-PACKAGE-SERVICE-HOST-COPY-INVALID'
        $stream = New-Object IO.FileStream(
            $artifactPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::Read, 65536, [IO.FileOptions]::SequentialScan
        )
        $lockedPackageStreams.Add($stream)
    }
    $fileRecords += [pscustomobject][ordered]@{
        artifactKind = 'derived-signed-artifact'
        path = $serviceHostPath
        sizeBytes = [int64]$signedBytes.Length
        sha256 = Get-NgcorSha256Hex $signedBytes
        buildProvenance = [pscustomobject][ordered]@{
            sourcePath = [string]$buildProvenanceInput.sourcePath
            sourceGitBlobOid = [string]$sourceRecord[0].gitBlobOid
            sourceSha256 = [string]$sourceRecord[0].sha256
            buildScriptPath = [string]$buildProvenanceInput.buildScriptPath
            buildScriptGitBlobOid = [string]$buildRecord[0].gitBlobOid
            buildScriptSha256 = [string]$buildRecord[0].sha256
            compilerPath = $compilerInputPath
            compilerSha256 = [string]$buildProvenanceInput.compilerSha256
            compilerVersion = [string]$buildProvenanceInput.compilerVersion
            deterministic = $true
            unsignedSha256 = [string]$buildProvenanceInput.unsignedSha256
            references = [object[]]$referenceRecords
        }
        detachedCms = [pscustomobject][ordered]@{
            path = $serviceHostDetachedCmsPackagePath
            sizeBytes = [int64]$cmsBytes.Length
            sha256 = Get-NgcorSha256Hex $cmsBytes
            signerCertificateSha256 = $ExpectedReleaseSignerCertificateSha256
        }
    }

    $actualInventory = @(Get-ChildItem -LiteralPath $output -Recurse -File | ForEach-Object {
        $_.FullName.Substring($output.Length).TrimStart('\').Replace('\','/')
    } | Sort-Object)
    $expectedInventory = @($packageInventoryPaths | ForEach-Object { $_.Replace('\','/') } | Sort-Object)
    if (($actualInventory -join '|') -cne ($expectedInventory -join '|')) {
        throw 'NGCOR-PACKAGE-INVENTORY-MISMATCH'
    }
    $signatureStatus = Invoke-NgcorGitText $repositoryRoot @('log','-1','--format=%G?',$Commit)
    if ($signatureStatus -notmatch '^[GUBXYREN]$') { $signatureStatus = 'unknown' }
    $manifest = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-release-manifest/v2'
        releaseId = $ReleaseId
        repository = [pscustomobject][ordered]@{
            identity = $repositoryIdentity
            origin = $origin
            commit = $resolvedCommit
            tree = $derivedTree
            objectFormat = 'sha1'
            commitSignatureStatus = $signatureStatus
            hostAllowlistId = $HostAllowlistId
            packageAllowlistSha256 = $fixedAllowlistSha256
            governanceExceptionId = $GovernanceExceptionId
        }
        sourceProof = [pscustomobject][ordered]@{
            sourceKind = 'raw-git-blobs-plus-derived-signed-artifact'
            headEqualsCommit = $true
            cleanWorktree = $true
            replaceRefsAbsent = $true
            submodulesAbsent = $true
            contentFiltersAbsent = $true
        }
        packageSemantics = [pscustomobject][ordered]@{
            sourceExecutableOnHost = $true
            installInitiallyEnabled = $false
            liveApplyImplemented = $true
            allowedProtocolCommands = @(
                'status','plan','approval-context','approve',
                'rollout-context','promote-rollout','apply','receipt'
            )
        }
        files = $fileRecords
    }
    $manifestJson = ConvertTo-NgcorPackageCanonicalJson $manifest
    $manifestPath = Join-Path $output 'release-manifest.json'
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson, (New-Object System.Text.UTF8Encoding($false)))
    $manifestHash = Get-NgcorFileSha256Hex $manifestPath
    [System.IO.File]::WriteAllText(
        (Join-Path $output 'release-manifest.sha256'),
        ($manifestHash + '  release-manifest.json' + [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false))
    )
    [pscustomobject][ordered]@{
        status = 'package-generated-with-verified-source-and-signed-derived-artifact-manifest-unsigned'
        releaseId = $ReleaseId
        packageRoot = $output
        repositoryCommit = $resolvedCommit
        repositoryTree = $derivedTree
        releaseManifestSha256 = $manifestHash
        installable = $false
        nextGate = 'detached-manifest-signing-and-pinned-bootstrap-verifier'
    }
}
catch {
    # Preserve partial output for forensic review. Never recursively delete a
    # caller-selected path, even when this process created the directory.
    throw
}
finally {
    foreach ($stream in $lockedPackageStreams) { $stream.Dispose() }
}
