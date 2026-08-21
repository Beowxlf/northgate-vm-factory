Set-StrictMode -Version Latest

$releaseRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$protocolManifest = Join-Path $releaseRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
$backendManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'NorthGate.VMFactory.CreateOnlyBackend.psd1'
Import-Module $protocolManifest -Force -ErrorAction Stop
$script:BackendModule = Import-Module $backendManifest -Force -PassThru -ErrorAction Stop

$script:RepositoryIdentity = 'Beowxlf/northgate-vm-factory'
$script:MaximumArtifactBytes = 1048576
$script:MaximumClockSkewSeconds = 300
$script:ApprovalMutexName = 'Global\NorthGateVmFactoryCreateOnlyApprovalAuthoring-v1'
$script:InertTestCertificateResolver = $null
$script:CoreCatalogRoles = [ordered]@{
    'catalog/images.json' = 'imageCatalog'
    'catalog/networks.json' = 'networkCatalog'
    'catalog/storage-profiles.json' = 'storageCatalog'
    'catalog/firmware-profiles.json' = 'firmwareCatalog'
    'catalog/bootstrap-profiles.json' = 'bootstrapCatalog'
    'catalog/recovery-profiles.json' = 'recoveryCatalog'
}
$script:ExactAssetOrder = @(
    'NG-VM-018','NG-VM-010','NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012',
    'NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015'
)

function Throw-NgcaError {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Format-NgcaUtc {
    param([Parameter(Mandatory)][DateTimeOffset]$Value)
    $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-NgcaUtc {
    param([Parameter(Mandatory)][string]$Value, [string]$Code = 'NGCA-TIME-INVALID')
    try {
        [DateTimeOffset]::ParseExact(
            $Value,"yyyy-MM-dd'T'HH:mm:ss'Z'",[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal
        ).ToUniversalTime()
    }
    catch { Throw-NgcaError $Code }
}

function Get-NgcaSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgcaRandomHex {
    param([ValidateRange(16,64)][int]$ByteCount = 32)
    $bytes = New-Object byte[] $ByteCount
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgcaCanonicalBytes {
    param([Parameter(Mandatory)][object]$Value)
    [Text.Encoding]::UTF8.GetBytes((ConvertTo-NorthGateCreateOnlyCanonicalJson $Value))
}

function Assert-NgcaExactProperties {
    param([object]$Object,[string[]]$Expected,[string]$Code)
    if ($null -eq $Object) { Throw-NgcaError $Code }
    $actual = @($Object.PSObject.Properties.Name)
    $expectedCopy = @($Expected)
    [array]::Sort($actual,[StringComparer]::Ordinal)
    [array]::Sort($expectedCopy,[StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expectedCopy -join '|')) { Throw-NgcaError $Code }
}

function Assert-NgcaPattern {
    param([object]$Value,[string]$Pattern,[string]$Code)
    if ($Value -isnot [string] -or [string]$Value -cnotmatch $Pattern) { Throw-NgcaError $Code }
}

function Test-NgcaEqualList {
    param([object[]]$Actual,[object[]]$Expected)
    if ($Actual.Count -ne $Expected.Count) { return $false }
    for ($index = 0; $index -lt $Actual.Count; $index++) {
        if ([string]$Actual[$index] -cne [string]$Expected[$index]) { return $false }
    }
    return $true
}

function Assert-NgcaNoReparseAncestor {
    param([Parameter(Mandatory)][string]$Path,[string]$Code='NGCA-REPARSE-FORBIDDEN')
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Throw-NgcaError $Code }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor -or [string]::IsNullOrEmpty($parent)) { break }
        $cursor = $parent
    }
    $full
}

function Read-NgcaCanonicalFile {
    param([Parameter(Mandatory)][string]$Path,[int]$MaximumBytes=$script:MaximumArtifactBytes,[string]$Code='NGCA-ARTIFACT-INVALID')
    try {
        $full = Assert-NgcaNoReparseAncestor $Path $Code
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -lt 2 -or $item.Length -gt $MaximumBytes) { Throw-NgcaError $Code }
        $bytes = [IO.File]::ReadAllBytes($item.FullName)
        $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bytes -MaximumBytes $MaximumBytes
        [pscustomobject][ordered]@{
            path=$item.FullName;bytes=$bytes;sha256=(Get-NgcaSha256Hex $bytes)
            canonicalJson=$parsed.CanonicalJson;value=$parsed.Value
        }
    }
    catch {
        if ($_.Exception.Message -ceq $Code) { throw }
        Throw-NgcaError $Code
    }
}

function Write-NgcaCreateNewBytes {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][byte[]]$Bytes,[string]$Code='NGCA-OUTPUT-EXISTS')
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null = [IO.Directory]::CreateDirectory($parent) }
    Assert-NgcaNoReparseAncestor $parent | Out-Null
    try {
        $stream = [IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    catch {
        if (Test-Path -LiteralPath $Path) { Throw-NgcaError $Code }
        throw
    }
}

function Write-NgcaAtomicBytes {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][byte[]]$Bytes)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null = [IO.Directory]::CreateDirectory($parent) }
    Assert-NgcaNoReparseAncestor $parent | Out-Null
    $temporary = Join-Path $parent ('.ngca-' + [guid]::NewGuid().ToString('N') + '.tmp')
    Write-NgcaCreateNewBytes $temporary $Bytes 'NGCA-TEMPORARY-COLLISION'
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary,$Path,($Path + '.previous'),$true)
        }
        else { [IO.File]::Move($temporary,$Path) }
    }
    finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

function ConvertTo-NgcaProcessArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    $null = $builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            $null = $builder.Append(('\' * (($backslashes * 2) + 1)))
            $null = $builder.Append('"'); $backslashes = 0; continue
        }
        if ($backslashes -gt 0) { $null = $builder.Append(('\' * $backslashes)); $backslashes = 0 }
        $null = $builder.Append($character)
    }
    if ($backslashes -gt 0) { $null = $builder.Append(('\' * ($backslashes * 2))) }
    $null = $builder.Append('"')
    $builder.ToString()
}

function Invoke-NgcaGitBytes {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int[]]$AllowedExitCodes=@(0)
    )
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = 'git.exe'
    $psi.WorkingDirectory = $RepositoryRoot
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $quotedArguments = @($Arguments | ForEach-Object { ConvertTo-NgcaProcessArgument ([string]$_) })
    $psi.Arguments = [string]::Join(' ',$quotedArguments)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    try {
        if (-not $process.Start()) { Throw-NgcaError 'NGCA-GIT-START-FAILED' }
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $memory = New-Object IO.MemoryStream
        try { $process.StandardOutput.BaseStream.CopyTo($memory); $process.WaitForExit(); $bytes = $memory.ToArray() }
        finally { $memory.Dispose() }
        $stderr = $stderrTask.Result
        if ($process.ExitCode -notin $AllowedExitCodes) { Throw-NgcaError ('NGCA-GIT-FAILED-' + $process.ExitCode) }
        [pscustomobject][ordered]@{bytes=$bytes;exitCode=$process.ExitCode;stderr=$stderr}
    }
    finally { $process.Dispose() }
}

function Invoke-NgcaGitText {
    param([string]$RepositoryRoot,[string[]]$Arguments,[int[]]$AllowedExitCodes=@(0))
    $result = Invoke-NgcaGitBytes $RepositoryRoot $Arguments $AllowedExitCodes
    try { $utf8 = New-Object Text.UTF8Encoding($false,$true); $text = $utf8.GetString($result.bytes) }
    catch { Throw-NgcaError 'NGCA-GIT-OUTPUT-INVALID' }
    [pscustomobject][ordered]@{text=$text;exitCode=$result.exitCode;stderr=$result.stderr}
}

function Get-NgcaGitTreeIndex {
    param([string]$RepositoryRoot,[string]$Commit)
    $result = Invoke-NgcaGitText $RepositoryRoot @('ls-tree','-r','-z','--full-tree',$Commit)
    $index = @{}
    foreach ($record in @($result.text -split "`0" | Where-Object { $_ -ne '' })) {
        if ($record -cnotmatch '^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[a-f0-9]{40})\t(?<path>.+)$') {
            Throw-NgcaError 'NGCA-GIT-TREE-INVALID'
        }
        $path = [string]$Matches.path
        if ($path -match '\\|(?:^|/)\.\.(?:/|$)' -or $index.ContainsKey($path.ToUpperInvariant())) {
            Throw-NgcaError 'NGCA-GIT-TREE-PATH-INVALID'
        }
        $index[$path.ToUpperInvariant()] = [pscustomobject][ordered]@{
            mode=[string]$Matches.mode;type=[string]$Matches.type;oid=[string]$Matches.oid;path=$path
        }
    }
    $index
}

function Get-NgcaGitBlob {
    param([string]$RepositoryRoot,[string]$Oid)
    Assert-NgcaPattern $Oid '^[a-f0-9]{40}$' 'NGCA-GIT-BLOB-OID-INVALID'
    (Invoke-NgcaGitBytes $RepositoryRoot @('cat-file','blob',$Oid)).bytes
}

function Assert-NgcaGitSourceBoundary {
    param([string]$RepositoryRoot,[string]$Commit,[string]$Tree)
    $root = Assert-NgcaNoReparseAncestor $RepositoryRoot 'NGCA-REPOSITORY-REPARSE-FORBIDDEN'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { Throw-NgcaError 'NGCA-REPOSITORY-NOT-FOUND' }
    Assert-NgcaPattern $Commit '^[a-f0-9]{40}$' 'NGCA-COMMIT-INVALID'
    Assert-NgcaPattern $Tree '^[a-f0-9]{40}$' 'NGCA-TREE-INVALID'
    $head = (Invoke-NgcaGitText $root @('rev-parse','--verify','HEAD^{commit}')).text.Trim()
    $observedTree = (Invoke-NgcaGitText $root @('rev-parse','--verify',($Commit + '^{tree}'))).text.Trim()
    if ($head -cne $Commit -or $observedTree -cne $Tree) { Throw-NgcaError 'NGCA-REPOSITORY-PIN-MISMATCH' }
    $treeIndex = Get-NgcaGitTreeIndex $root $Commit
    foreach ($entry in @($treeIndex.Values)) {
        if ($entry.mode -ceq '160000' -or $entry.type -ceq 'commit' -or $entry.path -ceq '.gitmodules') {
            Throw-NgcaError 'NGCA-GIT-SUBMODULE-FORBIDDEN'
        }
        if ($entry.path -cmatch '^(?:schemas|catalog|policy|manifests)/') {
            if ($entry.mode -cne '100644' -or $entry.type -cne 'blob') { Throw-NgcaError 'NGCA-DATA-EXECUTABLE-FORBIDDEN' }
        }
        if ($entry.path -cmatch '(?:^|/)\.gitattributes$') {
            $attributes = [Text.Encoding]::UTF8.GetString((Get-NgcaGitBlob $root $entry.oid))
            if ($attributes -match '(?im)(?:^|\s)filter(?:=|!|-|\s|$)') { Throw-NgcaError 'NGCA-GIT-FILTER-FORBIDDEN' }
        }
    }
    if ((Invoke-NgcaGitBytes $root @('status','--porcelain=v1','-z','--untracked-files=all')).bytes.Length -ne 0) {
        Throw-NgcaError 'NGCA-REPOSITORY-DIRTY'
    }
    if ((Invoke-NgcaGitText $root @('replace','-l')).text.Trim() -ne '') { Throw-NgcaError 'NGCA-GIT-REPLACE-REF-FORBIDDEN' }
    $filterConfig = Invoke-NgcaGitText $root @('config','--local','--get-regexp','^filter\.') @(0,1)
    if ($filterConfig.exitCode -eq 0 -and $filterConfig.text.Trim() -ne '') { Throw-NgcaError 'NGCA-GIT-FILTER-FORBIDDEN' }
    $attributesConfig = Invoke-NgcaGitText $root @('config','--path','--get','core.attributesFile') @(0,1)
    if ($attributesConfig.exitCode -eq 0 -and $attributesConfig.text.Trim() -ne '') { Throw-NgcaError 'NGCA-GIT-ATTRIBUTE-OVERRIDE-FORBIDDEN' }
    $infoAttributes = Join-Path $root '.git\info\attributes'
    if (Test-Path -LiteralPath $infoAttributes -PathType Leaf) {
        if ([IO.File]::ReadAllText($infoAttributes) -match '(?im)(?:^|\s)filter(?:=|!|-|\s|$)') {
            Throw-NgcaError 'NGCA-GIT-FILTER-FORBIDDEN'
        }
    }
    [pscustomobject][ordered]@{root=$root;commit=$Commit;tree=$Tree;treeIndex=$treeIndex}
}

function Assert-NgcaNoSecrets {
    param([object]$Value,[string]$Path='$')
    if ($Value -is [string]) {
        if ($Value -match '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]+=*|\bgh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}\b|(?:password|passwd|pwd|client_secret)\s*[=:]\s*[^\s,;]{4,}') {
            Throw-NgcaError 'NGCA-SECRET-MATERIAL-FORBIDDEN'
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary] -and
        $Value -isnot [Management.Automation.PSCustomObject]) {
        $index = 0; foreach ($item in $Value) { Assert-NgcaNoSecrets $item ($Path + '[' + $index + ']'); $index++ }
        return
    }
    if ($Value -is [Management.Automation.PSCustomObject] -or $Value -is [Collections.IDictionary]) {
        $names = if ($Value -is [Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) }
        foreach ($nameObject in $names) {
            $name = [string]$nameObject
            $child = if ($Value -is [Collections.IDictionary]) { $Value[$nameObject] } else { $Value.PSObject.Properties[$name].Value }
            if ($name -match '(?i)^(?:password|passwd|passphrase|secret|token|api[-_]?key|private[-_]?key|credential)$' -and
                $null -ne $child -and $child -isnot [Management.Automation.PSCustomObject] -and
                $child -isnot [Collections.IDictionary] -and [string]$child -ne '') {
                Throw-NgcaError 'NGCA-SECRET-MATERIAL-FORBIDDEN'
            }
            Assert-NgcaNoSecrets $child ($Path + '.' + $name)
        }
    }
}

function Get-NgcaCertificateSha256 {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    Get-NgcaSha256Hex $Certificate.RawData
}

function Set-NgcaInertTestCertificateResolver {
    param([AllowNull()][scriptblock]$Resolver)
    if ($env:NGCA_INERT_TEST_PROCESS -cne '1') { Throw-NgcaError 'NGCA-INERT-TEST-SEAM-DISABLED' }
    $script:InertTestCertificateResolver = $Resolver
}

function Get-NgcaSigningCertificate {
    param(
        [Parameter(Mandatory)][string]$CertificateSha256,
        [ValidateSet('LocalMachine','CurrentUser')][string]$StoreLocation='LocalMachine'
    )
    Assert-NgcaPattern $CertificateSha256 '^[a-f0-9]{64}$' 'NGCA-SIGNER-PIN-INVALID'
    if ($null -ne $script:InertTestCertificateResolver) {
        if ($env:NGCA_INERT_TEST_PROCESS -cne '1') { Throw-NgcaError 'NGCA-INERT-TEST-SEAM-DISABLED' }
        $certificate = & $script:InertTestCertificateResolver $CertificateSha256
        if ($null -eq $certificate -or -not $certificate.HasPrivateKey -or
            (Get-NgcaCertificateSha256 $certificate) -cne $CertificateSha256) {
            if ($certificate) { $certificate.Dispose() }
            Throw-NgcaError 'NGCA-INERT-TEST-SIGNER-INVALID'
        }
        try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate) }
        catch { $certificate.Dispose(); Throw-NgcaError 'NGCA-INERT-TEST-SIGNER-INVALID' }
        if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
            if ($rsa) { $rsa.Dispose() };$certificate.Dispose();Throw-NgcaError 'NGCA-INERT-TEST-SIGNER-INVALID'
        }
        $rsa.Dispose()
        return $certificate
    }
    if ($env:OS -cne 'Windows_NT') { Throw-NgcaError 'NGCA-WINDOWS-CERTIFICATE-STORE-REQUIRED' }
    $location = [Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('My',$location)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
            [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        $matches = @($store.Certificates | Where-Object {
            $_.HasPrivateKey -and (Get-NgcaCertificateSha256 $_) -ceq $CertificateSha256
        })
        if ($matches.Count -ne 1) { Throw-NgcaError 'NGCA-SIGNER-NOT-UNIQUE-OR-MISSING' }
        $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $matches[0]
    }
    finally { $store.Close(); $store.Dispose() }
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt [DateTimeOffset]$certificate.NotBefore.ToUniversalTime() -or
        $now -ge [DateTimeOffset]$certificate.NotAfter.ToUniversalTime()) {
        $certificate.Dispose(); Throw-NgcaError 'NGCA-SIGNER-NOT-CURRENT'
    }
    $keyUsage = @($certificate.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.15' })
    if ($keyUsage.Count -ne 1 -or
        (([Security.Cryptography.X509Certificates.X509KeyUsageExtension]$keyUsage[0]).KeyUsages -band
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
        $certificate.Dispose(); Throw-NgcaError 'NGCA-SIGNER-USAGE-INVALID'
    }
    try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate) }
    catch { $certificate.Dispose(); Throw-NgcaError 'NGCA-SIGNER-RSA-REQUIRED' }
    if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
        if ($rsa) { $rsa.Dispose() }; $certificate.Dispose(); Throw-NgcaError 'NGCA-SIGNER-RSA-REQUIRED'
    }
    try {
        $exportable = $false
        if ($rsa -is [Security.Cryptography.RSACng]) {
            $policy = $rsa.Key.ExportPolicy
            $exportable = (($policy -band [Security.Cryptography.CngExportPolicies]::AllowExport) -ne 0 -or
                ($policy -band [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport) -ne 0)
        }
        elseif ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            $exportable = $rsa.CspKeyContainerInfo.Exportable
        }
        else {
            try { $null = $rsa.ExportParameters($true); $exportable = $true } catch { $exportable = $false }
        }
        if ($exportable) { Throw-NgcaError 'NGCA-SIGNER-KEY-EXPORTABLE' }
    }
    catch {
        if ($_.Exception.Message -ceq 'NGCA-SIGNER-KEY-EXPORTABLE') { throw }
        Throw-NgcaError 'NGCA-SIGNER-KEY-STATE-UNKNOWN'
    }
    finally { $rsa.Dispose() }
    $certificate
}

function New-NgcaDetachedCmsSignature {
    param([byte[]]$ContentBytes,[Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    try {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
        $content = New-Object Security.Cryptography.Pkcs.ContentInfo (,$ContentBytes)
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms -ArgumentList $content,$true
        $signer = New-Object Security.Cryptography.Pkcs.CmsSigner $Certificate
        $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
        $cms.ComputeSignature($signer,$true)
        $cms.Encode()
    }
    catch { Throw-NgcaError 'NGCA-CMS-SIGNING-FAILED' }
}

function Assert-NgcaDetachedCmsSignature {
    param([byte[]]$ContentBytes,[byte[]]$SignatureBytes,[string]$ExpectedCertificateSha256,[string]$Code='NGCA-CMS-SIGNATURE-INVALID')
    Assert-NgcaPattern $ExpectedCertificateSha256 '^[a-f0-9]{64}$' $Code
    try {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
        $content = New-Object Security.Cryptography.Pkcs.ContentInfo (,$ContentBytes)
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms -ArgumentList $content,$true
        $cms.Decode($SignatureBytes)
        if ($cms.SignerInfos.Count -ne 1) { Throw-NgcaError $Code }
        $cms.CheckSignature($true)
        $certificate = $cms.SignerInfos[0].Certificate
        if ($null -eq $certificate -or (Get-NgcaCertificateSha256 $certificate) -cne $ExpectedCertificateSha256) {
            Throw-NgcaError $Code
        }
        [pscustomobject][ordered]@{
            signerCertificateSha256=$ExpectedCertificateSha256
            signatureSha256=(Get-NgcaSha256Hex $SignatureBytes)
        }
    }
    catch {
        if ($_.Exception.Message -ceq $Code) { throw }
        Throw-NgcaError $Code
    }
}

function Read-NgcaSignedAuthorization {
    param(
        [string]$AuthorizationPath,[string]$AuthorizationSignaturePath,
        [string]$ExpectedAuthorizationSha256,[string]$ExpectedAuthorizationSignerCertificateSha256
    )
    $artifact = Read-NgcaCanonicalFile $AuthorizationPath $script:MaximumArtifactBytes 'NGCA-AUTHORIZATION-INVALID'
    if ($artifact.sha256 -cne $ExpectedAuthorizationSha256) { Throw-NgcaError 'NGCA-AUTHORIZATION-HASH-MISMATCH' }
    $signatureItem = Get-Item -LiteralPath (Assert-NgcaNoReparseAncestor $AuthorizationSignaturePath) -Force -ErrorAction Stop
    if ($signatureItem.PSIsContainer -or $signatureItem.Length -lt 1 -or $signatureItem.Length -gt 1048576) {
        Throw-NgcaError 'NGCA-AUTHORIZATION-SIGNATURE-INVALID'
    }
    $null = Assert-NgcaDetachedCmsSignature $artifact.bytes ([IO.File]::ReadAllBytes($signatureItem.FullName)) `
        $ExpectedAuthorizationSignerCertificateSha256 'NGCA-AUTHORIZATION-SIGNATURE-INVALID'
    if ($artifact.value.identity.deploymentAuthorizationSignerCertificateSha256 -cne
        $ExpectedAuthorizationSignerCertificateSha256) { Throw-NgcaError 'NGCA-AUTHORIZATION-SIGNER-PIN-MISMATCH' }
    $release = [pscustomobject][ordered]@{
        releaseId=[string]$artifact.value.repository.releaseId
        repository=[pscustomobject][ordered]@{
            commit=[string]$artifact.value.repository.commit;tree=[string]$artifact.value.repository.tree
            hostAllowlistId=[string]$artifact.value.repository.hostAllowlistId
        }
    }
    & $script:BackendModule { param($a,$r,$h) Assert-NgcbHostAuthorization $a $r $h } `
        $artifact.value $release $artifact.sha256
    [pscustomobject][ordered]@{artifact=$artifact;authorization=$artifact.value}
}

function Get-NgcaDataRole {
    param([string]$SourcePath,[object]$Value)
    if ($script:CoreCatalogRoles.Contains($SourcePath)) { return [string]$script:CoreCatalogRoles[$SourcePath] }
    if ($SourcePath -cmatch '^manifests/vms/[A-Za-z0-9._-]{1,120}\.json$') { return 'manifest' }
    if ($SourcePath -cmatch '^schemas/[A-Za-z0-9._/-]{1,180}\.json$') { return 'schema' }
    if ($SourcePath -cmatch '^policy/[A-Za-z0-9._/-]{1,180}\.json$') { return 'policy' }
    Throw-NgcaError 'NGCA-DATA-SOURCE-NOT-ALLOWLISTED'
}

function Assert-NgcaDebianIdentity {
    param([object]$ImageCatalog)
    $matches = @($ImageCatalog.images | Where-Object { $_.id -ceq 'debian-12.12-amd64-netinst' })
    if ($matches.Count -ne 1 -or
        $matches[0].sourceArtifactId -cne 'debian-12.12.0-amd64-netinst-iso') {
        Throw-NgcaError 'NGCA-DEBIAN-IMAGE-IDENTITY-DRIFT'
    }
    if (@($ImageCatalog.images | Where-Object { $_.id -ceq 'debian-12.12.0-amd64-netinst' }).Count -ne 0) {
        Throw-NgcaError 'NGCA-DEBIAN-IMAGE-IDENTITY-DRIFT'
    }
}

function New-NorthGateCreateOnlyDataBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$SourcePaths,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SignerCertificateSha256,
        [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStoreLocation='LocalMachine',
        [ValidateRange(300,86400)][int]$LifetimeSeconds=3600,
        [Parameter(Mandatory)][switch]$ConfirmAuthoring
    )
    if (-not $ConfirmAuthoring) { Throw-NgcaError 'NGCA-AUTHORING-CONFIRMATION-REQUIRED' }
    if ($SourcePaths.Count -lt 7) { Throw-NgcaError 'NGCA-DATA-SOURCE-COUNT-INVALID' }
    $normalized = @()
    $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($sourcePathValue in $SourcePaths) {
        $sourcePath = ([string]$sourcePathValue).Replace('\','/')
        if ($sourcePath -cnotmatch '^(?:schemas|catalog|policy|manifests)/[A-Za-z0-9._/-]{1,180}\.json$' -or
            $sourcePath -match '(?:^|/)\.\.(?:/|$)' -or -not $seen.Add($sourcePath)) {
            Throw-NgcaError 'NGCA-DATA-SOURCE-PATH-INVALID'
        }
        $normalized += $sourcePath
    }
    [array]::Sort($normalized,[StringComparer]::Ordinal)
    $boundary = Assert-NgcaGitSourceBoundary $RepositoryRoot $Commit $Tree
    $records = @()
    $filePayloads = [ordered]@{}
    $roles = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($sourcePath in $normalized) {
        $key = $sourcePath.ToUpperInvariant()
        if (-not $boundary.treeIndex.ContainsKey($key)) { Throw-NgcaError 'NGCA-DATA-SOURCE-MISSING' }
        $treeEntry = $boundary.treeIndex[$key]
        if ($treeEntry.path -cne $sourcePath -or $treeEntry.mode -cne '100644' -or $treeEntry.type -cne 'blob') {
            Throw-NgcaError 'NGCA-DATA-SOURCE-MODE-INVALID'
        }
        $bytes = Get-NgcaGitBlob $boundary.root $treeEntry.oid
        if ($bytes.Length -lt 2 -or $bytes.Length -gt $script:MaximumArtifactBytes) { Throw-NgcaError 'NGCA-DATA-SOURCE-SIZE-INVALID' }
        try { $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bytes -MaximumBytes $script:MaximumArtifactBytes }
        catch { Throw-NgcaError 'NGCA-DATA-SOURCE-NONCANONICAL' }
        Assert-NgcaNoSecrets $parsed.Value
        $role = Get-NgcaDataRole $sourcePath $parsed.Value
        if ($role -in @($script:CoreCatalogRoles.Values) -and -not $roles.Add($role)) {
            Throw-NgcaError 'NGCA-DATA-ROLE-DUPLICATE'
        }
        if ($role -ceq 'imageCatalog') { Assert-NgcaDebianIdentity $parsed.Value }
        $sourceSha = Get-NgcaSha256Hex $bytes
        $relativePath = 'files/' + $sourcePath
        $record = [ordered]@{role=$role}
        if ($role -ceq 'manifest') {
            if ($parsed.Value.kind -cne 'VirtualMachine' -or $parsed.Value.metadata.assetId -cnotmatch '^NG-VM-[0-9]{3,}$') {
                Throw-NgcaError 'NGCA-MANIFEST-IDENTITY-INVALID'
            }
            $record.assetId = [string]$parsed.Value.metadata.assetId
        }
        $record.sourcePath = $sourcePath
        $record.gitBlobOid = [string]$treeEntry.oid
        $record.gitMode = '100644'
        $record.sourceSha256 = $sourceSha
        $record.canonicalRelativePath = $relativePath
        $record.canonicalSha256 = $sourceSha
        $record.sizeBytes = [int64]$bytes.Length
        $records += [pscustomobject]$record
        $filePayloads[$relativePath] = $bytes
    }
    foreach ($role in @($script:CoreCatalogRoles.Values)) {
        if (-not $roles.Contains([string]$role)) { Throw-NgcaError 'NGCA-DATA-CORE-CATALOG-MISSING' }
    }
    if (@($records | Where-Object { $_.role -ceq 'manifest' }).Count -lt 1) { Throw-NgcaError 'NGCA-DATA-MANIFEST-MISSING' }
    $created = [DateTimeOffset]::UtcNow
    $expires = $created.AddSeconds($LifetimeSeconds)
    $seed = [pscustomobject][ordered]@{
        repository=[pscustomobject][ordered]@{identity=$script:RepositoryIdentity;commit=$Commit;tree=$Tree}
        createdAtUtc=Format-NgcaUtc $created;expiresAtUtc=Format-NgcaUtc $expires;files=[object[]]$records
    }
    $bundleId = 'ngdata-' + (Get-NgcaSha256Hex (Get-NgcaCanonicalBytes $seed))
    $bundle = [pscustomobject][ordered]@{
        schema='northgate/create-only-data-bundle/v1';bundleId=$bundleId
        repository=$seed.repository;createdAtUtc=$seed.createdAtUtc;expiresAtUtc=$seed.expiresAtUtc
        files=[object[]]$records
    }
    $bundleBytes = Get-NgcaCanonicalBytes $bundle
    $certificate = Get-NgcaSigningCertificate $SignerCertificateSha256 $CertificateStoreLocation
    try { $signatureBytes = New-NgcaDetachedCmsSignature $bundleBytes $certificate }
    finally { $certificate.Dispose() }
    $null = Assert-NgcaDetachedCmsSignature $bundleBytes $signatureBytes $SignerCertificateSha256
    $fullOutput = [IO.Path]::GetFullPath($OutputRoot)
    if (Test-Path -LiteralPath $fullOutput) { Throw-NgcaError 'NGCA-OUTPUT-EXISTS' }
    $parent = Split-Path -Parent $fullOutput
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null=[IO.Directory]::CreateDirectory($parent) }
    Assert-NgcaNoReparseAncestor $parent | Out-Null
    $staging = Join-Path $parent ('.ngca-data-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($staging)
    try {
        foreach ($relative in $filePayloads.Keys) {
            Write-NgcaCreateNewBytes (Join-Path $staging ($relative.Replace('/','\'))) $filePayloads[$relative]
        }
        Write-NgcaCreateNewBytes (Join-Path $staging 'bundle.json') $bundleBytes
        Write-NgcaCreateNewBytes (Join-Path $staging 'bundle.p7s') $signatureBytes
        [IO.Directory]::Move($staging,$fullOutput)
    }
    catch {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
        throw
    }
    [pscustomobject][ordered]@{
        status='signed-data-bundle-authored';bundleId=$bundleId;repositoryCommit=$Commit;repositoryTree=$Tree
        bundlePath=(Join-Path $fullOutput 'bundle.json');bundleSha256=(Get-NgcaSha256Hex $bundleBytes)
        signaturePath=(Join-Path $fullOutput 'bundle.p7s');signatureSha256=(Get-NgcaSha256Hex $signatureBytes)
        signerCertificateSha256=$SignerCertificateSha256;fileCount=$records.Count;outputRoot=$fullOutput
    }
}

function Read-NgcaRawGitCanonicalDocument {
    param([object]$Boundary,[string]$SourcePath,[string]$Code='NGCA-GIT-DOCUMENT-INVALID')
    $path = $SourcePath.Replace('\','/')
    if ($path -cnotmatch '^(?:schemas|catalog|policy|manifests)/[A-Za-z0-9._/-]{1,180}\.json$' -or
        $path -match '(?:^|/)\.\.(?:/|$)') { Throw-NgcaError $Code }
    $key = $path.ToUpperInvariant()
    if (-not $Boundary.treeIndex.ContainsKey($key)) { Throw-NgcaError $Code }
    $entry = $Boundary.treeIndex[$key]
    if ($entry.path -cne $path -or $entry.mode -cne '100644' -or $entry.type -cne 'blob') { Throw-NgcaError $Code }
    $bytes = Get-NgcaGitBlob $Boundary.root $entry.oid
    try { $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes $bytes $script:MaximumArtifactBytes }
    catch { Throw-NgcaError $Code }
    Assert-NgcaNoSecrets $parsed.Value
    [pscustomobject][ordered]@{path=$path;oid=$entry.oid;bytes=$bytes;sha256=(Get-NgcaSha256Hex $bytes);value=$parsed.Value}
}

function Assert-NgcaExactPromotion {
    param([object]$Promotion)
    Assert-NgcaExactProperties $Promotion @(
        '$schema','apiVersion','kind','promotionVersion','status','changeRef','approvalReference','scope',
        'controls','retainedAssetNames','canaryAssetIds','persistentAssetIds','orderedAssetIds',
        'firmwareExceptions','requiredGates'
    ) 'NGCA-PROMOTION-CONTRACT-INVALID'
    Assert-NgcaExactProperties $Promotion.controls @(
        'rawGitDataOnly','installedSignedReleaseRequired','signedHostAuthorizationRequired','freshHostPlanRequired',
        'exactOneTimePlanApprovalRequired','oneAssetPerPlan','retainedAssetMutationAllowed','deletePathAllowed',
        'replacePathAllowed','adoptPathAllowed','quarantineOnUncertainty','signedReceiptRequired'
    ) 'NGCA-PROMOTION-CONTRACT-INVALID'
    if ($Promotion.'$schema' -cne '../schemas/deployment-promotion.schema.json' -or
        $Promotion.apiVersion -cne 'northgate/v1alpha1' -or
        $Promotion.kind -cne 'CreateOnlyDeploymentPromotion' -or $Promotion.status -cne 'approved' -or
        $Promotion.changeRef -cnotmatch '^NG-CHG-[0-9]{8}-[0-9]{3,}$' -or
        $Promotion.approvalReference -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' -or
        $Promotion.scope -cne 'exact-new-fleet-create-only') { Throw-NgcaError 'NGCA-PROMOTION-CONTRACT-INVALID' }
    $requiredTrue = @('rawGitDataOnly','installedSignedReleaseRequired','signedHostAuthorizationRequired',
        'freshHostPlanRequired','exactOneTimePlanApprovalRequired','oneAssetPerPlan','quarantineOnUncertainty','signedReceiptRequired')
    $requiredFalse = @('retainedAssetMutationAllowed','deletePathAllowed','replacePathAllowed','adoptPathAllowed')
    foreach ($name in $requiredTrue) { if ($Promotion.controls.$name -ne $true) { Throw-NgcaError 'NGCA-PROMOTION-CONTROL-WIDENED' } }
    foreach ($name in $requiredFalse) { if ($Promotion.controls.$name -ne $false) { Throw-NgcaError 'NGCA-PROMOTION-CONTROL-WIDENED' } }
    if (-not (Test-NgcaEqualList @($Promotion.retainedAssetNames) @('JS-BlueBench','JS-Server-01','OPNsense-Tooling','TRMM-Tooling','Wazuh-Machine')) -or
        -not (Test-NgcaEqualList @($Promotion.canaryAssetIds) @('NG-VM-018','NG-VM-010')) -or
        -not (Test-NgcaEqualList @($Promotion.persistentAssetIds) @('NG-VM-014','NG-VM-013','NG-VM-011','NG-VM-012','NG-VM-019','NG-VM-020','NG-VM-021','NG-VM-016','NG-VM-017','NG-VM-015')) -or
        -not (Test-NgcaEqualList @($Promotion.orderedAssetIds) $script:ExactAssetOrder)) {
        Throw-NgcaError 'NGCA-PROMOTION-ASSET-SCOPE-INVALID'
    }
    if (@($Promotion.firmwareExceptions).Count -ne 1) { Throw-NgcaError 'NGCA-PROMOTION-FIRMWARE-EXCEPTION-INVALID' }
    $exception = @($Promotion.firmwareExceptions)[0]
    Assert-NgcaExactProperties $exception @('exceptionId','assetId','profileRef','secureBootEnabled','reason') `
        'NGCA-PROMOTION-FIRMWARE-EXCEPTION-INVALID'
    if ($exception.exceptionId -cne 'NG-FW-20260802-KALI-UNSIGNED' -or $exception.assetId -cne 'NG-VM-015' -or
        $exception.profileRef -cne 'kali-gen2-unsigned' -or $exception.secureBootEnabled -ne $false -or
        $exception.reason -cne 'official-kali-installer-kernel-is-not-secure-boot-signed') {
        Throw-NgcaError 'NGCA-PROMOTION-FIRMWARE-EXCEPTION-INVALID'
    }
    $gates = @(
        'control-plane-negative-tests-passed','immutable-signed-release-installed','signed-host-authorization-verified',
        'immutable-images-promoted','opaque-profiles-approved','retained-system-backups-verified',
        'debian-canary-before-windows-canary','canaries-accepted-before-persistent-fleet','one-asset-per-fresh-plan',
        'exact-plan-human-approval','quarantine-route-proven','signed-receipt-ready'
    )
    if (-not (Test-NgcaEqualList @($Promotion.requiredGates) $gates)) { Throw-NgcaError 'NGCA-PROMOTION-GATES-INVALID' }
}

function Assert-NgcaResourcePolicyPromotion {
    param([object]$ResourcePolicy,[object]$Mapping)
    Assert-NgcaExactProperties $ResourcePolicy @(
        '$schema','apiVersion','kind','policyVersion','status','applyEnabled','hostReserveMemoryMiB',
        'minimumVolumeFreeGiB','minimumVolumeFreePercent','perVm','plannerActions','executableActions','deniedOperations'
    ) 'NGCA-RESOURCE-POLICY-INVALID'
    if ($ResourcePolicy.'$schema' -cne '../schemas/resource-policy.schema.json' -or
        $ResourcePolicy.apiVersion -cne 'northgate/v1alpha1' -or $ResourcePolicy.kind -cne 'ResourcePolicy' -or
        $ResourcePolicy.status -cne 'approved' -or $ResourcePolicy.applyEnabled -ne $true -or
        -not (Test-NgcaEqualList @($ResourcePolicy.executableActions) @('Create')) -or
        $ResourcePolicy.policyVersion -cne $Mapping.policyVersion -or
        [int]$ResourcePolicy.hostReserveMemoryMiB -ne [int]$Mapping.limits.hostReserveMemoryMiB -or
        [int64]$ResourcePolicy.minimumVolumeFreeGiB * 1GB -ne [int64]$Mapping.limits.minimumVolumeFreeBytes -or
        [int]$ResourcePolicy.minimumVolumeFreePercent -ne [int]$Mapping.limits.minimumVolumeFreePercent -or
        [int]$ResourcePolicy.perVm.maximumProcessors -ne [int]$Mapping.limits.maximumProcessorCount -or
        [int]$ResourcePolicy.perVm.maximumStartupMemoryMiB -ne [int]$Mapping.limits.maximumStartupMemoryMiB -or
        [int]$ResourcePolicy.perVm.maximumDynamicMemoryMiB -ne [int]$Mapping.limits.maximumDynamicMemoryMiB -or
        [int]$ResourcePolicy.perVm.maximumOsDiskGiB -ne [int]$Mapping.limits.maximumOsDiskGiB) {
        Throw-NgcaError 'NGCA-RESOURCE-POLICY-NOT-PROMOTED'
    }
}

function Assert-NgcaBackendPolicyMapping {
    param([object]$Mapping,[object]$Authorization)
    Assert-NgcaExactProperties $Mapping @(
        'schema','policyId','policyVersion','stateKeyId','planTtlSeconds','approvalTtlSeconds','limits','rollout',
        'storageProfiles','networkProfiles','images','bootstrapMedia','firmwareProfiles','bootstrapProfiles','recoveryProfiles','allowedAssets'
    ) 'NGCA-POLICY-MAPPING-CONTRACT-INVALID'
    if ($Mapping.schema -cne 'northgate/create-only-backend-policy-mapping/v1' -or
        $Mapping.policyId -cnotmatch '^[a-z0-9][a-z0-9.-]{1,63}$' -or
        $Mapping.policyVersion -cnotmatch '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$' -or
        $Mapping.stateKeyId -cnotmatch '^ngkey-[a-z0-9-]{8,64}$' -or
        [int]$Mapping.planTtlSeconds -lt 30 -or [int]$Mapping.planTtlSeconds -gt 900 -or
        [int]$Mapping.approvalTtlSeconds -lt 30 -or [int]$Mapping.approvalTtlSeconds -gt 600) {
        Throw-NgcaError 'NGCA-POLICY-MAPPING-CONTRACT-INVALID'
    }
    if ($Mapping.limits.maximumVcpuToLogicalRatio -isnot [int] -or
        [int]$Mapping.limits.maximumVcpuToLogicalRatio -lt 1 -or
        [int]$Mapping.limits.maximumVcpuToLogicalRatio -gt 2) {
        Throw-NgcaError 'NGCA-POLICY-MAPPING-CONTRACT-INVALID'
    }
    foreach ($collectionName in @('storageProfiles','networkProfiles','images','bootstrapMedia','firmwareProfiles','bootstrapProfiles','recoveryProfiles','allowedAssets')) {
        if (@($Mapping.$collectionName).Count -lt 1) { Throw-NgcaError 'NGCA-POLICY-MAPPING-CONTRACT-INVALID' }
    }
    foreach ($storage in @($Mapping.storageProfiles)) {
        $volume = @($Authorization.volumes | Where-Object { $_.volumeId -ceq $storage.volumeId })
        if ($volume.Count -ne 1 -or [IO.Path]::GetFullPath([string]$volume[0].root).TrimEnd('\') -ine
            [IO.Path]::GetFullPath([string]$storage.root).TrimEnd('\')) { Throw-NgcaError 'NGCA-POLICY-STORAGE-AUTHORIZATION-MISMATCH' }
    }
    foreach ($network in @($Mapping.networkProfiles)) {
        $property = $Authorization.switch.vlanProfiles.PSObject.Properties[[string]$network.profileRef]
        if ($null -eq $property -or [int]$property.Value -ne [int]$network.vlanId -or
            $network.switchPolicyId -cne $Authorization.switch.switchPolicyId) {
            Throw-NgcaError 'NGCA-POLICY-NETWORK-AUTHORIZATION-MISMATCH'
        }
    }
    foreach ($image in @($Mapping.images)) {
        $authorized = @($Authorization.images | Where-Object { $_.imageId -ceq $image.authorizationImageId })
        if ($authorized.Count -ne 1 -or $image.imageRef -cne $image.authorizationImageId -or
            [IO.Path]::GetFullPath([string]$authorized[0].path) -ine [IO.Path]::GetFullPath([string]$image.path) -or
            $authorized[0].sha256 -cne $image.sha256 -or [int64]$authorized[0].sizeBytes -ne [int64]$image.sizeBytes) {
            Throw-NgcaError 'NGCA-POLICY-IMAGE-AUTHORIZATION-MISMATCH'
        }
    }
    if (@($Mapping.bootstrapMedia).Count -ne 12 -or @($Authorization.bootstrapMedia).Count -ne 12) {
        Throw-NgcaError 'NGCA-POLICY-BOOTSTRAP-MEDIA-SCOPE-INVALID'
    }
    foreach ($media in @($Mapping.bootstrapMedia)) {
        $authorized = @($Authorization.bootstrapMedia | Where-Object { $_.mediaId -ceq $media.mediaId })
        if ($authorized.Count -ne 1 -or
            (ConvertTo-NorthGateCreateOnlyCanonicalJson $media) -cne
                (ConvertTo-NorthGateCreateOnlyCanonicalJson $authorized[0])) {
            Throw-NgcaError 'NGCA-POLICY-BOOTSTRAP-MEDIA-AUTHORIZATION-MISMATCH'
        }
    }
    if (@($Mapping.images | Where-Object { $_.imageRef -ceq 'debian-12.12.0-amd64-netinst' }).Count -gt 0 -or
        @($Mapping.images | Where-Object { $_.imageRef -ceq 'debian-12.12-amd64-netinst' -and
            $_.authorizationImageId -ceq 'debian-12.12-amd64-netinst' }).Count -ne 1) {
        Throw-NgcaError 'NGCA-DEBIAN-IMAGE-IDENTITY-DRIFT'
    }
    $identities = @($Mapping.allowedAssets | ForEach-Object { [string]$_.assetId })
    $macs = @($Mapping.allowedAssets | ForEach-Object { [string]$_.staticMacAddress })
    if (@($identities | Select-Object -Unique).Count -ne $identities.Count -or
        @($macs | Select-Object -Unique).Count -ne $macs.Count) { Throw-NgcaError 'NGCA-POLICY-ASSET-IDENTITY-DUPLICATE' }
    foreach ($asset in @($Mapping.allowedAssets)) {
        if ($asset.assetId -cnotmatch '^NG-VM-[0-9]{3,}$' -or $asset.staticMacAddress -cnotmatch '^02[0-9A-F]{10}$') {
            Throw-NgcaError 'NGCA-POLICY-ASSET-IDENTITY-INVALID'
        }
        if (@($Mapping.bootstrapMedia | Where-Object {
            $_.assetId -ceq $asset.assetId -and $_.mediaId -ceq $asset.bootstrapMediaId
        }).Count -ne 1) { Throw-NgcaError 'NGCA-POLICY-ASSET-REFERENCE-INVALID' }
        foreach ($reference in @($asset.allowedImageRefs)) {
            if (@($Mapping.images | Where-Object { $_.imageRef -ceq $reference }).Count -ne 1) { Throw-NgcaError 'NGCA-POLICY-ASSET-REFERENCE-INVALID' }
        }
        foreach ($reference in @($asset.allowedStorageProfileRefs)) {
            if (@($Mapping.storageProfiles | Where-Object { $_.profileRef -ceq $reference }).Count -ne 1) { Throw-NgcaError 'NGCA-POLICY-ASSET-REFERENCE-INVALID' }
        }
        foreach ($reference in @($asset.allowedNetworkProfileRefs)) {
            if (@($Mapping.networkProfiles | Where-Object { $_.profileRef -ceq $reference }).Count -ne 1) { Throw-NgcaError 'NGCA-POLICY-ASSET-REFERENCE-INVALID' }
        }
    }
}

function New-NorthGateCreateOnlyBackendPolicyArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$HostAuthorizationPath,
        [Parameter(Mandatory)][string]$HostAuthorizationSignaturePath,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSha256,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSignerCertificateSha256,
        [Parameter(Mandatory)][string]$MappingPath,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SignerCertificateSha256,
        [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStoreLocation='LocalMachine',
        [ValidateRange(300,86400)][int]$LifetimeSeconds=3600,
        [string]$PromotionRecordPath='',
        [string]$ExpectedPromotionRecordSha256='',
        [Parameter(Mandatory)][switch]$ConfirmAuthoring
    )
    if (-not $ConfirmAuthoring) { Throw-NgcaError 'NGCA-AUTHORING-CONFIRMATION-REQUIRED' }
    $authorizationResult = Read-NgcaSignedAuthorization $HostAuthorizationPath $HostAuthorizationSignaturePath `
        $ExpectedHostAuthorizationSha256 $ExpectedHostAuthorizationSignerCertificateSha256
    $authorization = $authorizationResult.authorization
    if ($SignerCertificateSha256 -cne $authorization.identity.releaseSignerCertificateSha256) {
        Throw-NgcaError 'NGCA-POLICY-SIGNER-PIN-MISMATCH'
    }
    $mappingArtifact = Read-NgcaCanonicalFile $MappingPath $script:MaximumArtifactBytes 'NGCA-POLICY-MAPPING-INVALID'
    Assert-NgcaNoSecrets $mappingArtifact.value
    Assert-NgcaBackendPolicyMapping $mappingArtifact.value $authorization
    $boundary = Assert-NgcaGitSourceBoundary $RepositoryRoot `
        ([string]$authorization.repository.commit) ([string]$authorization.repository.tree)
    $promotionEnabled = $false
    $promotionHash = ''
    if (($PromotionRecordPath -eq '') -xor ($ExpectedPromotionRecordSha256 -eq '')) {
        Throw-NgcaError 'NGCA-PROMOTION-PARAMETERS-INCOMPLETE'
    }
    if ($PromotionRecordPath -ne '') {
        if ($PromotionRecordPath -cne 'policy/deployment-promotion.json') { Throw-NgcaError 'NGCA-PROMOTION-PATH-INVALID' }
        Assert-NgcaPattern $ExpectedPromotionRecordSha256 '^[a-f0-9]{64}$' 'NGCA-PROMOTION-HASH-INVALID'
        $promotionArtifact = Read-NgcaRawGitCanonicalDocument $boundary $PromotionRecordPath 'NGCA-PROMOTION-INVALID'
        if ($promotionArtifact.sha256 -cne $ExpectedPromotionRecordSha256) { Throw-NgcaError 'NGCA-PROMOTION-HASH-MISMATCH' }
        Assert-NgcaExactPromotion $promotionArtifact.value
        $resourceArtifact = Read-NgcaRawGitCanonicalDocument $boundary 'policy/resource-limits.json' 'NGCA-RESOURCE-POLICY-INVALID'
        Assert-NgcaResourcePolicyPromotion $resourceArtifact.value $mappingArtifact.value
        if (-not (Test-NgcaEqualList @($mappingArtifact.value.allowedAssets | ForEach-Object { $_.assetId }) $script:ExactAssetOrder)) {
            Throw-NgcaError 'NGCA-PROMOTION-MAPPING-SCOPE-INVALID'
        }
        $promotionEnabled = $true
        $promotionHash = $promotionArtifact.sha256
    }
    $issued = [DateTimeOffset]::UtcNow
    $authorizationExpiry = ConvertTo-NgcaUtc $authorization.expiresAtUtc 'NGCA-AUTHORIZATION-TIME-INVALID'
    $expires = $issued.AddSeconds($LifetimeSeconds)
    if ($authorizationExpiry -lt $expires) { $expires = $authorizationExpiry }
    if ($expires -le $issued.AddSeconds(30)) { Throw-NgcaError 'NGCA-POLICY-LIFETIME-INSUFFICIENT' }
    $mapping = $mappingArtifact.value
    $policy = [pscustomobject][ordered]@{
        schema='northgate/create-only-backend-policy/v1';policyId=[string]$mapping.policyId
        policyVersion=[string]$mapping.policyVersion;authorizationSha256=$authorizationResult.artifact.sha256
        releaseManifestSha256=[string]$authorization.releaseManifestSha256;hostId=[string]$authorization.host.hostId
        issuedAtUtc=(Format-NgcaUtc $issued);expiresAtUtc=(Format-NgcaUtc $expires);applyEnabled=[bool]$promotionEnabled
        executableActions=[object[]]@('Create');planTtlSeconds=[int]$mapping.planTtlSeconds
        approvalTtlSeconds=[int]$mapping.approvalTtlSeconds;stateKeyId=[string]$mapping.stateKeyId
        limits=$mapping.limits;storageProfiles=[object[]]@($mapping.storageProfiles)
        rollout=$mapping.rollout
        networkProfiles=[object[]]@($mapping.networkProfiles);images=[object[]]@($mapping.images)
        bootstrapMedia=[object[]]@($mapping.bootstrapMedia)
        firmwareProfiles=[object[]]@($mapping.firmwareProfiles);bootstrapProfiles=[object[]]@($mapping.bootstrapProfiles)
        recoveryProfiles=[object[]]@($mapping.recoveryProfiles);allowedAssets=[object[]]@($mapping.allowedAssets)
    }
    $policyBytes = Get-NgcaCanonicalBytes $policy
    $policySha = Get-NgcaSha256Hex $policyBytes
    & $script:BackendModule { param($p,$a,$ah,$ph) Assert-NgcbBackendPolicy $p $a $ah $ph } `
        $policy $authorization $authorizationResult.artifact.sha256 $policySha
    $certificate = Get-NgcaSigningCertificate $SignerCertificateSha256 $CertificateStoreLocation
    try { $signatureBytes = New-NgcaDetachedCmsSignature $policyBytes $certificate }
    finally { $certificate.Dispose() }
    $null = Assert-NgcaDetachedCmsSignature $policyBytes $signatureBytes $SignerCertificateSha256
    $fullOutput = [IO.Path]::GetFullPath($OutputRoot)
    if (Test-Path -LiteralPath $fullOutput) { Throw-NgcaError 'NGCA-OUTPUT-EXISTS' }
    $parent = Split-Path -Parent $fullOutput
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null=[IO.Directory]::CreateDirectory($parent) }
    Assert-NgcaNoReparseAncestor $parent | Out-Null
    $staging = Join-Path $parent ('.ngca-policy-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($staging)
    try {
        Write-NgcaCreateNewBytes (Join-Path $staging 'backend-policy.json') $policyBytes
        Write-NgcaCreateNewBytes (Join-Path $staging 'backend-policy.p7s') $signatureBytes
        [IO.Directory]::Move($staging,$fullOutput)
    }
    catch {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
        throw
    }
    [pscustomobject][ordered]@{
        status='signed-backend-policy-authored';applyEnabled=[bool]$promotionEnabled
        promotionRecordSha256=$promotionHash;authorizationSha256=$authorizationResult.artifact.sha256
        repositoryCommit=[string]$authorization.repository.commit;repositoryTree=[string]$authorization.repository.tree
        policyPath=(Join-Path $fullOutput 'backend-policy.json');policySha256=$policySha
        signaturePath=(Join-Path $fullOutput 'backend-policy.p7s');signatureSha256=(Get-NgcaSha256Hex $signatureBytes)
        signerCertificateSha256=$SignerCertificateSha256;expiresAtUtc=$policy.expiresAtUtc;outputRoot=$fullOutput
    }
}

function Read-NgcaPlanEvidence {
    param([string]$Path)
    $artifact = Read-NgcaCanonicalFile $Path $script:MaximumArtifactBytes 'NGCA-PLAN-EVIDENCE-INVALID'
    $evidence = $artifact.value
    Assert-NgcaExactProperties $evidence @(
        'planId','planHash','planAuthenticationHash','state','approvalState','expiresAtUtc',
        'assetId','name','action','canonicalPlan'
    ) 'NGCA-PLAN-EVIDENCE-INVALID'
    if ($evidence.planId -cnotmatch '^ngp-[a-f0-9]{64}$' -or $evidence.planHash -cnotmatch '^[a-f0-9]{64}$' -or
        $evidence.planAuthenticationHash -cnotmatch '^[a-f0-9]{64}$' -or $evidence.state -cne 'Registered' -or
        $evidence.approvalState -cne 'Pending' -or $evidence.action -cne 'Create' -or
        $evidence.assetId -cnotmatch '^NG-VM-[0-9]{3,}$' -or $evidence.canonicalPlan -isnot [string]) {
        Throw-NgcaError 'NGCA-PLAN-EVIDENCE-INVALID'
    }
    $planBytes = [Text.Encoding]::UTF8.GetBytes([string]$evidence.canonicalPlan)
    try { $parsedPlan = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes $planBytes $script:MaximumArtifactBytes }
    catch { Throw-NgcaError 'NGCA-PLAN-EVIDENCE-INVALID' }
    $plan = $parsedPlan.Value
    if ((Get-NgcaSha256Hex $planBytes) -cne $evidence.planHash -or $plan.planId -cne $evidence.planId -or
        $plan.expiresAtUtc -cne $evidence.expiresAtUtc -or $plan.operation.assetId -cne $evidence.assetId -or
        $plan.operation.name -cne $evidence.name -or $plan.operation.action -cne 'Create') {
        Throw-NgcaError 'NGCA-PLAN-EVIDENCE-BINDING-INVALID'
    }
    [pscustomobject][ordered]@{artifact=$artifact;evidence=$evidence;plan=$plan;planBytes=$planBytes}
}

function Assert-NgcaApprovalStateAcl {
    param([string]$StateRoot,[string]$CurrentSid)
    $full = Assert-NgcaNoReparseAncestor $StateRoot 'NGCA-APPROVAL-STATE-REPARSE-FORBIDDEN'
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { Throw-NgcaError 'NGCA-APPROVAL-STATE-ROOT-MISSING' }
    try { $acl = Get-Acl -LiteralPath $full -ErrorAction Stop }
    catch { Throw-NgcaError 'NGCA-APPROVAL-STATE-ACL-INVALID' }
    $allowed = @('S-1-5-18','S-1-5-32-544',$CurrentSid)
    try { $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { try { $ownerSid = ([Security.Principal.SecurityIdentifier]$acl.Owner).Value } catch { Throw-NgcaError 'NGCA-APPROVAL-STATE-ACL-INVALID' } }
    if ($ownerSid -notin $allowed) { Throw-NgcaError 'NGCA-APPROVAL-STATE-ACL-INVALID' }
    foreach ($rule in @($acl.Access)) {
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { Throw-NgcaError 'NGCA-APPROVAL-STATE-ACL-INVALID' }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::ReadData -bor
                [Security.AccessControl.FileSystemRights]::WriteData -bor
                [Security.AccessControl.FileSystemRights]::Modify -bor
                [Security.AccessControl.FileSystemRights]::FullControl)) -ne 0 -and $sid -notin $allowed) {
            Throw-NgcaError 'NGCA-APPROVAL-STATE-ACL-INVALID'
        }
    }
    $full
}

function New-NgcaPlanApprovalArtifactCore {
    param(
        [object]$PlanResult,[object]$AuthorizationArtifact,[object]$PolicyArtifact,[object]$BundleArtifact,
        [string]$ApproverSid,[string]$ApprovalStateRoot,[string]$OutputRoot,
        [string]$SignerCertificateSha256,[string]$CertificateStoreLocation,[int]$LifetimeSeconds,
        [switch]$SkipAclForInertTest
    )
    $authorization = $AuthorizationArtifact.value
    $policy = $PolicyArtifact.value
    $bundle = $BundleArtifact.value
    $plan = $PlanResult.plan
    if ($SignerCertificateSha256 -cne $authorization.identity.approvalSignerCertificateSha256 -or
        $SignerCertificateSha256 -eq $authorization.identity.releaseSignerCertificateSha256 -or
        $SignerCertificateSha256 -eq $authorization.identity.receiptSignerCertificateSha256 -or
        $SignerCertificateSha256 -eq $authorization.identity.deploymentAuthorizationSignerCertificateSha256) {
        Throw-NgcaError 'NGCA-APPROVAL-SIGNER-SEPARATION-INVALID'
    }
    if ($ApproverSid -cnotmatch '^S-1-[0-9-]+$' -or $ApproverSid -in @(
        [string]$authorization.identity.sshIdentitySid,[string]$authorization.identity.serviceIdentitySid
    )) { Throw-NgcaError 'NGCA-APPROVER-IDENTITY-INVALID' }
    if ($plan.repository.identity -cne $script:RepositoryIdentity -or
        $plan.repository.commit -cne $authorization.repository.commit -or
        $plan.repository.tree -cne $authorization.repository.tree -or
        $plan.release.releaseManifestSha256 -cne $authorization.releaseManifestSha256 -or
        $plan.authorization.authorizationSha256 -cne $AuthorizationArtifact.sha256 -or
        $plan.policy.policySha256 -cne $PolicyArtifact.sha256 -or
        $plan.data.dataBundleSha256 -cne $BundleArtifact.sha256 -or
        $policy.authorizationSha256 -cne $AuthorizationArtifact.sha256 -or
        $policy.releaseManifestSha256 -cne $authorization.releaseManifestSha256 -or
        $bundle.repository.commit -cne $authorization.repository.commit -or
        $bundle.repository.tree -cne $authorization.repository.tree) {
        Throw-NgcaError 'NGCA-APPROVAL-ANCHOR-MISMATCH'
    }
    $now = [DateTimeOffset]::UtcNow
    $planIssued = ConvertTo-NgcaUtc $plan.issuedAtUtc 'NGCA-PLAN-TIME-INVALID'
    $planExpires = ConvertTo-NgcaUtc $plan.expiresAtUtc 'NGCA-PLAN-TIME-INVALID'
    if ($planIssued -gt $now.AddSeconds($script:MaximumClockSkewSeconds) -or $planExpires -le $now) {
        Throw-NgcaError 'NGCA-PLAN-NOT-CURRENT'
    }
    $expires = $now.AddSeconds([Math]::Min($LifetimeSeconds,[int]$policy.approvalTtlSeconds))
    foreach ($anchor in @(
        $planExpires,(ConvertTo-NgcaUtc $authorization.expiresAtUtc),(ConvertTo-NgcaUtc $policy.expiresAtUtc),
        (ConvertTo-NgcaUtc $bundle.expiresAtUtc)
    )) { if ($anchor -lt $expires) { $expires=$anchor } }
    if ($expires -le $now.AddSeconds(5)) { Throw-NgcaError 'NGCA-APPROVAL-LIFETIME-INSUFFICIENT' }
    $nonce = Get-NgcaRandomHex 32
    $identitySeed = [pscustomobject][ordered]@{
        planId=[string]$plan.planId;planHash=[string]$PlanResult.evidence.planHash
        planAuthenticationHash=[string]$PlanResult.evidence.planAuthenticationHash
        approverSid=$ApproverSid;nonce=$nonce
    }
    $approvalId = 'nga-' + (Get-NgcaSha256Hex (Get-NgcaCanonicalBytes $identitySeed))
    $approval = [pscustomobject][ordered]@{
        schema='northgate/create-only-plan-approval/v1';approvalId=$approvalId;decision='approve'
        planId=[string]$plan.planId;planHash=[string]$PlanResult.evidence.planHash
        planAuthenticationHash=[string]$PlanResult.evidence.planAuthenticationHash
        changeId=[string]$plan.operation.changeId
        repository=[pscustomobject][ordered]@{identity=$script:RepositoryIdentity;commit=[string]$plan.repository.commit;tree=[string]$plan.repository.tree}
        releaseManifestSha256=[string]$plan.release.releaseManifestSha256
        authorizationSha256=$AuthorizationArtifact.sha256;policySha256=$PolicyArtifact.sha256
        dataBundleSha256=$BundleArtifact.sha256;issuedAtUtc=(Format-NgcaUtc $now);expiresAtUtc=(Format-NgcaUtc $expires)
        approverSid=$ApproverSid;nonce=$nonce;useLimit=1
    }
    $approvalBytes = Get-NgcaCanonicalBytes $approval
    & $script:BackendModule { param($a,$pr,$p,$c) Assert-NgcbApprovalContract $a $pr $p $c } `
        $approval ([pscustomobject]@{planId=$PlanResult.evidence.planId;planHash=$PlanResult.evidence.planHash;planAuthenticationHash=$PlanResult.evidence.planAuthenticationHash}) `
        $plan ([pscustomobject]@{Authorization=$authorization;AuthorizationSha256=$AuthorizationArtifact.sha256;Policy=$policy;PolicySha256=$PolicyArtifact.sha256;DataBundleSha256=$BundleArtifact.sha256;ReleaseManifestSha256=$authorization.releaseManifestSha256})
    $stateRoot = if ($SkipAclForInertTest) { Assert-NgcaNoReparseAncestor $ApprovalStateRoot } else {
        Assert-NgcaApprovalStateAcl $ApprovalStateRoot $ApproverSid
    }
    $claimsRoot = Join-Path $stateRoot 'claims'
    if (-not (Test-Path -LiteralPath $claimsRoot -PathType Container)) { $null=[IO.Directory]::CreateDirectory($claimsRoot) }
    Assert-NgcaNoReparseAncestor $claimsRoot | Out-Null
    $claimPath = Join-Path $claimsRoot ([string]$plan.planId + '.json')
    $mutex = New-Object Threading.Mutex($false,$script:ApprovalMutexName)
    $acquired = $false
    $claim = [pscustomobject][ordered]@{
        schema='northgate/create-only-approval-authoring-claim/v1';planId=[string]$plan.planId
        planHash=[string]$PlanResult.evidence.planHash;approvalId=$approvalId;nonce=$nonce
        approverSid=$ApproverSid;state='Reserved';reservedAtUtc=(Format-NgcaUtc $now)
        approvalSha256='';signatureSha256=''
    }
    try {
        $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(15))
        if (-not $acquired) { Throw-NgcaError 'NGCA-APPROVAL-AUTHORING-LOCK-BUSY' }
        Write-NgcaCreateNewBytes $claimPath (Get-NgcaCanonicalBytes $claim) 'NGCA-APPROVAL-ALREADY-AUTHORED'
        $certificate = Get-NgcaSigningCertificate $SignerCertificateSha256 $CertificateStoreLocation
        try { $signatureBytes = New-NgcaDetachedCmsSignature $approvalBytes $certificate }
        finally { $certificate.Dispose() }
        $null = Assert-NgcaDetachedCmsSignature $approvalBytes $signatureBytes $SignerCertificateSha256
        $fullOutput = [IO.Path]::GetFullPath($OutputRoot)
        if (Test-Path -LiteralPath $fullOutput) { Throw-NgcaError 'NGCA-OUTPUT-EXISTS' }
        $parent = Split-Path -Parent $fullOutput
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $null=[IO.Directory]::CreateDirectory($parent) }
        Assert-NgcaNoReparseAncestor $parent | Out-Null
        $staging = Join-Path $parent ('.ngca-approval-' + [guid]::NewGuid().ToString('N'))
        $null=[IO.Directory]::CreateDirectory($staging)
        try {
            Write-NgcaCreateNewBytes (Join-Path $staging 'approval.json') $approvalBytes
            Write-NgcaCreateNewBytes (Join-Path $staging 'approval.p7s') $signatureBytes
            [IO.Directory]::Move($staging,$fullOutput)
        }
        catch {
            if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
            throw
        }
        $claim.state='Authored';$claim.approvalSha256=Get-NgcaSha256Hex $approvalBytes
        $claim.signatureSha256=Get-NgcaSha256Hex $signatureBytes
        Write-NgcaAtomicBytes $claimPath (Get-NgcaCanonicalBytes $claim)
        [pscustomobject][ordered]@{
            status='one-use-approval-authored';planId=[string]$plan.planId;approvalId=$approvalId
            approvalPath=(Join-Path $fullOutput 'approval.json');approvalSha256=$claim.approvalSha256
            signaturePath=(Join-Path $fullOutput 'approval.p7s');signatureSha256=$claim.signatureSha256
            signerCertificateSha256=$SignerCertificateSha256;approverSid=$ApproverSid
            expiresAtUtc=$approval.expiresAtUtc;claimPath=$claimPath;durableConsumeOwner='production-backend-apply'
        }
    }
    catch {
        if (Test-Path -LiteralPath $claimPath -PathType Leaf) {
            try { $claim.state='OutcomeUnknown'; Write-NgcaAtomicBytes $claimPath (Get-NgcaCanonicalBytes $claim) } catch { }
        }
        throw
    }
    finally { if ($acquired) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}

function New-NorthGateCreateOnlyPlanApprovalArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PlanEvidencePath,
        [Parameter(Mandatory)][string]$HostAuthorizationPath,
        [Parameter(Mandatory)][string]$HostAuthorizationSignaturePath,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSha256,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedHostAuthorizationSignerCertificateSha256,
        [Parameter(Mandatory)][string]$BackendPolicyPath,
        [Parameter(Mandatory)][string]$BackendPolicySignaturePath,
        [Parameter(Mandatory)][string]$DataBundlePath,
        [Parameter(Mandatory)][string]$DataBundleSignaturePath,
        [Parameter(Mandatory)][string]$ApprovalStateRoot,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$SignerCertificateSha256,
        [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStoreLocation='LocalMachine',
        [ValidateRange(30,600)][int]$LifetimeSeconds=300,
        [Parameter(Mandatory)][switch]$ConfirmApproval
    )
    if (-not $ConfirmApproval) { Throw-NgcaError 'NGCA-APPROVAL-CONFIRMATION-REQUIRED' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Throw-NgcaError 'NGCA-APPROVAL-NATIVE-ADMIN-REQUIRED'
    }
    $authorizationResult = Read-NgcaSignedAuthorization $HostAuthorizationPath $HostAuthorizationSignaturePath `
        $ExpectedHostAuthorizationSha256 $ExpectedHostAuthorizationSignerCertificateSha256
    $planResult = Read-NgcaPlanEvidence $PlanEvidencePath
    $policyArtifact = Read-NgcaCanonicalFile $BackendPolicyPath $script:MaximumArtifactBytes 'NGCA-POLICY-INVALID'
    $bundleArtifact = Read-NgcaCanonicalFile $DataBundlePath 10485760 'NGCA-DATA-BUNDLE-INVALID'
    $policySignature = [IO.File]::ReadAllBytes((Assert-NgcaNoReparseAncestor $BackendPolicySignaturePath))
    $bundleSignature = [IO.File]::ReadAllBytes((Assert-NgcaNoReparseAncestor $DataBundleSignaturePath))
    $null = Assert-NgcaDetachedCmsSignature $policyArtifact.bytes $policySignature `
        ([string]$authorizationResult.authorization.identity.releaseSignerCertificateSha256) 'NGCA-POLICY-SIGNATURE-INVALID'
    $null = Assert-NgcaDetachedCmsSignature $bundleArtifact.bytes $bundleSignature `
        ([string]$authorizationResult.authorization.identity.releaseSignerCertificateSha256) 'NGCA-DATA-BUNDLE-SIGNATURE-INVALID'
    New-NgcaPlanApprovalArtifactCore $planResult $authorizationResult.artifact $policyArtifact $bundleArtifact `
        $identity.User.Value $ApprovalStateRoot $OutputRoot $SignerCertificateSha256 $CertificateStoreLocation `
        $LifetimeSeconds
}

Export-ModuleMember -Function @(
    'New-NorthGateCreateOnlyDataBundle',
    'New-NorthGateCreateOnlyBackendPolicyArtifact',
    'New-NorthGateCreateOnlyPlanApprovalArtifact'
)
