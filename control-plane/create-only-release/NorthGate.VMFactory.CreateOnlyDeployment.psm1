Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -ErrorAction Stop

$script:DeploymentSchema = 'northgate/create-only-deployment-transaction/v1'
$script:ProtectedRecordSchema = 'northgate/create-only-protected-record/v1'
$script:BackupSchema = 'northgate/create-only-deployment-backup/v1'
$script:BackupReceiptSchema = 'northgate/create-only-backup-receipt/v1'
$script:PointerSchema = 'northgate/create-only-current-release/v1'
$script:InstalledReleaseSchema = 'northgate/create-only-installed-release/v1'
$script:PolicySchema = 'northgate/create-only-installed-policy/v1'
$script:DeploymentLockName = 'Global\NorthGate.VMFactory.CreateOnly.Deployment.v1'
$script:ServiceName = 'NorthGateCreateOnly'
$script:ServiceAccount = 'NT SERVICE\NorthGateCreateOnly'
$script:PipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$script:ManagedSshBegin = '# BEGIN NORTHGATE CREATE-ONLY MANAGED BLOCK'
$script:ManagedSshEnd = '# END NORTHGATE CREATE-ONLY MANAGED BLOCK'
$script:FixedSshSourceCidr = '10.10.100.20/32'
$script:HeldDeploymentLocks = @{}

function Stop-Ngcd {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Get-NgcdUtcTimestamp {
    [DateTimeOffset]::UtcNow.ToString(
        "yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-NgcdSha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgcdHmacHex {
    param([Parameter(Mandatory)][byte[]]$Key, [Parameter(Mandatory)][string]$Value)
    if ($Key.Length -lt 32) { Stop-Ngcd 'NGCOR-DEPLOYMENT-STATE-KEY-INVALID' }
    $algorithm = New-Object System.Security.Cryptography.HMACSHA256(,$Key)
    try { $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value)) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgcdFixedHexEquals {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    $difference -eq 0
}

function Assert-NgcdExactProperties {
    param([object]$Value, [string[]]$Expected, [string]$Code)
    if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) { Stop-Ngcd $Code }
    $actual = @($Value.PSObject.Properties.Name)
    $wanted = @($Expected)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    [array]::Sort($wanted, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($wanted -join '|')) { Stop-Ngcd $Code }
}

function Get-NgcdFullPath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Code)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 240 -or
        $Path -match '[\x00-\x1f"<>|*?%$]' -or $Path -match '(?:^|\\)\.{1,2}(?:\\|$)') {
        Stop-Ngcd $Code
    }
    try { [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/') }
    catch { Stop-Ngcd $Code }
}

function Assert-NgcdPathWithin {
    param([string]$Path, [string]$Parent, [string]$Code)
    $full = Get-NgcdFullPath $Path $Code
    $root = Get-NgcdFullPath $Parent $Code
    if (-not $full.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase)) { Stop-Ngcd $Code }
    $full
}

function Assert-NgcdNoReparsePath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Code)
    $full = Get-NgcdFullPath $Path $Code
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor) -and -not [string]::IsNullOrWhiteSpace($cursor)) {
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and (Test-Path -LiteralPath $cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { Stop-Ngcd $Code }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    $full
}

function Read-NgcdExclusiveBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 67108864)][int64]$MaximumBytes = 16777216,
        [string]$Code = 'NGCOR-DEPLOYMENT-FILE-INVALID'
    )
    $full = Assert-NgcdNoReparsePath $Path $Code
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Stop-Ngcd $Code }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) { Stop-Ngcd $Code }
    $stream = New-Object System.IO.FileStream(
        $full, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::SequentialScan
    )
    try {
        $memory = New-Object System.IO.MemoryStream
        try { $stream.CopyTo($memory); $memory.ToArray() }
        finally { $memory.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Write-NgcdAtomicBytes {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][byte[]]$Bytes)
    $full = Assert-NgcdNoReparsePath $Path 'NGCOR-DEPLOYMENT-ATOMIC-PATH-INVALID'
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-ATOMIC-PARENT-MISSING'
    }
    $temporary = Join-Path $parent ('.ngcor-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $backup = Join-Path $parent ('.ngcor-replace-' + [guid]::NewGuid().ToString('N') + '.bak')
    try {
        $stream = New-Object System.IO.FileStream(
            $temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::WriteThrough
        )
        try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $full) {
            [System.IO.File]::Replace($temporary, $full, $backup, $true)
            if (Test-Path -LiteralPath $backup) { [System.IO.File]::Delete($backup) }
        }
        else { [System.IO.File]::Move($temporary, $full) }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { [System.IO.File]::Delete($temporary) }
        if (Test-Path -LiteralPath $backup) { [System.IO.File]::Delete($backup) }
    }
}

function Write-NgcdAtomicCanonicalJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Value)
    $json = ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $Value
    Write-NgcdAtomicBytes $Path ([System.Text.Encoding]::UTF8.GetBytes($json))
    $readback = Read-NgcdExclusiveBytes $Path 16777216 'NGCOR-DEPLOYMENT-ATOMIC-READBACK-FAILED'
    if (-not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $readback) `
            (Get-NgcdSha256Bytes ([System.Text.Encoding]::UTF8.GetBytes($json))))) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-ATOMIC-READBACK-FAILED'
    }
}

function New-NgcdProtectedEnvelope {
    param([Parameter(Mandatory)][object]$Record, [Parameter(Mandatory)][byte[]]$MacKey)
    $canonicalRecord = ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $Record
    [pscustomobject][ordered]@{
        schema = $script:ProtectedRecordSchema
        record = $Record
        mac = Get-NgcdHmacHex $MacKey $canonicalRecord
    }
}

function Write-NgcdProtectedRecord {
    param([string]$Path, [object]$Record, [byte[]]$MacKey)
    Write-NgcdAtomicCanonicalJson $Path (New-NgcdProtectedEnvelope $Record $MacKey)
}

function Read-NgcdProtectedRecord {
    param([string]$Path, [byte[]]$MacKey, [string]$Code = 'NGCOR-DEPLOYMENT-STATE-AUTHENTICATION-FAILED')
    $bytes = Read-NgcdExclusiveBytes $Path 1048576 $Code
    try { $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bytes -MaximumBytes 1048576 }
    catch { Stop-Ngcd $Code }
    $envelope = $parsed.Value
    Assert-NgcdExactProperties $envelope @('schema','record','mac') $Code
    if ($envelope.schema -cne $script:ProtectedRecordSchema -or $envelope.mac -cnotmatch '^[a-f0-9]{64}$') {
        Stop-Ngcd $Code
    }
    $expected = Get-NgcdHmacHex $MacKey (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $envelope.record)
    if (-not (Test-NgcdFixedHexEquals ([string]$envelope.mac) $expected)) { Stop-Ngcd $Code }
    $envelope.record
}

function Enter-NgcdDeploymentLock {
    param([string]$Name = $script:DeploymentLockName)
    if ($script:HeldDeploymentLocks.ContainsKey($Name)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-LOCK-BUSY'
    }
    $mutex = New-Object System.Threading.Mutex($false, $Name)
    try {
        try { $acquired = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { Stop-Ngcd 'NGCOR-DEPLOYMENT-LOCK-BUSY' }
        $script:HeldDeploymentLocks[$Name] = $true
        [pscustomobject]@{ Name = $Name; Mutex = $mutex; Acquired = $true }
    }
    catch { $mutex.Dispose(); throw }
}

function Exit-NgcdDeploymentLock {
    param([Parameter(Mandatory)][object]$Lock)
    try {
        if ($Lock.Acquired) { $Lock.Mutex.ReleaseMutex(); $Lock.Acquired = $false }
    }
    finally {
        if ($Lock.PSObject.Properties.Name -contains 'Name') {
            $script:HeldDeploymentLocks.Remove([string]$Lock.Name)
        }
        $Lock.Mutex.Dispose()
    }
}

function New-NgcdRandomHex {
    param([ValidateRange(16,64)][int]$ByteCount = 32)
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Initialize-NgcdDirectory {
    param([string]$Path)
    $full = Assert-NgcdNoReparsePath $Path 'NGCOR-DEPLOYMENT-DIRECTORY-REPARSE-FORBIDDEN'
    if (-not (Test-Path -LiteralPath $full)) { $null = [System.IO.Directory]::CreateDirectory($full) }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { Stop-Ngcd 'NGCOR-DEPLOYMENT-DIRECTORY-INVALID' }
    $full
}

function New-NgcdLocalTestContext {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][byte[]]$MacKey)
    if ($MacKey.Length -lt 32) { Stop-Ngcd 'NGCOR-DEPLOYMENT-STATE-KEY-INVALID' }
    $fullRoot = Initialize-NgcdDirectory $Root
    $releaseParent = Initialize-NgcdDirectory (Join-Path $fullRoot 'releases')
    $stateRoot = Initialize-NgcdDirectory (Join-Path $fullRoot 'state')
    $quarantineRoot = Initialize-NgcdDirectory (Join-Path $fullRoot 'quarantine')
    $policyRoot = Initialize-NgcdDirectory (Join-Path $fullRoot 'policy')
    $sshRoot = Initialize-NgcdDirectory (Join-Path $fullRoot 'ssh')
    $transactionsRoot = Initialize-NgcdDirectory (Join-Path $stateRoot 'deployment-transactions')
    $backupsRoot = Initialize-NgcdDirectory (Join-Path $stateRoot 'deployment-backups')
    [pscustomobject][ordered]@{
        Mode = 'LocalTestOnly'
        Root = $fullRoot
        ReleaseParent = $releaseParent
        StateRoot = $stateRoot
        QuarantineRoot = $quarantineRoot
        TransactionsRoot = $transactionsRoot
        BackupsRoot = $backupsRoot
        CurrentPointerPath = Join-Path $stateRoot 'current-release.json'
        PolicyPath = Join-Path $policyRoot 'installed-policy.json'
        SshConfigPath = Join-Path $sshRoot 'sshd_config'
        ServiceName = $script:ServiceName
        ServiceHostFileName = 'NorthGate.CreateOnly.ServiceHost.exe'
        LockName = 'Local\NorthGate.VMFactory.CreateOnly.Deployment.Test.' + [guid]::NewGuid().ToString('N')
        MacKey = $MacKey
    }
}

function Assert-NgcdContext {
    param([object]$Context)
    Assert-NgcdExactProperties $Context @(
        'Mode','Root','ReleaseParent','StateRoot','QuarantineRoot','TransactionsRoot','BackupsRoot',
        'CurrentPointerPath','PolicyPath','SshConfigPath','ServiceName','ServiceHostFileName','LockName','MacKey'
    ) 'NGCOR-DEPLOYMENT-CONTEXT-INVALID'
    if ($Context.Mode -notin @('LocalTestOnly','Production') -or $Context.MacKey -isnot [byte[]] -or
        $Context.MacKey.Length -lt 32) { Stop-Ngcd 'NGCOR-DEPLOYMENT-CONTEXT-INVALID' }
    foreach ($path in @($Context.Root,$Context.ReleaseParent,$Context.StateRoot,$Context.QuarantineRoot,
        $Context.TransactionsRoot,$Context.BackupsRoot)) {
        $null = Assert-NgcdNoReparsePath $path 'NGCOR-DEPLOYMENT-CONTEXT-REPARSE-FORBIDDEN'
    }
}

function Assert-NgcdAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-ADMINISTRATOR-REQUIRED'
    }
}

function Get-NgcdAclRuleFingerprint {
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemAccessRule]$Rule)
    '{0}|{1}|{2}|{3}|{4}|{5}' -f `
        ([string]$Rule.IdentityReference.Value),
        ([int]$Rule.AccessControlType),
        ([int64]$Rule.FileSystemRights),
        ([int]$Rule.InheritanceFlags),
        ([int]$Rule.PropagationFlags),
        ([bool]$Rule.IsInherited)
}

function Get-NgcdRawAclFingerprint {
    param([AllowNull()][System.Security.AccessControl.RawAcl]$Acl)
    if ($null -eq $Acl) { return '<null-dacl>' }
    [string[]]$aces = @(
        for ($index = 0; $index -lt $Acl.Count; $index++) {
            $ace = $Acl[$index]
            $bytes = New-Object byte[] $ace.BinaryLength
            $ace.GetBinaryForm($bytes, 0)
            (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
        }
    )
    [array]::Sort($aces, [System.StringComparer]::Ordinal)
    ([string]$Acl.Count) + '|' + ($aces -join "`n")
}

function Set-NgcdProtectedDirectoryAcl {
    param(
        [string]$Path, [string]$ServiceSid, [string]$SshSid, [bool]$AllowSshRead,
        [System.Security.AccessControl.FileSystemRights]$ServiceRights =
            [System.Security.AccessControl.FileSystemRights]::Modify
    )
    $directory = Initialize-NgcdDirectory $Path
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $service = New-Object System.Security.Principal.SecurityIdentifier($ServiceSid)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($sid in @($administrators,$system)) {
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation,
            [System.Security.AccessControl.AccessControlType]::Allow
        )))
    }
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $service, $ServiceRights, $inheritance, $propagation,
        [System.Security.AccessControl.AccessControlType]::Allow
    )))
    if ($AllowSshRead) {
        $ssh = New-Object System.Security.Principal.SecurityIdentifier($SshSid)
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ssh, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inheritance, $propagation,
            [System.Security.AccessControl.AccessControlType]::Allow
        )))
    }
    $security.SetOwner($administrators)
    [System.IO.Directory]::SetAccessControl($directory, $security)
    $readback = [System.IO.Directory]::GetAccessControl($directory)
    if (-not $readback.AreAccessRulesProtected) { Stop-Ngcd 'NGCOR-DEPLOYMENT-ACL-READBACK-FAILED' }
    $actualOwner = [string]$readback.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($actualOwner -cne [string]$administrators.Value) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-ACL-READBACK-FAILED'
    }
    # Windows can normalize descriptor control flags and ACE ordering during
    # persistence. Compare the complete authorization semantics instead: the
    # protected flag and owner above, then every explicit/inherited DACL rule by
    # trustee, type, rights bitmask, inheritance, propagation, and origin.
    [string[]]$wantedRules = @($security.GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier]
    ) | ForEach-Object { Get-NgcdAclRuleFingerprint $_ })
    [string[]]$actualRules = @($readback.GetAccessRules(
        $true, $true, [System.Security.Principal.SecurityIdentifier]
    ) | ForEach-Object { Get-NgcdAclRuleFingerprint $_ })
    [array]::Sort($wantedRules, [System.StringComparer]::Ordinal)
    [array]::Sort($actualRules, [System.StringComparer]::Ordinal)
    if (($wantedRules -join "`n") -cne ($actualRules -join "`n")) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-ACL-READBACK-FAILED'
    }
    $directory
}

function Get-NgcdProductionMacKey {
    param([string]$StateRoot)
    $keyPath = Join-Path $StateRoot 'deployment-state-key.dpapi'
    $entropy = [System.Text.Encoding]::UTF8.GetBytes('NorthGate.CreateOnly.Deployment.State.v1')
    if (Test-Path -LiteralPath $keyPath) {
        $protected = Read-NgcdExclusiveBytes $keyPath 4096 'NGCOR-DEPLOYMENT-STATE-KEY-INVALID'
        try {
            $key = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $protected, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-STATE-KEY-INVALID' }
        if ($key.Length -ne 32) { Stop-Ngcd 'NGCOR-DEPLOYMENT-STATE-KEY-INVALID' }
        return ,$key
    }
    $key = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($key) }
    finally { $generator.Dispose() }
    try {
        $protected = [System.Security.Cryptography.ProtectedData]::Protect(
            $key, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-STATE-KEY-PROTECTION-FAILED' }
    Write-NgcdAtomicBytes $keyPath $protected
    $readback = [System.Security.Cryptography.ProtectedData]::Unprotect(
        (Read-NgcdExclusiveBytes $keyPath 4096 'NGCOR-DEPLOYMENT-STATE-KEY-INVALID'),
        $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    if (-not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $key) (Get-NgcdSha256Bytes $readback))) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-STATE-KEY-READBACK-FAILED'
    }
    return ,$key
}

function New-NgcdProductionContext {
    param([object]$Authorization)
    Assert-NgcdAdministrator
    $releaseRoot = Get-NgcdFullPath ([string]$Authorization.install.versionedReleaseRoot) `
        'NGCOR-DEPLOYMENT-RELEASE-PATH-INVALID'
    $releaseParent = Split-Path -Parent $releaseRoot
    $stateRoot = Get-NgcdFullPath ([string]$Authorization.install.stateRoot) `
        'NGCOR-DEPLOYMENT-STATE-PATH-INVALID'
    $quarantineRoot = Get-NgcdFullPath ([string]$Authorization.install.quarantineRoot) `
        'NGCOR-DEPLOYMENT-QUARANTINE-PATH-INVALID'
    $serviceSid = [string]$Authorization.identity.serviceIdentitySid
    $sshSid = [string]$Authorization.identity.sshIdentitySid
    if ((Get-NgcdServiceSid) -cne $serviceSid) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-SID-MISMATCH' }
    $null = Set-NgcdProtectedDirectoryAcl $releaseParent $serviceSid $sshSid $true `
        ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
    $serviceRead = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $null = Set-NgcdProtectedDirectoryAcl $stateRoot $serviceSid $sshSid $false $serviceRead
    $null = Set-NgcdProtectedDirectoryAcl $quarantineRoot $serviceSid $sshSid $false $serviceRead
    $transactionsRoot = Set-NgcdProtectedDirectoryAcl (Join-Path $stateRoot 'deployment-transactions') `
        $serviceSid $sshSid $false $serviceRead
    $backupsRoot = Set-NgcdProtectedDirectoryAcl (Join-Path $stateRoot 'deployment-backups') `
        $serviceSid $sshSid $false $serviceRead
    $policyRoot = Set-NgcdProtectedDirectoryAcl (Join-Path (Split-Path -Parent $stateRoot) 'policy') `
        $serviceSid $sshSid $false $serviceRead
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    [pscustomobject][ordered]@{
        Mode = 'Production'
        Root = Split-Path -Parent $releaseParent
        ReleaseParent = $releaseParent
        StateRoot = $stateRoot
        QuarantineRoot = $quarantineRoot
        TransactionsRoot = $transactionsRoot
        BackupsRoot = $backupsRoot
        CurrentPointerPath = Join-Path $stateRoot 'current-release.json'
        PolicyPath = Join-Path $policyRoot 'installed-policy.json'
        SshConfigPath = Join-Path $programData 'ssh\sshd_config'
        ServiceName = $script:ServiceName
        ServiceHostFileName = 'NorthGate.CreateOnly.ServiceHost.exe'
        LockName = $script:DeploymentLockName
        MacKey = Get-NgcdProductionMacKey $stateRoot
    }
}

function Get-NgcdExistingProductionContext {
    param([object]$Authorization)
    Assert-NgcdAdministrator
    $releaseRoot = Get-NgcdFullPath ([string]$Authorization.install.versionedReleaseRoot) `
        'NGCOR-DEPLOYMENT-RELEASE-PATH-INVALID'
    $releaseParent = Split-Path -Parent $releaseRoot
    $stateRoot = Get-NgcdFullPath ([string]$Authorization.install.stateRoot) `
        'NGCOR-DEPLOYMENT-STATE-PATH-INVALID'
    $quarantineRoot = Get-NgcdFullPath ([string]$Authorization.install.quarantineRoot) `
        'NGCOR-DEPLOYMENT-QUARANTINE-PATH-INVALID'
    $transactionsRoot = Join-Path $stateRoot 'deployment-transactions'
    $backupsRoot = Join-Path $stateRoot 'deployment-backups'
    $policyRoot = Join-Path (Split-Path -Parent $stateRoot) 'policy'
    foreach ($required in @($releaseParent,$stateRoot,$quarantineRoot,$transactionsRoot,$backupsRoot,$policyRoot)) {
        $null = Assert-NgcdNoReparsePath $required 'NGCOR-ROLLBACK-STATE-PATH-INVALID'
        if (-not (Test-Path -LiteralPath $required -PathType Container)) { Stop-Ngcd 'NGCOR-ROLLBACK-STATE-MISSING' }
    }
    if ((Get-NgcdServiceSid) -cne [string]$Authorization.identity.serviceIdentitySid) {
        Stop-Ngcd 'NGCOR-ROLLBACK-SERVICE-SID-MISMATCH'
    }
    $keyPath = Join-Path $stateRoot 'deployment-state-key.dpapi'
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { Stop-Ngcd 'NGCOR-ROLLBACK-STATE-KEY-MISSING' }
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    [pscustomobject][ordered]@{
        Mode = 'Production'
        Root = Split-Path -Parent $releaseParent
        ReleaseParent = $releaseParent
        StateRoot = $stateRoot
        QuarantineRoot = $quarantineRoot
        TransactionsRoot = $transactionsRoot
        BackupsRoot = $backupsRoot
        CurrentPointerPath = Join-Path $stateRoot 'current-release.json'
        PolicyPath = Join-Path $policyRoot 'installed-policy.json'
        SshConfigPath = Join-Path $programData 'ssh\sshd_config'
        ServiceName = $script:ServiceName
        ServiceHostFileName = 'NorthGate.CreateOnly.ServiceHost.exe'
        LockName = $script:DeploymentLockName
        MacKey = Get-NgcdProductionMacKey $stateRoot
    }
}

function Get-NgcdRuntimeContext {
    param([object]$Authorization)
    $expectedServiceSid = [string]$Authorization.identity.serviceIdentitySid
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $actualSids = @([string]$identity.User.Value) + @($identity.Groups | ForEach-Object { [string]$_.Value })
    if ($expectedServiceSid -notin $actualSids -or (Get-NgcdServiceSid) -cne $expectedServiceSid) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-IDENTITY-MISMATCH'
    }
    $releaseRoot = Get-NgcdFullPath ([string]$Authorization.install.versionedReleaseRoot) `
        'NGCOR-DEPLOYMENT-RELEASE-PATH-INVALID'
    $releaseParent = Split-Path -Parent $releaseRoot
    $stateRoot = Get-NgcdFullPath ([string]$Authorization.install.stateRoot) `
        'NGCOR-DEPLOYMENT-STATE-PATH-INVALID'
    $quarantineRoot = Get-NgcdFullPath ([string]$Authorization.install.quarantineRoot) `
        'NGCOR-DEPLOYMENT-QUARANTINE-PATH-INVALID'
    $transactionsRoot = Join-Path $stateRoot 'deployment-transactions'
    $backupsRoot = Join-Path $stateRoot 'deployment-backups'
    $policyRoot = Join-Path (Split-Path -Parent $stateRoot) 'policy'
    foreach ($required in @($releaseParent,$stateRoot,$quarantineRoot,$transactionsRoot,$backupsRoot,$policyRoot)) {
        $null = Assert-NgcdNoReparsePath $required 'NGCOR-DEPLOYMENT-RUNTIME-PATH-INVALID'
        if (-not (Test-Path -LiteralPath $required -PathType Container)) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-PATH-INVALID'
        }
    }
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    [pscustomobject][ordered]@{
        Mode = 'Production'
        Root = Split-Path -Parent $releaseParent
        ReleaseParent = $releaseParent
        StateRoot = $stateRoot
        QuarantineRoot = $quarantineRoot
        TransactionsRoot = $transactionsRoot
        BackupsRoot = $backupsRoot
        CurrentPointerPath = Join-Path $stateRoot 'current-release.json'
        PolicyPath = Join-Path $policyRoot 'installed-policy.json'
        SshConfigPath = Join-Path $programData 'ssh\sshd_config'
        ServiceName = $script:ServiceName
        ServiceHostFileName = 'NorthGate.CreateOnly.ServiceHost.exe'
        LockName = $script:DeploymentLockName
        MacKey = Get-NgcdProductionMacKey $stateRoot
    }
}

function Get-NgcdFileSddl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    try { (Get-Acl -LiteralPath $Path).Sddl }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-ACL-READ-FAILED' }
}

function Set-NgcdFileSddl {
    param([string]$Path, [string]$Sddl)
    if ([string]::IsNullOrEmpty($Sddl)) { return }
    try {
        $wanted = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
        $current = [System.IO.File]::GetAccessControl($Path)
        $currentOwner = $current.GetOwner([System.Security.Principal.SecurityIdentifier])
        $currentGroup = $current.GetGroup([System.Security.Principal.SecurityIdentifier])
        if ($null -ne $wanted.Owner -and $currentOwner.Value -cne $wanted.Owner.Value) {
            $ownerSecurity = New-Object System.Security.AccessControl.FileSecurity
            $ownerSecurity.SetOwner($wanted.Owner)
            [System.IO.File]::SetAccessControl($Path, $ownerSecurity)
        }
        if ($null -ne $wanted.Group -and $currentGroup.Value -cne $wanted.Group.Value) {
            $groupSecurity = New-Object System.Security.AccessControl.FileSecurity
            $groupSecurity.SetGroup($wanted.Group)
            [System.IO.File]::SetAccessControl($Path, $groupSecurity)
        }
        $accessSection = [System.Security.AccessControl.AccessControlSections]::Access
        $accessSecurity = New-Object System.Security.AccessControl.FileSecurity
        $accessSecurity.SetSecurityDescriptorSddlForm($Sddl, $accessSection)
        [System.IO.File]::SetAccessControl($Path, $accessSecurity)

        $readbackSddl = ([System.IO.File]::GetAccessControl($Path)).Sddl
        $actual = New-Object System.Security.AccessControl.RawSecurityDescriptor($readbackSddl)
        $wantedOwner = if ($null -eq $wanted.Owner) { '' } else { [string]$wanted.Owner.Value }
        $actualOwner = if ($null -eq $actual.Owner) { '' } else { [string]$actual.Owner.Value }
        $wantedGroup = if ($null -eq $wanted.Group) { '' } else { [string]$wanted.Group.Value }
        $actualGroup = if ($null -eq $actual.Group) { '' } else { [string]$actual.Group.Value }
        $protectedFlag = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
        $wantedProtected = (($wanted.ControlFlags -band $protectedFlag) -ne 0)
        $actualProtected = (($actual.ControlFlags -band $protectedFlag) -ne 0)
        $wantedDacl = Get-NgcdRawAclFingerprint $wanted.DiscretionaryAcl
        $actualDacl = Get-NgcdRawAclFingerprint $actual.DiscretionaryAcl
        if ($wantedOwner -cne $actualOwner -or $wantedGroup -cne $actualGroup -or
            $wantedProtected -ne $actualProtected -or $wantedDacl -cne $actualDacl) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-ACL-READBACK-FAILED'
        }
    }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-ACL-READBACK-FAILED' }
}

function Get-NgcdServiceConfiguration {
    param([object]$Context)
    if ($Context.Mode -ne 'Production') {
        return [pscustomobject][ordered]@{
            existed = $false; name = $script:ServiceName; pathName = ''; startMode = ''
            startName = ''; state = ''; description = ''
        }
    }
    $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") `
        -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [pscustomobject][ordered]@{
            existed = $false; name = $script:ServiceName; pathName = ''; startMode = ''
            startName = ''; state = ''; description = ''
        }
    }
    [pscustomobject][ordered]@{
        existed = $true
        name = $script:ServiceName
        pathName = [string]$service.PathName
        startMode = [string]$service.StartMode
        startName = [string]$service.StartName
        state = [string]$service.State
        description = [string]$service.Description
    }
}

function Restore-NgcdServiceConfiguration {
    param([object]$Context, [object]$Configuration)
    Assert-NgcdExactProperties $Configuration @(
        'existed','name','pathName','startMode','startName','state','description'
    ) 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID'
    if ($Configuration.name -cne $script:ServiceName) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID' }
    if ($Context.Mode -ne 'Production') { return }
    $current = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") `
        -ErrorAction SilentlyContinue
    if ($Configuration.existed -eq $false) {
        if ($null -ne $current) {
            if ($current.State -ne 'Stopped') { $null = Invoke-NgcdSc @('stop',$script:ServiceName) }
            $null = Invoke-NgcdSc @('delete',$script:ServiceName)
        }
        return
    }
    if ($Configuration.existed -ne $true -or [string]::IsNullOrWhiteSpace([string]$Configuration.pathName) -or
        [string]::IsNullOrWhiteSpace([string]$Configuration.startName)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID'
    }
    $start = switch ([string]$Configuration.startMode) {
        'Auto' { 'auto' }
        'Manual' { 'demand' }
        'Disabled' { 'disabled' }
        default { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID' }
    }
    if ($null -eq $current) {
        $null = Invoke-NgcdSc @(
            'create',$script:ServiceName,'binPath=',([string]$Configuration.pathName),
            'start=',$start,'obj=',([string]$Configuration.startName)
        )
    }
    else {
        if ($current.State -ne 'Stopped') { $null = Invoke-NgcdSc @('stop',$script:ServiceName) }
        $null = Invoke-NgcdSc @(
            'config',$script:ServiceName,'binPath=',([string]$Configuration.pathName),
            'start=',$start,'obj=',([string]$Configuration.startName)
        )
    }
    if (-not [string]::IsNullOrEmpty([string]$Configuration.description)) {
        $null = Invoke-NgcdSc @('description',$script:ServiceName,([string]$Configuration.description))
    }
    if ($Configuration.state -ceq 'Running') { $null = Invoke-NgcdSc @('start',$script:ServiceName) }
}

function New-NgcdBackup {
    param([object]$Context, [string]$TransactionId, [object]$Binding)
    Assert-NgcdContext $Context
    if ($TransactionId -cnotmatch '^ngtxn-[a-f0-9]{64}$') { Stop-Ngcd 'NGCOR-DEPLOYMENT-TRANSACTION-ID-INVALID' }
    $backupRoot = Join-Path $Context.BackupsRoot $TransactionId
    if (Test-Path -LiteralPath $backupRoot) { Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-EXISTS' }
    $null = [System.IO.Directory]::CreateDirectory($backupRoot)
    $filesRoot = Join-Path $backupRoot 'files'
    $null = [System.IO.Directory]::CreateDirectory($filesRoot)
    $targets = @(
        [pscustomobject]@{ name = 'currentPointer'; path = [string]$Context.CurrentPointerPath },
        [pscustomobject]@{ name = 'installedPolicy'; path = [string]$Context.PolicyPath },
        [pscustomobject]@{ name = 'sshdConfig'; path = [string]$Context.SshConfigPath }
    )
    $records = @()
    foreach ($target in $targets) {
        $null = Assert-NgcdNoReparsePath $target.path 'NGCOR-DEPLOYMENT-BACKUP-TARGET-INVALID'
        if (Test-Path -LiteralPath $target.path -PathType Leaf) {
            $bytes = Read-NgcdExclusiveBytes $target.path 16777216 'NGCOR-DEPLOYMENT-BACKUP-READ-FAILED'
            $backupFile = $target.name + '.bin'
            $backupPath = Join-Path $filesRoot $backupFile
            $stream = New-Object System.IO.FileStream(
                $backupPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::WriteThrough
            )
            try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
            finally { $stream.Dispose() }
            $records += [pscustomobject][ordered]@{
                name = $target.name; path = $target.path; existed = $true; backupFile = $backupFile
                sizeBytes = [int64]$bytes.Length; sha256 = Get-NgcdSha256Bytes $bytes
                sddl = Get-NgcdFileSddl $target.path
            }
        }
        else {
            $records += [pscustomobject][ordered]@{
                name = $target.name; path = $target.path; existed = $false; backupFile = ''
                sizeBytes = [int64]0; sha256 = '0' * 64; sddl = ''
            }
        }
    }
    $backup = [pscustomobject][ordered]@{
        schema = $script:BackupSchema
        transactionId = $TransactionId
        createdAtUtc = Get-NgcdUtcTimestamp
        binding = $Binding
        targets = [object[]]$records
        serviceConfiguration = Get-NgcdServiceConfiguration $Context
    }
    $recordPath = Join-Path $backupRoot 'backup-record.json'
    Write-NgcdProtectedRecord $recordPath $backup $Context.MacKey
    $recordBytes = Read-NgcdExclusiveBytes $recordPath
    $receipt = [pscustomobject][ordered]@{
        schema = $script:BackupReceiptSchema
        transactionId = $TransactionId
        releaseId = [string]$Binding.releaseId
        releaseManifestSha256 = [string]$Binding.releaseManifestSha256
        deploymentAuthorizationSha256 = [string]$Binding.deploymentAuthorizationSha256
        hostId = [string]$Binding.hostId
        receiptSignerCertificateSha256 = [string]$Binding.receiptSignerCertificateSha256
        backupRecordSha256 = Get-NgcdSha256Bytes $recordBytes
        permittedTargets = [object[]]@('currentPointer','installedPolicy','sshdConfig','serviceConfiguration','releaseDirectory')
        createdAtUtc = Get-NgcdUtcTimestamp
    }
    $receiptPath = Join-Path $backupRoot 'backup-receipt.json'
    Write-NgcdAtomicCanonicalJson $receiptPath $receipt
    $receiptHash = Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $receiptPath)
    $receiptSignaturePath = ''
    if ($Context.Mode -eq 'Production') {
        $receiptSignaturePath = Join-Path $backupRoot 'backup-receipt.p7s'
        New-NgcdDetachedCmsSignature $receiptPath $receiptSignaturePath `
            ([string]$Binding.receiptSignerCertificateSha256)
    }
    [pscustomobject][ordered]@{
        BackupRoot = $backupRoot
        BackupRecordPath = $recordPath
        BackupReceiptPath = $receiptPath
        BackupReceiptSha256 = $receiptHash
        BackupReceiptSignaturePath = $receiptSignaturePath
    }
}

function Get-NgcdExpectedManagedPath {
    param([object]$Context, [string]$Name)
    switch ($Name) {
        'currentPointer' { return [string]$Context.CurrentPointerPath }
        'installedPolicy' { return [string]$Context.PolicyPath }
        'sshdConfig' { return [string]$Context.SshConfigPath }
        default { Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-TARGET-INVALID' }
    }
}

function Restore-NgcdBackup {
    param([object]$Context, [string]$BackupRoot, [object]$ExpectedBinding)
    Assert-NgcdContext $Context
    $root = Assert-NgcdPathWithin $BackupRoot $Context.BackupsRoot 'NGCOR-DEPLOYMENT-BACKUP-PATH-INVALID'
    $backup = Read-NgcdProtectedRecord (Join-Path $root 'backup-record.json') $Context.MacKey
    Assert-NgcdExactProperties $backup @('schema','transactionId','createdAtUtc','binding','targets','serviceConfiguration') `
        'NGCOR-DEPLOYMENT-BACKUP-INVALID'
    if ($backup.schema -cne $script:BackupSchema -or
        (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $backup.binding) -cne
        (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $ExpectedBinding)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-BINDING-MISMATCH'
    }
    if ($backup.targets -isnot [System.Array] -or @($backup.targets).Count -ne 3) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
    }
    foreach ($record in @($backup.targets)) {
        Assert-NgcdExactProperties $record @('name','path','existed','backupFile','sizeBytes','sha256','sddl') `
            'NGCOR-DEPLOYMENT-BACKUP-INVALID'
        $expectedPath = Get-NgcdExpectedManagedPath $Context ([string]$record.name)
        if ([string]$record.path -cne $expectedPath) { Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-TARGET-INVALID' }
        $null = Assert-NgcdNoReparsePath $expectedPath 'NGCOR-DEPLOYMENT-BACKUP-TARGET-INVALID'
        if ($record.existed -eq $true) {
            if ($record.backupFile -cnotmatch '^[A-Za-z][A-Za-z0-9-]{1,63}\.bin$') {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
            }
            $backupPath = Assert-NgcdPathWithin (Join-Path (Join-Path $root 'files') ([string]$record.backupFile)) `
                (Join-Path $root 'files') 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
            $bytes = Read-NgcdExclusiveBytes $backupPath 16777216 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
            if ([int64]$bytes.Length -ne [int64]$record.sizeBytes -or
                -not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $bytes) ([string]$record.sha256))) {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-HASH-MISMATCH'
            }
            Write-NgcdAtomicBytes $expectedPath $bytes
            Set-NgcdFileSddl $expectedPath ([string]$record.sddl)
        }
        elseif ($record.existed -eq $false) {
            if (Test-Path -LiteralPath $expectedPath) { [System.IO.File]::Delete($expectedPath) }
        }
        else { Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID' }
    }
    Restore-NgcdServiceConfiguration $Context $backup.serviceConfiguration
}

function Get-NgcdManifestPhysicalRecords {
    param([object[]]$FileRecords)
    if ($FileRecords.Count -lt 1 -or $FileRecords.Count -gt 32) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
    }
    $physical = New-Object 'Collections.Generic.List[object]'
    $rawByPath = @{}
    $derived = @()
    $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $FileRecords) {
        $kind = [string]$record.artifactKind
        if ($kind -ceq 'raw-git-blob') {
            Assert-NgcdExactProperties $record @(
                'artifactKind','path','gitMode','gitBlobOid','sizeBytes','sha256'
            ) 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            if ($record.gitMode -cne '100644' -or $record.gitBlobOid -cnotmatch '^[a-f0-9]{40}$') {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            }
            $rawByPath[[string]$record.path] = $record
        }
        elseif ($kind -ceq 'derived-signed-artifact') {
            Assert-NgcdExactProperties $record @(
                'artifactKind','path','sizeBytes','sha256','buildProvenance','detachedCms'
            ) 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            if ($record.path -cne 'NorthGate.CreateOnly.ServiceHost.exe') {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            }
            Assert-NgcdExactProperties $record.buildProvenance @(
                'sourcePath','sourceGitBlobOid','sourceSha256','buildScriptPath','buildScriptGitBlobOid',
                'buildScriptSha256','compilerPath','compilerSha256','compilerVersion','deterministic',
                'unsignedSha256','references'
            ) 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            Assert-NgcdExactProperties $record.detachedCms @(
                'path','sizeBytes','sha256','signerCertificateSha256'
            ) 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            $build = $record.buildProvenance
            if ($build.sourcePath -cne 'NorthGate.CreateOnly.ServiceHost.cs' -or
                $build.buildScriptPath -cne 'Build-NorthGateCreateOnlyServiceHost.ps1' -or
                $build.sourceGitBlobOid -cnotmatch '^[a-f0-9]{40}$' -or
                $build.buildScriptGitBlobOid -cnotmatch '^[a-f0-9]{40}$' -or
                $build.sourceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $build.buildScriptSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                -not [IO.Path]::IsPathRooted([string]$build.compilerPath) -or
                [string]::IsNullOrWhiteSpace([string]$build.compilerVersion) -or
                $build.compilerSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $build.unsignedSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $build.deterministic -ne $true -or @($build.references).Count -ne 5 -or
                $record.detachedCms.path -cne 'NorthGate.CreateOnly.ServiceHost.exe.p7s' -or
                $record.detachedCms.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $record.detachedCms.signerCertificateSha256 -cnotmatch '^[a-f0-9]{64}$') {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            }
            $referenceNames = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($reference in @($build.references)) {
                Assert-NgcdExactProperties $reference @('path','sha256','fileVersion') `
                    'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
                if (-not [IO.Path]::IsPathRooted([string]$reference.path) -or
                    $reference.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    [string]::IsNullOrWhiteSpace([string]$reference.fileVersion) -or
                    -not $referenceNames.Add([IO.Path]::GetFileName([string]$reference.path))) {
                    Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
                }
            }
            $derived += $record
        }
        else { Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID' }

        $relative = [string]$record.path
        if ($relative -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$' -or
            $relative -match '(?:^|/)\.\.?(/|$)' -or -not $seen.Add($relative) -or
            $record.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            -not ($record.sizeBytes -is [int64] -or $record.sizeBytes -is [int32]) -or
            [int64]$record.sizeBytes -le 0 -or [int64]$record.sizeBytes -gt 67108864) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
        }
        $physical.Add([pscustomobject]@{
            path = $relative; sizeBytes = [int64]$record.sizeBytes; sha256 = [string]$record.sha256
        })
        if ($kind -ceq 'derived-signed-artifact') {
            if (-not $seen.Add([string]$record.detachedCms.path) -or
                -not ($record.detachedCms.sizeBytes -is [int64] -or
                    $record.detachedCms.sizeBytes -is [int32]) -or
                [int64]$record.detachedCms.sizeBytes -le 0 -or
                [int64]$record.detachedCms.sizeBytes -gt 1048576) {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
            }
            $physical.Add([pscustomobject]@{
                path = [string]$record.detachedCms.path
                sizeBytes = [int64]$record.detachedCms.sizeBytes
                sha256 = [string]$record.detachedCms.sha256
            })
        }
    }
    if ($derived.Count -ne 1) { Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID' }
    $derivedBuild = $derived[0].buildProvenance
    foreach ($binding in @(
            [pscustomobject]@{ path = [string]$derivedBuild.sourcePath; oid = [string]$derivedBuild.sourceGitBlobOid; hash = [string]$derivedBuild.sourceSha256 },
            [pscustomobject]@{ path = [string]$derivedBuild.buildScriptPath; oid = [string]$derivedBuild.buildScriptGitBlobOid; hash = [string]$derivedBuild.buildScriptSha256 }
        )) {
        if (-not $rawByPath.ContainsKey($binding.path) -or
            $rawByPath[$binding.path].gitBlobOid -cne $binding.oid -or
            $rawByPath[$binding.path].sha256 -cne $binding.hash) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-MANIFEST-FILE-INVALID'
        }
    }
    [object[]]$physical.ToArray()
}

function Copy-NgcdPackageFiles {
    param([string]$PackageRoot, [string]$StagingRoot, [object[]]$FileRecords)
    $package = Assert-NgcdNoReparsePath $PackageRoot 'NGCOR-DEPLOYMENT-PACKAGE-REPARSE-FORBIDDEN'
    if (-not (Test-Path -LiteralPath $package -PathType Container)) { Stop-Ngcd 'NGCOR-DEPLOYMENT-PACKAGE-INVALID' }
    if (Test-Path -LiteralPath $StagingRoot) { Stop-Ngcd 'NGCOR-DEPLOYMENT-STAGING-EXISTS' }
    $null = [System.IO.Directory]::CreateDirectory($StagingRoot)
    $physicalRecords = Get-NgcdManifestPhysicalRecords $FileRecords
    foreach ($record in $physicalRecords) {
        $relative = [string]$record.path
        $source = Assert-NgcdPathWithin (Join-Path $package $relative.Replace('/','\')) $package `
            'NGCOR-DEPLOYMENT-PACKAGE-PATH-INVALID'
        $destination = Assert-NgcdPathWithin (Join-Path $StagingRoot $relative.Replace('/','\')) $StagingRoot `
            'NGCOR-DEPLOYMENT-STAGING-PATH-INVALID'
        $destinationParent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $destinationParent)) { $null = [IO.Directory]::CreateDirectory($destinationParent) }
        $bytes = Read-NgcdExclusiveBytes $source 67108864 'NGCOR-DEPLOYMENT-PACKAGE-FILE-INVALID'
        if ([int64]$bytes.Length -ne [int64]$record.sizeBytes -or
            -not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $bytes) ([string]$record.sha256))) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-PACKAGE-FILE-HASH-MISMATCH'
        }
        $stream = New-Object System.IO.FileStream(
            $destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None, 65536, [System.IO.FileOptions]::WriteThrough
        )
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        $readback = Read-NgcdExclusiveBytes $destination 67108864 'NGCOR-DEPLOYMENT-STAGING-READBACK-FAILED'
        if (-not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $readback) ([string]$record.sha256))) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-STAGING-READBACK-FAILED'
        }
    }
}

function Test-NgcdPackageFiles {
    param([string]$Root, [object[]]$FileRecords)
    foreach ($record in @(Get-NgcdManifestPhysicalRecords $FileRecords)) {
        $path = Assert-NgcdPathWithin (Join-Path $Root ([string]$record.path).Replace('/','\')) $Root `
            'NGCOR-DEPLOYMENT-INSTALLED-PATH-INVALID'
        $bytes = Read-NgcdExclusiveBytes $path 67108864 'NGCOR-DEPLOYMENT-INSTALLED-FILE-INVALID'
        if ([int64]$bytes.Length -ne [int64]$record.sizeBytes -or
            -not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $bytes) ([string]$record.sha256))) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-INSTALLED-FILE-HASH-MISMATCH'
        }
    }
    $true
}

function Write-NgcdRuntimeArtifactsToStaging {
    param([string]$StagingRoot,[object]$RuntimeArtifacts)
    Assert-NgcdExactProperties $RuntimeArtifacts @(
        'releaseManifestSignature','deploymentAuthorizationSignature','backendPolicy',
        'backendPolicySignature','backendPolicySha256','dataBundle','dataBundleSignature',
        'dataBundleSha256','dataBundleId','stateKeyId',
        'deploymentAuthorizationSignerCertificateSha256','dataFiles'
    ) 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID'
    foreach ($hash in @(
            $RuntimeArtifacts.backendPolicySha256,$RuntimeArtifacts.dataBundleSha256,
            $RuntimeArtifacts.deploymentAuthorizationSignerCertificateSha256
        )) {
        if ($hash -cnotmatch '^[a-f0-9]{64}$') { Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID' }
    }
    if ($RuntimeArtifacts.dataBundleId -cnotmatch '^ngdata-[a-f0-9]{64}$' -or
        $RuntimeArtifacts.stateKeyId -cnotmatch '^ngkey-[a-z0-9-]{8,64}$') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID'
    }
    $fixed = [ordered]@{
        'release-manifest.p7s'=$RuntimeArtifacts.releaseManifestSignature
        'deployment-authorization.p7s'=$RuntimeArtifacts.deploymentAuthorizationSignature
        'backend-policy.json'=$RuntimeArtifacts.backendPolicy
        'backend-policy.p7s'=$RuntimeArtifacts.backendPolicySignature
        'backend-data\bundle.json'=$RuntimeArtifacts.dataBundle
        'backend-data\bundle.p7s'=$RuntimeArtifacts.dataBundleSignature
    }
    foreach ($name in $fixed.Keys) {
        if ($fixed[$name] -isnot [byte[]] -or $fixed[$name].Length -le 0 -or $fixed[$name].Length -gt 10485760) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID'
        }
        $destination=Join-Path $StagingRoot $name
        $parent=Split-Path -Parent $destination
        if(-not(Test-Path -LiteralPath $parent -PathType Container)){$null=[IO.Directory]::CreateDirectory($parent)}
        Write-NgcdAtomicBytes $destination $fixed[$name]
    }
    $dataRoot=Join-Path $StagingRoot 'backend-data'
    $null=[IO.Directory]::CreateDirectory($dataRoot)
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($file in @($RuntimeArtifacts.dataFiles)) {
        Assert-NgcdExactProperties $file @('relativePath','bytes') 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID'
        if ($file.relativePath -cnotmatch '^files/[A-Za-z0-9._/-]{1,180}\.json$' -or
            $file.relativePath -match '(?:^|/)\.\.(?:/|$)' -or -not $seen.Add([string]$file.relativePath) -or
            $file.bytes -isnot [byte[]] -or $file.bytes.Length -le 0 -or $file.bytes.Length -gt 1048576) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID'
        }
        $destination=Assert-NgcdPathWithin (Join-Path $dataRoot ([string]$file.relativePath).Replace('/','\')) `
            $dataRoot 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID'
        $parent=Split-Path -Parent $destination
        if(-not(Test-Path -LiteralPath $parent -PathType Container)){$null=[IO.Directory]::CreateDirectory($parent)}
        Write-NgcdAtomicBytes $destination $file.bytes
    }
    if ($seen.Count -lt 7) { Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACTS-INVALID' }
}

function Test-NgcdInstalledRuntimeArtifacts {
    param([string]$ReleaseRoot,[object]$RuntimeArtifacts)
    $expected=[ordered]@{
        'release-manifest.p7s'=$RuntimeArtifacts.releaseManifestSignature
        'deployment-authorization.p7s'=$RuntimeArtifacts.deploymentAuthorizationSignature
        'backend-policy.json'=$RuntimeArtifacts.backendPolicy
        'backend-policy.p7s'=$RuntimeArtifacts.backendPolicySignature
        'backend-data\bundle.json'=$RuntimeArtifacts.dataBundle
        'backend-data\bundle.p7s'=$RuntimeArtifacts.dataBundleSignature
    }
    foreach($file in @($RuntimeArtifacts.dataFiles)){
        $expected[('backend-data\'+([string]$file.relativePath).Replace('/','\'))]=$file.bytes
    }
    foreach($relative in $expected.Keys){
        $actual=Read-NgcdExclusiveBytes (Join-Path $ReleaseRoot $relative) 10485760 `
            'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACT-READBACK-FAILED'
        if(-not(Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $actual) (Get-NgcdSha256Bytes $expected[$relative]))){
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RUNTIME-ARTIFACT-READBACK-FAILED'
        }
    }
    $true
}

function Initialize-NgcdBackendState {
    param([object]$Context,[object]$Authorization,[string]$ReleaseId,[string]$StateKeyId)
    $backendParent=Join-Path $Context.StateRoot 'backend'
    $null=Set-NgcdProtectedDirectoryAcl $backendParent ([string]$Authorization.identity.serviceIdentitySid) `
        ([string]$Authorization.identity.sshIdentitySid) $false `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    $backendRoot=Join-Path $backendParent $ReleaseId
    if(Test-Path -LiteralPath $backendRoot){Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKEND-STATE-EXISTS'}
    $null=Set-NgcdProtectedDirectoryAcl $backendRoot ([string]$Authorization.identity.serviceIdentitySid) `
        ([string]$Authorization.identity.sshIdentitySid) $false `
        ([Security.AccessControl.FileSystemRights]::Modify)
    $key=New-Object byte[] 32
    $generator=[Security.Cryptography.RandomNumberGenerator]::Create()
    try{$generator.GetBytes($key)}finally{$generator.Dispose()}
    $entropy=[Text.Encoding]::UTF8.GetBytes('northgate-vm-factory|'+$StateKeyId)
    try{$protected=[Security.Cryptography.ProtectedData]::Protect($key,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)}
    catch{Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKEND-STATE-KEY-PROTECTION-FAILED'}
    $keyPath=Join-Path $backendRoot 'state-key.dpapi'
    Write-NgcdAtomicBytes $keyPath $protected
    try{$readback=[Security.Cryptography.ProtectedData]::Unprotect((Read-NgcdExclusiveBytes $keyPath 4096),$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)}
    catch{Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKEND-STATE-KEY-READBACK-FAILED'}
    if(-not(Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes $key) (Get-NgcdSha256Bytes $readback))){
        Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKEND-STATE-KEY-READBACK-FAILED'
    }
    [pscustomobject]@{Root=$backendRoot;KeyPath=$keyPath}
}

function New-NgcdBinding {
    param([object]$Manifest, [object]$Authorization, [string]$AuthorizationSha256)
    [pscustomobject][ordered]@{
        releaseId = [string]$Manifest.releaseId
        releaseManifestSha256 = [string]$Authorization.releaseManifestSha256
        deploymentAuthorizationSha256 = $AuthorizationSha256
        hostId = [string]$Authorization.host.hostId
        repositoryCommit = [string]$Manifest.repository.commit
        repositoryTree = [string]$Manifest.repository.tree
        receiptSignerCertificateSha256 = [string]$Authorization.identity.receiptSignerCertificateSha256
    }
}

function New-NgcdTransactionId {
    param([object]$Binding, [string]$AuthorizationId)
    $material = (ConvertTo-NorthGateCreateOnlyCanonicalJson -InputObject $Binding) + '|' + $AuthorizationId
    'ngtxn-' + (Get-NgcdSha256Bytes ([System.Text.Encoding]::UTF8.GetBytes($material)))
}

function New-NgcdJournal {
    param([object]$Context, [string]$TransactionId, [object]$Binding, [object]$Paths, [string]$ReceiptSha256)
    $record = [pscustomobject][ordered]@{
        schema = $script:DeploymentSchema
        transactionId = $TransactionId
        sequence = 1
        phase = 'Prepared'
        binding = $Binding
        paths = $Paths
        backupReceiptSha256 = $ReceiptSha256
        events = [object[]]@([pscustomobject][ordered]@{ sequence = 1; phase = 'Prepared'; atUtc = Get-NgcdUtcTimestamp })
    }
    $journalPath = Join-Path $Context.TransactionsRoot ($TransactionId + '.json')
    if (Test-Path -LiteralPath $journalPath) { Stop-Ngcd 'NGCOR-DEPLOYMENT-JOURNAL-EXISTS' }
    Write-NgcdProtectedRecord $journalPath $record $Context.MacKey
    [pscustomobject]@{ Path = $journalPath; Record = $record }
}

function Read-NgcdJournal {
    param([object]$Context, [string]$JournalPath)
    $path = Assert-NgcdPathWithin $JournalPath $Context.TransactionsRoot 'NGCOR-DEPLOYMENT-JOURNAL-PATH-INVALID'
    $record = Read-NgcdProtectedRecord $path $Context.MacKey
    Assert-NgcdExactProperties $record @(
        'schema','transactionId','sequence','phase','binding','paths','backupReceiptSha256','events'
    ) 'NGCOR-DEPLOYMENT-JOURNAL-INVALID'
    if ($record.schema -cne $script:DeploymentSchema -or $record.transactionId -cnotmatch '^ngtxn-[a-f0-9]{64}$' -or
        $record.phase -notin @('Prepared','Activated','Verified','Recovered','RolledBack','OutcomeUnknown') -or
        $record.backupReceiptSha256 -cnotmatch '^[a-f0-9]{64}$') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-JOURNAL-INVALID'
    }
    $record
}

function Set-NgcdJournalPhase {
    param([object]$Context, [string]$JournalPath, [string]$ExpectedPhase, [string]$NextPhase)
    $allowed = @{
        Prepared = @('Activated','Recovered','OutcomeUnknown')
        Activated = @('Verified','Recovered','OutcomeUnknown')
        Verified = @('RolledBack','OutcomeUnknown')
    }
    $record = Read-NgcdJournal $Context $JournalPath
    if ($record.phase -cne $ExpectedPhase -or -not $allowed.ContainsKey($ExpectedPhase) -or
        $NextPhase -notin $allowed[$ExpectedPhase]) { Stop-Ngcd 'NGCOR-DEPLOYMENT-JOURNAL-TRANSITION-INVALID' }
    $nextSequence = [int64]$record.sequence + 1
    $record.sequence = $nextSequence
    $record.phase = $NextPhase
    $record.events = [object[]]@($record.events) + [object[]]@(
        [pscustomobject][ordered]@{ sequence = $nextSequence; phase = $NextPhase; atUtc = Get-NgcdUtcTimestamp }
    )
    Write-NgcdProtectedRecord $JournalPath $record $Context.MacKey
    Read-NgcdJournal $Context $JournalPath
}

function Move-NgcdDirectoryToQuarantine {
    param([object]$Context, [string]$Source, [string]$TransactionId, [string]$Label)
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { return '' }
    $null = Assert-NgcdNoReparsePath $Source 'NGCOR-DEPLOYMENT-QUARANTINE-SOURCE-INVALID'
    if ($Label -cnotmatch '^[a-z]{3,16}$') { Stop-Ngcd 'NGCOR-DEPLOYMENT-QUARANTINE-LABEL-INVALID' }
    $target = Join-Path $Context.QuarantineRoot ($TransactionId + '-' + $Label)
    if (Test-Path -LiteralPath $target) { Stop-Ngcd 'NGCOR-DEPLOYMENT-QUARANTINE-TARGET-EXISTS' }
    [System.IO.Directory]::Move($Source, $target)
    $target
}

function Confirm-NgcdPointer {
    param([object]$Context, [object]$Binding, [string]$DestinationRoot, [string]$TransactionId)
    $bytes = Read-NgcdExclusiveBytes $Context.CurrentPointerPath 1048576 'NGCOR-DEPLOYMENT-POINTER-INVALID'
    try { $parsed = ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes -Bytes $bytes -MaximumBytes 1048576 }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-POINTER-INVALID' }
    $pointer = $parsed.Value
    Assert-NgcdExactProperties $pointer @(
        'schema','transactionId','releaseId','releaseManifestSha256','deploymentAuthorizationSha256',
        'repositoryCommit','repositoryTree','releaseRoot','activatedAtUtc'
    ) 'NGCOR-DEPLOYMENT-POINTER-INVALID'
    if ($pointer.schema -cne $script:PointerSchema -or $pointer.transactionId -cne $TransactionId -or
        $pointer.releaseId -cne $Binding.releaseId -or
        $pointer.releaseManifestSha256 -cne $Binding.releaseManifestSha256 -or
        $pointer.deploymentAuthorizationSha256 -cne $Binding.deploymentAuthorizationSha256 -or
        $pointer.repositoryCommit -cne $Binding.repositoryCommit -or $pointer.repositoryTree -cne $Binding.repositoryTree -or
        $pointer.releaseRoot -cne $DestinationRoot) { Stop-Ngcd 'NGCOR-DEPLOYMENT-POINTER-BINDING-MISMATCH' }
    $pointer
}

function Repair-NgcdInterruptedTransaction {
    param([object]$Context, [string]$JournalPath)
    $journal = Read-NgcdJournal $Context $JournalPath
    if ($journal.phase -in @('Verified','Recovered','RolledBack')) { return $journal }
    if ($journal.phase -eq 'OutcomeUnknown') { Stop-Ngcd 'NGCOR-DEPLOYMENT-OUTCOME-UNKNOWN' }
    try {
        Restore-NgcdBackup $Context ([string]$journal.paths.backupRoot) $journal.binding
        if ($journal.phase -eq 'Prepared') {
            $null = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.stagingRoot) `
                ([string]$journal.transactionId) 'prepared'
            $null = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.destinationRoot) `
                ([string]$journal.transactionId) 'ambiguous'
            if ($journal.paths.PSObject.Properties['backendStateRoot'] -and
                -not [string]::IsNullOrEmpty([string]$journal.paths.backendStateRoot)) {
                $null = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.backendStateRoot) `
                    ([string]$journal.transactionId) 'backend'
            }
        }
        elseif ($journal.phase -eq 'Activated') {
            $null = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.destinationRoot) `
                ([string]$journal.transactionId) 'activated'
            if ($journal.paths.PSObject.Properties['backendStateRoot'] -and
                -not [string]::IsNullOrEmpty([string]$journal.paths.backendStateRoot)) {
                $null = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.backendStateRoot) `
                    ([string]$journal.transactionId) 'backend'
            }
        }
        Set-NgcdJournalPhase $Context $JournalPath ([string]$journal.phase) 'Recovered'
    }
    catch {
        try { $null = Set-NgcdJournalPhase $Context $JournalPath ([string]$journal.phase) 'OutcomeUnknown' }
        catch { }
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RECOVERY-FAILED'
    }
}

function Invoke-NgcdFileInstallTransaction {
    param(
        [object]$Context, [string]$PackageRoot, [object]$Manifest, [object]$Authorization,
        [string]$AuthorizationSha256, [byte[]]$PolicyBytes, [byte[]]$SshConfigBytes,
        [ValidateSet('None','Prepared','Activated')][string]$StopAfterPhase = 'None',
        [AllowNull()][object]$RuntimeArtifacts = $null
    )
    Assert-NgcdContext $Context
    $binding = New-NgcdBinding $Manifest $Authorization $AuthorizationSha256
    $transactionId = New-NgcdTransactionId $binding ([string]$Authorization.authorizationId)
    $journalPath = Join-Path $Context.TransactionsRoot ($transactionId + '.json')
    $destinationRoot = Join-Path $Context.ReleaseParent ([string]$Manifest.releaseId)
    $stagingRoot = Join-Path $Context.ReleaseParent ('.staging-' + $transactionId)
    $lock = Enter-NgcdDeploymentLock $Context.LockName
    try {
        if (Test-Path -LiteralPath $journalPath) {
            $existing = Read-NgcdJournal $Context $journalPath
            if ($existing.phase -eq 'Verified') {
                $null = Test-NgcdPackageFiles $destinationRoot @($Manifest.files)
                if ($null -ne $RuntimeArtifacts) {
                    $null = Test-NgcdInstalledRuntimeArtifacts $destinationRoot $RuntimeArtifacts
                }
                $null = Confirm-NgcdPointer $Context $binding $destinationRoot $transactionId
                if (-not (Test-NgcdFixedHexEquals `
                        (Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $Context.PolicyPath)) `
                        (Get-NgcdSha256Bytes $PolicyBytes)) -or
                    -not (Test-NgcdFixedHexEquals `
                        (Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $Context.SshConfigPath)) `
                        (Get-NgcdSha256Bytes $SshConfigBytes))) {
                    Stop-Ngcd 'NGCOR-DEPLOYMENT-VERIFIED-REPLAY-CONFIGURATION-MISMATCH'
                }
                return [pscustomobject][ordered]@{
                    status = 'already-verified'; transactionId = $transactionId; phase = 'Verified'
                    releaseRoot = $destinationRoot; backupReceiptSha256 = $existing.backupReceiptSha256
                }
            }
            if ($existing.phase -in @('Prepared','Activated')) {
                $null = Repair-NgcdInterruptedTransaction $Context $journalPath
                Stop-Ngcd 'NGCOR-DEPLOYMENT-RECOVERED-RERUN-REQUIRED'
            }
            Stop-Ngcd 'NGCOR-DEPLOYMENT-AUTHORIZATION-ALREADY-CONSUMED'
        }
        if (Test-Path -LiteralPath $destinationRoot) { Stop-Ngcd 'NGCOR-DEPLOYMENT-RELEASE-ROOT-EXISTS' }
        $backup = New-NgcdBackup $Context $transactionId $binding
        Copy-NgcdPackageFiles $PackageRoot $stagingRoot @($Manifest.files)
        if ($null -ne $RuntimeArtifacts) { Write-NgcdRuntimeArtifactsToStaging $stagingRoot $RuntimeArtifacts }
        $installedFields = [ordered]@{
            schema = $script:InstalledReleaseSchema
            transactionId = $transactionId
            releaseId = [string]$Manifest.releaseId
            releaseManifestSha256 = [string]$binding.releaseManifestSha256
            deploymentAuthorizationSha256 = $AuthorizationSha256
            repositoryCommit = [string]$Manifest.repository.commit
            repositoryTree = [string]$Manifest.repository.tree
            releaseSignerCertificateSha256 = [string]$Authorization.identity.releaseSignerCertificateSha256
            serviceIdentitySid = [string]$Authorization.identity.serviceIdentitySid
            sshIdentitySid = [string]$Authorization.identity.sshIdentitySid
            serviceHostFileName = [string]$Context.ServiceHostFileName
            installedAtUtc = Get-NgcdUtcTimestamp
        }
        if ($null -ne $RuntimeArtifacts) {
            $installedFields.deploymentAuthorizationSignerCertificateSha256 =
                [string]$RuntimeArtifacts.deploymentAuthorizationSignerCertificateSha256
            $installedFields.backendPolicySha256 = [string]$RuntimeArtifacts.backendPolicySha256
            $installedFields.dataBundleSha256 = [string]$RuntimeArtifacts.dataBundleSha256
            $installedFields.dataBundleId = [string]$RuntimeArtifacts.dataBundleId
            $installedFields.backendDataRoot = Join-Path $destinationRoot 'backend-data'
            $installedFields.backendStateRoot = Join-Path (Join-Path $Context.StateRoot 'backend') `
                ([string]$Manifest.releaseId)
            $installedFields.backendStateKeyPath = Join-Path $installedFields.backendStateRoot 'state-key.dpapi'
        }
        $installedRecord = [pscustomobject]$installedFields
        Write-NgcdAtomicCanonicalJson (Join-Path $stagingRoot 'installed-release.json') $installedRecord
        Write-NgcdAtomicCanonicalJson (Join-Path $stagingRoot 'release-manifest.json') $Manifest
        Write-NgcdAtomicCanonicalJson (Join-Path $stagingRoot 'deployment-authorization.json') $Authorization
        if (-not (Test-NgcdFixedHexEquals `
                (Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes (Join-Path $stagingRoot 'release-manifest.json'))) `
                ([string]$binding.releaseManifestSha256)) -or
            -not (Test-NgcdFixedHexEquals `
                (Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes (Join-Path $stagingRoot 'deployment-authorization.json'))) `
                $AuthorizationSha256)) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-EVIDENCE-READBACK-FAILED'
        }
        $paths = [pscustomobject][ordered]@{
            stagingRoot = $stagingRoot
            destinationRoot = $destinationRoot
            backupRoot = $backup.BackupRoot
            currentPointerPath = [string]$Context.CurrentPointerPath
            policyPath = [string]$Context.PolicyPath
            sshConfigPath = [string]$Context.SshConfigPath
            backendStateRoot = if($null -eq $RuntimeArtifacts){''}else{[string]$installedFields.backendStateRoot}
        }
        $journal = New-NgcdJournal $Context $transactionId $binding $paths $backup.BackupReceiptSha256
        if ($null -ne $RuntimeArtifacts) {
            $backendState = Initialize-NgcdBackendState $Context $Authorization ([string]$Manifest.releaseId) `
                ([string]$RuntimeArtifacts.stateKeyId)
            if ($backendState.Root -cne $installedFields.backendStateRoot -or
                $backendState.KeyPath -cne $installedFields.backendStateKeyPath) {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKEND-STATE-BINDING-MISMATCH'
            }
        }
        if ($StopAfterPhase -eq 'Prepared') { Stop-Ngcd 'NGCOR-DEPLOYMENT-TEST-CRASH-PREPARED' }

        [System.IO.Directory]::Move($stagingRoot, $destinationRoot)
        if ($null -ne $RuntimeArtifacts) {
            $null=Test-NgcdInstalledRuntimeArtifacts $destinationRoot $RuntimeArtifacts
        }
        Write-NgcdAtomicBytes $Context.PolicyPath $PolicyBytes
        Write-NgcdAtomicBytes $Context.SshConfigPath $SshConfigBytes
        $pointer = [pscustomobject][ordered]@{
            schema = $script:PointerSchema
            transactionId = $transactionId
            releaseId = [string]$binding.releaseId
            releaseManifestSha256 = [string]$binding.releaseManifestSha256
            deploymentAuthorizationSha256 = [string]$binding.deploymentAuthorizationSha256
            repositoryCommit = [string]$binding.repositoryCommit
            repositoryTree = [string]$binding.repositoryTree
            releaseRoot = $destinationRoot
            activatedAtUtc = Get-NgcdUtcTimestamp
        }
        Write-NgcdAtomicCanonicalJson $Context.CurrentPointerPath $pointer
        if ($Context.Mode -eq 'Production') {
            $serviceHostPath = Join-Path $destinationRoot ([string]$Context.ServiceHostFileName)
            $null = Set-NgcdWindowsService $serviceHostPath $destinationRoot `
                ([string]$Authorization.identity.serviceIdentitySid)
            try {
                $sshAccount = (New-Object System.Security.Principal.SecurityIdentifier(
                    [string]$Authorization.identity.sshIdentitySid
                )).Translate([System.Security.Principal.NTAccount]).Value
            }
            catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-IDENTITY-UNRESOLVED' }
            $sshUser = ($sshAccount -split '\\')[-1]
            $null = Test-NgcdSshConfiguration $Context.SshConfigPath $sshUser
            Restart-Service -Name 'sshd' -Force -ErrorAction Stop
            $sshdService = Get-Service -Name 'sshd' -ErrorAction Stop
            if ($sshdService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-SSHD-READBACK-FAILED'
            }
        }
        $null = Set-NgcdJournalPhase $Context $journal.Path 'Prepared' 'Activated'
        if ($StopAfterPhase -eq 'Activated') { Stop-Ngcd 'NGCOR-DEPLOYMENT-TEST-CRASH-ACTIVATED' }

        $null = Test-NgcdPackageFiles $destinationRoot @($Manifest.files)
        if ($null -ne $RuntimeArtifacts) {
            $null=Test-NgcdInstalledRuntimeArtifacts $destinationRoot $RuntimeArtifacts
        }
        $null = Confirm-NgcdPointer $Context $binding $destinationRoot $transactionId
        if (-not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $Context.PolicyPath)) `
                (Get-NgcdSha256Bytes $PolicyBytes)) -or
            -not (Test-NgcdFixedHexEquals (Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $Context.SshConfigPath)) `
                (Get-NgcdSha256Bytes $SshConfigBytes))) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-CONFIGURATION-READBACK-FAILED'
        }
        $verified = Set-NgcdJournalPhase $Context $journal.Path 'Activated' 'Verified'
        [pscustomobject][ordered]@{
            status = 'verified'; transactionId = $transactionId; phase = [string]$verified.phase
            releaseRoot = $destinationRoot; backupReceiptPath = $backup.BackupReceiptPath
            backupReceiptSha256 = $backup.BackupReceiptSha256
            backupReceiptSignaturePath = $backup.BackupReceiptSignaturePath
        }
    }
    finally { Exit-NgcdDeploymentLock $lock }
}

function Invoke-NgcdFileRollbackTransaction {
    param(
        [object]$Context, [string]$TransactionId, [string]$ExpectedReleaseId,
        [string]$ExpectedManifestSha256, [string]$ExpectedBackupReceiptSha256
    )
    Assert-NgcdContext $Context
    $journalPath = Join-Path $Context.TransactionsRoot ($TransactionId + '.json')
    $lock = Enter-NgcdDeploymentLock $Context.LockName
    $mutationStarted = $false
    try {
        $journal = Read-NgcdJournal $Context $journalPath
        if ($journal.phase -cne 'Verified' -or $journal.binding.releaseId -cne $ExpectedReleaseId -or
            $journal.binding.releaseManifestSha256 -cne $ExpectedManifestSha256 -or
            $journal.backupReceiptSha256 -cne $ExpectedBackupReceiptSha256) {
            Stop-Ngcd 'NGCOR-ROLLBACK-BINDING-MISMATCH'
        }
        $receiptPath = Join-Path ([string]$journal.paths.backupRoot) 'backup-receipt.json'
        $actualReceiptHash = Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $receiptPath)
        if (-not (Test-NgcdFixedHexEquals $actualReceiptHash $ExpectedBackupReceiptSha256)) {
            Stop-Ngcd 'NGCOR-ROLLBACK-RECEIPT-HASH-MISMATCH'
        }
        $mutationStarted = $true
        Restore-NgcdBackup $Context ([string]$journal.paths.backupRoot) $journal.binding
        $quarantine = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.destinationRoot) `
            $TransactionId 'rollback'
        $rolledBack = Set-NgcdJournalPhase $Context $journalPath 'Verified' 'RolledBack'
        [pscustomobject][ordered]@{
            status = 'rolled-back'; transactionId = $TransactionId; phase = [string]$rolledBack.phase
            quarantinedReleaseRoot = $quarantine; durableStatePreserved = $true
        }
    }
    catch {
        if ($mutationStarted) {
            try {
                $current = Read-NgcdJournal $Context $journalPath
                if ($current.phase -eq 'Verified') {
                    $null = Set-NgcdJournalPhase $Context $journalPath 'Verified' 'OutcomeUnknown'
                }
            }
            catch { }
        }
        throw
    }
    finally { Exit-NgcdDeploymentLock $lock }
}

function Test-NgcdCertificatePin {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$ExpectedSha256)
    if ($null -eq $Certificate -or $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ExpectedSha256 -ceq ('0' * 64)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SIGNER-PIN-INVALID'
    }
    $actual = Get-NgcdSha256Bytes $Certificate.RawData
    if (-not (Test-NgcdFixedHexEquals $actual $ExpectedSha256)) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SIGNER-PIN-MISMATCH' }
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SIGNER-CERTIFICATE-EXPIRED'
    }
    $hasLeafConstraint = $false
    $hasCodeSigningEku = $false
    $hasDigitalSignatureUsage = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $hasLeafConstraint = $true
            if ($extension.CertificateAuthority) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SIGNER-CA-FORBIDDEN' }
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
                Stop-Ngcd 'NGCOR-DEPLOYMENT-SIGNER-KEY-USAGE-INVALID'
            }
        }
    }
    if (-not $hasLeafConstraint -or -not $hasCodeSigningEku -or -not $hasDigitalSignatureUsage) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SIGNER-KEY-USAGE-INVALID'
    }
    $true
}

function Test-NgcdDetachedCms {
    param([byte[]]$ContentBytes, [string]$SignaturePath, [string]$ExpectedSignerSha256)
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    $signatureBytes = Read-NgcdExclusiveBytes $SignaturePath 1048576 'NGCOR-DEPLOYMENT-CMS-SIGNATURE-INVALID'
    try {
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($content, $true)
        $cms.Decode($signatureBytes)
        if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-CMS-SIGNER-COUNT-INVALID'
        }
        if ($cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-CMS-DIGEST-INVALID'
        }
        $cms.CheckSignature($true)
        $certificate = $cms.SignerInfos[0].Certificate
        $null = Test-NgcdCertificatePin $certificate $ExpectedSignerSha256
        [pscustomobject][ordered]@{ valid = $true; signerSha256 = $ExpectedSignerSha256 }
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        Stop-Ngcd 'NGCOR-DEPLOYMENT-CMS-SIGNATURE-INVALID'
    }
}

function New-NgcdDetachedCmsSignature {
    param([string]$ContentPath, [string]$SignaturePath, [string]$ExpectedSignerSha256)
    $contentBytes = Read-NgcdExclusiveBytes $ContentPath 1048576 'NGCOR-DEPLOYMENT-RECEIPT-INVALID'
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches = @($store.Certificates | Where-Object {
            $_.HasPrivateKey -and (Get-NgcdSha256Bytes $_.RawData) -ceq $ExpectedSignerSha256
        })
    }
    finally { $store.Close(); $store.Dispose() }
    if ($matches.Count -ne 1) { Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-SIGNING-KEY-UNAVAILABLE' }
    $certificate = $matches[0]
    $null = Test-NgcdCertificatePin $certificate $ExpectedSignerSha256
    try {
        try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
        catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,$contentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($content, $true)
        $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner($certificate)
        $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
        $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
        $cms.ComputeSignature($signer, $true)
        Write-NgcdAtomicBytes $SignaturePath $cms.Encode()
        $null = Test-NgcdDetachedCms $contentBytes $SignaturePath $ExpectedSignerSha256
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-SIGNING-FAILED'
    }
}

function Get-NgcdServiceSid {
    param([string]$ServiceName = $script:ServiceName)
    if ($ServiceName -cnotmatch '^[A-Za-z][A-Za-z0-9]{2,63}$') { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-NAME-INVALID' }
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($ServiceName.ToUpperInvariant())
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha1.ComputeHash($bytes) }
    finally { $sha1.Dispose() }
    $parts = for ($index = 0; $index -lt 5; $index++) { [BitConverter]::ToUInt32($hash, $index * 4) }
    'S-1-5-80-' + ($parts -join '-')
}

function Invoke-NgcdSc {
    param([string[]]$Arguments)
    $sc = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'sc.exe'
    if (-not (Test-Path -LiteralPath $sc -PathType Leaf)) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SC-UNAVAILABLE' }
    $output = @(& $sc @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
    (@($output | ForEach-Object { [string]$_ }) -join "`n")
}

function Set-NgcdWindowsService {
    param([string]$ServiceHostPath, [string]$ReleaseRoot, [string]$ExpectedServiceSid)
    if ((Get-NgcdServiceSid) -cne $ExpectedServiceSid) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-SID-MISMATCH' }
    $hostPath = Assert-NgcdPathWithin $ServiceHostPath $ReleaseRoot 'NGCOR-DEPLOYMENT-SERVICE-HOST-PATH-INVALID'
    $serviceScript = Assert-NgcdPathWithin (Join-Path $ReleaseRoot 'Start-NorthGateCreateOnlyPipeService.ps1') `
        $ReleaseRoot 'NGCOR-DEPLOYMENT-SERVICE-SCRIPT-PATH-INVALID'
    $binaryPath = '"' + $hostPath + '" --script "' + $serviceScript + '"'
    $existing = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        try {
            $created = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                Name = $script:ServiceName; DisplayName = $script:ServiceName; PathName = $binaryPath
                StartMode = 'Automatic'; StartName = $script:ServiceAccount
            } -ErrorAction Stop
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        if ([int]$created.ReturnValue -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
    }
    else {
        if ($existing.State -ne 'Stopped') { $null = Invoke-NgcdSc @('stop',$script:ServiceName) }
        try {
            $changed = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{
                PathName = $binaryPath; StartMode = 'Automatic'; StartName = $script:ServiceAccount
            } -ErrorAction Stop
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        if ([int]$changed.ReturnValue -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
    }
    $null = Invoke-NgcdSc @('description',$script:ServiceName,'NorthGate create-only VM Factory control service')
    $null = Invoke-NgcdSc @('failure',$script:ServiceName,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')
    $null = Invoke-NgcdSc @('failureflag',$script:ServiceName,'1')
    $null = Invoke-NgcdSc @('sidtype',$script:ServiceName,'restricted')
    $null = Invoke-NgcdSc @('start',$script:ServiceName)
    Start-Sleep -Milliseconds 500
    $readback = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") -ErrorAction Stop
    if ($readback.PathName -cne $binaryPath -or $readback.StartMode -cne 'Auto' -or
        $readback.StartName -cne $script:ServiceAccount -or $readback.State -cne 'Running') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-READBACK-FAILED'
    }
    $true
}

function New-NgcdInstalledPolicy {
    param(
        [object]$Authorization, [string]$ReleaseId, [string]$ManifestSha256,
        [string]$BackendPolicySha256='', [string]$DataBundleSha256=''
    )
    [pscustomobject][ordered]@{
        schema = $script:PolicySchema
        releaseId = $ReleaseId
        releaseManifestSha256 = $ManifestSha256
        pipeName = $script:PipeName
        sshIdentitySid = [string]$Authorization.identity.sshIdentitySid
        serviceIdentitySid = [string]$Authorization.identity.serviceIdentitySid
        serviceName = $script:ServiceName
        serviceHostSignerCertificateSha256 = [string]$Authorization.identity.releaseSignerCertificateSha256
        backendPolicySha256 = $BackendPolicySha256
        dataBundleSha256 = $DataBundleSha256
        applyEnabled = -not [string]::IsNullOrEmpty($BackendPolicySha256)
        executableActions = if([string]::IsNullOrEmpty($BackendPolicySha256)){[object[]]@()}else{[object[]]@('Create')}
        canaryStage = if([string]::IsNullOrEmpty($BackendPolicySha256)){'disabled'}else{'signed-policy'}
    }
}

function New-NgcdManagedSshConfiguration {
    param([string]$ExistingConfiguration, [string]$SshUserName, [string]$ReleaseRoot)
    if ($SshUserName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or
        $ExistingConfiguration.Contains($script:ManagedSshBegin) -or
        $ExistingConfiguration.Contains($script:ManagedSshEnd)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-CONFIGURATION-INVALID'
    }
    $powerShell = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) `
        'WindowsPowerShell\v1.0\powershell.exe'
    $handler = Join-Path $ReleaseRoot 'Invoke-NorthGateCreateOnlyForcedCommand.ps1'
    $authorizedKeys = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) `
        'ssh\northgate-create-only-authorized_keys'
    $block = @(
        $script:ManagedSshBegin,
        ('Match User ' + $SshUserName + ',.\' + $SshUserName + ' Address ' + $script:FixedSshSourceCidr),
        '    AuthenticationMethods publickey',
        '    PubkeyAuthentication yes',
        '    PasswordAuthentication no',
        '    KbdInteractiveAuthentication no',
        ('    AuthorizedKeysFile "' + $authorizedKeys + '"'),
        ('    ForceCommand "' + $powerShell + '" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "' + $handler + '"'),
        '    DisableForwarding yes',
        '    AllowTcpForwarding no',
        '    AllowAgentForwarding no',
        '    X11Forwarding no',
        '    PermitTunnel no',
        '    PermitTTY no',
        '    PermitUserRC no',
        '    PermitListen none',
        '    PermitOpen none',
        '    GatewayPorts no',
        '    MaxSessions 1',
        $script:ManagedSshEnd
    ) -join "`r`n"
    $ExistingConfiguration.TrimEnd("`r","`n") + "`r`n`r`n" + $block + "`r`n"
}

function Test-NgcdSshConfiguration {
    param([string]$ConfigurationPath, [string]$SshUserName)
    $sshd = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'ssh\sshd.exe'
    if (-not (Test-Path -LiteralPath $sshd -PathType Leaf)) {
        $sshd = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'OpenSSH\sshd.exe'
    }
    if (-not (Test-Path -LiteralPath $sshd -PathType Leaf)) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SSHD-UNAVAILABLE' }
    $null = @(& $sshd -t -f $ConfigurationPath 2>&1)
    if ($LASTEXITCODE -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-SYNTAX-INVALID' }
    $effective = @(& $sshd -T -f $ConfigurationPath -C ("user=.\$SshUserName,host=$env:COMPUTERNAME,addr=10.10.100.20") 2>&1)
    if ($LASTEXITCODE -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-EFFECTIVE-CONFIG-INVALID' }
    $text = (@($effective | ForEach-Object { [string]$_ }) -join "`n").ToLowerInvariant()
    foreach ($required in @(
        'authenticationmethods publickey','passwordauthentication no','kbdinteractiveauthentication no',
        'pubkeyauthentication yes','disableforwarding yes','allowtcpforwarding no','allowagentforwarding no',
        'x11forwarding no','permittty no','permittunnel no','permituserenvironment no','permituserrc no',
        'permitlisten none','permitopen none','maxsessions 1'
    )) {
        if ($text -notmatch ('(?m)^' + [regex]::Escape($required) + '$')) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-EFFECTIVE-CONFIG-INVALID'
        }
    }
    $true
}

function Invoke-NorthGateCreateOnlyInstallTransaction {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$PackageRoot,
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][object]$Authorization,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$AuthorizationSha256,
        [Parameter(Mandatory)][byte[]]$PolicyBytes,
        [Parameter(Mandatory)][byte[]]$SshConfigBytes,
        [Parameter(Mandatory)][object]$RuntimeArtifacts
    )
    Assert-NgcdContext $Context
    if ($Context.Mode -cne 'Production') { Stop-Ngcd 'NGCOR-DEPLOYMENT-PRODUCTION-CONTEXT-REQUIRED' }
    if (-not $PSCmdlet.ShouldProcess([string]$Authorization.host.hostId, 'Install verified create-only release')) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-CONFIRMATION-REQUIRED'
    }
    Invoke-NgcdFileInstallTransaction $Context $PackageRoot $Manifest $Authorization $AuthorizationSha256 `
        $PolicyBytes $SshConfigBytes 'None' $RuntimeArtifacts
}

function Invoke-NorthGateCreateOnlyRollbackTransaction {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][ValidatePattern('^ngtxn-[a-f0-9]{64}$')][string]$TransactionId,
        [Parameter(Mandatory)][ValidatePattern('^ngcor-[a-z0-9][a-z0-9.-]{7,63}$')][string]$ExpectedReleaseId,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha256,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedBackupReceiptSha256
    )
    Assert-NgcdContext $Context
    if ($Context.Mode -cne 'Production') { Stop-Ngcd 'NGCOR-DEPLOYMENT-PRODUCTION-CONTEXT-REQUIRED' }
    if (-not $PSCmdlet.ShouldProcess($TransactionId, 'Rollback create-only release and quarantine current code')) {
        Stop-Ngcd 'NGCOR-ROLLBACK-CONFIRMATION-REQUIRED'
    }
    Invoke-NgcdFileRollbackTransaction $Context $TransactionId $ExpectedReleaseId `
        $ExpectedManifestSha256 $ExpectedBackupReceiptSha256
}

function Test-NorthGateCreateOnlyInstalledRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][object]$Authorization,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$AuthorizationSha256
    )
    Assert-NgcdContext $Context
    $binding = New-NgcdBinding $Manifest $Authorization $AuthorizationSha256
    $transactionId = New-NgcdTransactionId $binding ([string]$Authorization.authorizationId)
    $journal = Read-NgcdJournal $Context (Join-Path $Context.TransactionsRoot ($transactionId + '.json'))
    if ($journal.phase -cne 'Verified') { Stop-Ngcd 'NGCOR-DEPLOYMENT-NOT-VERIFIED' }
    $destinationRoot = Join-Path $Context.ReleaseParent ([string]$Manifest.releaseId)
    $null = Test-NgcdPackageFiles $destinationRoot @($Manifest.files)
    $null = Confirm-NgcdPointer $Context $binding $destinationRoot $transactionId
    [pscustomobject][ordered]@{
        status = 'verified'; transactionId = $transactionId; releaseId = [string]$Manifest.releaseId
        releaseRoot = $destinationRoot; applyEnabled = $false
    }
}

Export-ModuleMember -Function @(
    'Invoke-NorthGateCreateOnlyInstallTransaction',
    'Invoke-NorthGateCreateOnlyRollbackTransaction',
    'Test-NorthGateCreateOnlyInstalledRelease'
)
