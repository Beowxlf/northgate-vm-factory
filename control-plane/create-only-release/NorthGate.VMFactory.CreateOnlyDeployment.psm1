Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -ErrorAction Stop

$script:DeploymentSchema = 'northgate/create-only-deployment-transaction/v1'
$script:ProtectedRecordSchema = 'northgate/create-only-protected-record/v1'
$script:BackupSchema = 'northgate/create-only-deployment-backup/v2'
$script:LegacyBackupSchema = 'northgate/create-only-deployment-backup/v1'
$script:BackupReceiptSchema = 'northgate/create-only-backup-receipt/v2'
$script:PointerSchema = 'northgate/create-only-current-release/v1'
$script:InstalledReleaseSchema = 'northgate/create-only-installed-release/v1'
$script:PolicySchema = 'northgate/create-only-installed-policy/v1'
$script:InitialActivationSchema = 'northgate/create-only-initial-activation/v1'
$script:InitialActivationRecordSchema = 'northgate/create-only-initial-activation-record/v1'
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
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-DPAPI-UNAVAILABLE' }
    if ($null -eq ('System.Security.Cryptography.ProtectedData' -as [type])) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-DPAPI-UNAVAILABLE'
    }
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

function Get-NgcdServiceSecurityDescriptor {
    $sddl = ([string](Invoke-NgcdSc @('sdshow',$script:ServiceName))).Trim()
    if ($sddl -cnotmatch '^D:.{1,4096}$' -or $sddl -match '[\r\n]') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-ACL-READBACK-FAILED'
    }
    try { $null = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl) }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-ACL-READBACK-FAILED' }
    $sddl
}

function Set-NgcdServiceQueryIdentity {
    param([string]$IdentitySid)
    if ($IdentitySid -cnotmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-QUERY-SID-INVALID'
    }
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($IdentitySid)
        $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor(
            (Get-NgcdServiceSecurityDescriptor)
        )
        for ($index = $descriptor.DiscretionaryAcl.Count - 1; $index -ge 0; $index--) {
            $existingAce = $descriptor.DiscretionaryAcl[$index]
            if ($null -ne $existingAce.SecurityIdentifier -and
                $existingAce.SecurityIdentifier.Value -ceq $IdentitySid) {
                $descriptor.DiscretionaryAcl.RemoveAce($index)
            }
        }
        $queryAce = New-Object System.Security.AccessControl.CommonAce(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            0x0004, $sid, $false, $null
        )
        $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count, $queryAce)
        $wanted = $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        $null = Invoke-NgcdSc @('sdset',$script:ServiceName,$wanted)
        $readback = New-Object System.Security.AccessControl.RawSecurityDescriptor(
            (Get-NgcdServiceSecurityDescriptor)
        )
        $matches = @($readback.DiscretionaryAcl | Where-Object {
            $null -ne $_.SecurityIdentifier -and $_.SecurityIdentifier.Value -ceq $IdentitySid -and
            $_.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
            $_.AccessMask -eq 0x0004
        })
        if ($matches.Count -ne 1) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-ACL-READBACK-FAILED' }
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-ACL-CONFIGURATION-FAILED'
    }
    $true
}

function Get-NgcdServiceConfiguration {
    param([object]$Context)
    if ($Context.Mode -ne 'Production') {
        return [pscustomobject][ordered]@{
            existed = $false; name = $script:ServiceName; pathName = ''; startMode = ''
            startName = ''; state = ''; description = ''; securityDescriptorSddl = ''
        }
    }
    $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") `
        -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [pscustomobject][ordered]@{
            existed = $false; name = $script:ServiceName; pathName = ''; startMode = ''
            startName = ''; state = ''; description = ''; securityDescriptorSddl = ''
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
        securityDescriptorSddl = Get-NgcdServiceSecurityDescriptor
    }
}

function Restore-NgcdServiceConfiguration {
    param([object]$Context, [object]$Configuration)
    Assert-NgcdExactProperties $Configuration @(
        'existed','name','pathName','startMode','startName','state','description','securityDescriptorSddl'
    ) 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID'
    if ($Configuration.name -cne $script:ServiceName) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID' }
    if ($Context.Mode -ne 'Production') { return }
    $current = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") `
        -ErrorAction SilentlyContinue
    if ($Configuration.existed -eq $false) {
        if ($null -ne $current) {
            if ($current.State -ne 'Stopped') {
                $null = Invoke-NgcdSc @('stop',$script:ServiceName)
                try {
                    (Get-Service -Name $script:ServiceName -ErrorAction Stop).WaitForStatus(
                        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                        [TimeSpan]::FromSeconds(15)
                    )
                }
                catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
            }
            $null = Invoke-NgcdSc @('delete',$script:ServiceName)
        }
        return
    }
    if ($Configuration.existed -ne $true -or [string]::IsNullOrWhiteSpace([string]$Configuration.pathName) -or
        [string]::IsNullOrWhiteSpace([string]$Configuration.startName)) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID'
    }
    $startMode = switch ([string]$Configuration.startMode) {
        'Auto' { 'Automatic' }
        'Manual' { 'Manual' }
        'Disabled' { 'Disabled' }
        default { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID' }
    }
    if ([string]$Configuration.startName -cne $script:ServiceAccount) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID'
    }
    if ($null -eq $current) {
        try {
            $created = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                Name = $script:ServiceName
                DisplayName = $script:ServiceName
                PathName = [string]$Configuration.pathName
                StartMode = $startMode
                StartName = [string]$Configuration.startName
            } -ErrorAction Stop
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        if ([int]$created.ReturnValue -ne 0) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED'
        }
    }
    else {
        if ($current.State -ne 'Stopped') {
            $null = Invoke-NgcdSc @('stop',$script:ServiceName)
            try {
                (Get-Service -Name $script:ServiceName -ErrorAction Stop).WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                    [TimeSpan]::FromSeconds(15)
                )
            }
            catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        }
        try {
            $changed = Invoke-CimMethod -InputObject $current -MethodName Change -Arguments @{
                PathName = [string]$Configuration.pathName
                StartMode = $startMode
                StartName = [string]$Configuration.startName
            } -ErrorAction Stop
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        if ([int]$changed.ReturnValue -ne 0) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED'
        }
    }
    if (-not [string]::IsNullOrEmpty([string]$Configuration.description)) {
        $null = Invoke-NgcdSc @('description',$script:ServiceName,([string]$Configuration.description))
    }
    if ([string]::IsNullOrWhiteSpace([string]$Configuration.securityDescriptorSddl) -or
        [string]$Configuration.securityDescriptorSddl -cnotmatch '^D:.{1,4096}$') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-BACKUP-INVALID'
    }
    $null = Invoke-NgcdSc @('sdset',$script:ServiceName,([string]$Configuration.securityDescriptorSddl))
    if ($Configuration.state -ceq 'Running') {
        $null = Invoke-NgcdSc @('start',$script:ServiceName)
        try {
            (Get-Service -Name $script:ServiceName -ErrorAction Stop).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(15)
            )
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
    }
    $readback = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") `
        -ErrorAction Stop
    if ($readback.PathName -cne [string]$Configuration.pathName -or
        $readback.StartMode -cne [string]$Configuration.startMode -or
        $readback.StartName -cne [string]$Configuration.startName -or
        $readback.State -cne [string]$Configuration.state -or
        (Get-NgcdServiceSecurityDescriptor) -cne [string]$Configuration.securityDescriptorSddl) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-READBACK-FAILED'
    }
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
    $receiptSignerKey = if ($Context.Mode -eq 'Production') {
        Get-NgcdReceiptSignerKeyDescriptor `
            ([string]$Binding.receiptSignerCertificateSha256) ([string]$Binding.serviceIdentitySid)
    }
    else { [pscustomobject]@{ KeyPath = ''; KeyProvider = 'InertTest'; Sddl = '' } }
    $backup = [pscustomobject][ordered]@{
        schema = $script:BackupSchema
        transactionId = $TransactionId
        createdAtUtc = Get-NgcdUtcTimestamp
        binding = $Binding
        targets = [object[]]$records
        serviceConfiguration = Get-NgcdServiceConfiguration $Context
        receiptSignerKey = [pscustomobject][ordered]@{
            managed = ($Context.Mode -eq 'Production')
            signerCertificateSha256 = [string]$Binding.receiptSignerCertificateSha256
            serviceIdentitySid = [string]$Binding.serviceIdentitySid
            keyPath = [string]$receiptSignerKey.KeyPath
            keyProvider = [string]$receiptSignerKey.KeyProvider
            sddl = [string]$receiptSignerKey.Sddl
        }
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
        permittedTargets = [object[]]@(
            'currentPointer','installedPolicy','sshdConfig','serviceConfiguration','releaseDirectory',
            'receiptSignerPrivateKeyAcl'
        )
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
    if ($backup.schema -ceq $script:BackupSchema) {
        Assert-NgcdExactProperties $backup @(
            'schema','transactionId','createdAtUtc','binding','targets','serviceConfiguration','receiptSignerKey'
        ) 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
    }
    elseif ($backup.schema -ceq $script:LegacyBackupSchema) {
        Assert-NgcdExactProperties $backup @(
            'schema','transactionId','createdAtUtc','binding','targets','serviceConfiguration'
        ) 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
    }
    else { Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID' }
    if (
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
    if ($backup.schema -ceq $script:BackupSchema) {
        Assert-NgcdExactProperties $backup.receiptSignerKey @(
            'managed','signerCertificateSha256','serviceIdentitySid','keyPath','keyProvider','sddl'
        ) 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
        if ($backup.receiptSignerKey.signerCertificateSha256 -cne
                $ExpectedBinding.receiptSignerCertificateSha256 -or
            $backup.receiptSignerKey.serviceIdentitySid -cne $ExpectedBinding.serviceIdentitySid -or
            $backup.receiptSignerKey.managed -isnot [bool]) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
        }
        if ($backup.receiptSignerKey.managed) {
            if ($Context.Mode -ne 'Production' -or $backup.receiptSignerKey.sddl -cnotmatch '^O:.{1,8192}$') {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
            }
            $currentKey = Get-NgcdReceiptSignerKeyDescriptor `
                ([string]$backup.receiptSignerKey.signerCertificateSha256) `
                ([string]$backup.receiptSignerKey.serviceIdentitySid)
            if ($currentKey.KeyPath -cne [string]$backup.receiptSignerKey.keyPath -or
                $currentKey.KeyProvider -cne [string]$backup.receiptSignerKey.keyProvider) {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-PATH-INVALID'
            }
            Set-NgcdFileSddl $currentKey.KeyPath ([string]$backup.receiptSignerKey.sddl)
        }
        elseif ($Context.Mode -eq 'Production' -or $backup.receiptSignerKey.keyPath -cne '' -or
            $backup.receiptSignerKey.keyProvider -cne 'InertTest' -or $backup.receiptSignerKey.sddl -cne '') {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-BACKUP-INVALID'
        }
    }
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
        serviceIdentitySid = [string]$Authorization.identity.serviceIdentitySid
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
        $record.phase -notin @(
            'Prepared','Activated','Verified','RollbackPending','Recovered','RolledBack','OutcomeUnknown'
        ) -or
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
        Verified = @('RollbackPending','OutcomeUnknown')
        RollbackPending = @('RolledBack','OutcomeUnknown')
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
                if ($Context.Mode -eq 'Production') {
                    $null = Test-NgcdReceiptSignerKeyAccess `
                        ([string]$binding.receiptSignerCertificateSha256) ([string]$binding.serviceIdentitySid)
                }
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
            if ($existing.phase -ceq 'RollbackPending') {
                Stop-Ngcd 'NGCOR-DEPLOYMENT-ROLLBACK-RETRY-REQUIRED'
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
            serviceName = $script:ServiceName
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
        if ($Context.Mode -eq 'Production') {
            $null = Set-NgcdReceiptSignerKeyAccess `
                ([string]$binding.receiptSignerCertificateSha256) ([string]$binding.serviceIdentitySid)
        }
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
                ([string]$Authorization.identity.serviceIdentitySid) `
                ([string]$Authorization.identity.sshIdentitySid) `
                ([bool]$Authorization.initialPolicy.applyEnabled)
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
    try {
        $journal = Read-NgcdJournal $Context $journalPath
        if ($journal.phase -notin @('Verified','RollbackPending') -or
            $journal.binding.releaseId -cne $ExpectedReleaseId -or
            $journal.binding.releaseManifestSha256 -cne $ExpectedManifestSha256 -or
            $journal.backupReceiptSha256 -cne $ExpectedBackupReceiptSha256) {
            Stop-Ngcd 'NGCOR-ROLLBACK-BINDING-MISMATCH'
        }
        $receiptPath = Join-Path ([string]$journal.paths.backupRoot) 'backup-receipt.json'
        $actualReceiptHash = Get-NgcdSha256Bytes (Read-NgcdExclusiveBytes $receiptPath)
        if (-not (Test-NgcdFixedHexEquals $actualReceiptHash $ExpectedBackupReceiptSha256)) {
            Stop-Ngcd 'NGCOR-ROLLBACK-RECEIPT-HASH-MISMATCH'
        }
        if ($journal.phase -ceq 'Verified') {
            $journal = Set-NgcdJournalPhase $Context $journalPath 'Verified' 'RollbackPending'
        }
        Restore-NgcdBackup $Context ([string]$journal.paths.backupRoot) $journal.binding
        $quarantine = Move-NgcdDirectoryToQuarantine $Context ([string]$journal.paths.destinationRoot) `
            $TransactionId 'rollback'
        $backendQuarantine = ''
        if ($journal.paths.PSObject.Properties['backendStateRoot'] -and
            -not [string]::IsNullOrEmpty([string]$journal.paths.backendStateRoot)) {
            $backendQuarantine = Move-NgcdDirectoryToQuarantine $Context `
                ([string]$journal.paths.backendStateRoot) $TransactionId 'backend'
        }
        $rolledBack = Set-NgcdJournalPhase $Context $journalPath 'RollbackPending' 'RolledBack'
        [pscustomobject][ordered]@{
            status = 'rolled-back'; transactionId = $TransactionId; phase = [string]$rolledBack.phase
            quarantinedReleaseRoot = $quarantine
            quarantinedBackendStateRoot = $backendQuarantine
            durableStatePreserved = $true
        }
    }
    catch { throw }
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

function Test-NgcdAclMutationRights {
    param([Security.AccessControl.FileSystemRights]$Rights)
    $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    ($Rights -band $writeMask) -ne 0
}

function Get-NgcdReceiptSignerKeyDescriptor {
    param(
        [Parameter(Mandatory)][string]$ExpectedSignerSha256,
        [Parameter(Mandatory)][string]$ExpectedServiceSid
    )
    if ((Get-NgcdServiceSid) -cne $ExpectedServiceSid) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-SERVICE-SID-MISMATCH'
    }
    $certificates = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.HasPrivateKey -and
            (Get-NgcdSha256Bytes $_.RawData) -ceq $ExpectedSignerSha256
        })
    if ($certificates.Count -ne 1) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-SIGNING-KEY-UNAVAILABLE'
    }
    $certificate = $certificates[0]
    $null = Test-NgcdCertificatePin $certificate $ExpectedSignerSha256
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        if ($rsa -is [Security.Cryptography.RSACng]) {
            $keyRoot = Join-Path $programData 'Microsoft\Crypto\Keys'
            $keyPath = Join-Path $keyRoot ([string]$rsa.Key.UniqueName)
        }
        elseif ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            $keyRoot = Join-Path $programData 'Microsoft\Crypto\RSA\MachineKeys'
            $keyPath = Join-Path $keyRoot ([string]$rsa.CspKeyContainerInfo.UniqueKeyContainerName)
        }
        else { Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-PROVIDER-INVALID' }
        $keyPath = Assert-NgcdPathWithin $keyPath $keyRoot 'NGCOR-DEPLOYMENT-RECEIPT-KEY-PATH-INVALID'
        $null = Assert-NgcdNoReparsePath $keyPath 'NGCOR-DEPLOYMENT-RECEIPT-KEY-PATH-INVALID'
        if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-PATH-INVALID'
        }
        try { $acl = Get-Acl -LiteralPath $keyPath -ErrorAction Stop }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACL-UNREADABLE' }
        [pscustomobject][ordered]@{
            KeyPath = $keyPath
            KeyProvider = $rsa.GetType().Name
            Sddl = [string]$acl.Sddl
        }
    }
    finally { if ($null -ne $rsa) { $rsa.Dispose() } }
}

function Test-NgcdReceiptSignerKeyAccess {
    param(
        [Parameter(Mandatory)][string]$ExpectedSignerSha256,
        [Parameter(Mandatory)][string]$ExpectedServiceSid
    )
    $descriptor = Get-NgcdReceiptSignerKeyDescriptor $ExpectedSignerSha256 $ExpectedServiceSid
    try { $acl = Get-Acl -LiteralPath $descriptor.KeyPath -ErrorAction Stop }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACL-UNREADABLE' }
    $effective = @($acl.Access | Where-Object {
        try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ceq $ExpectedServiceSid }
        catch { $false }
    })
    $allowsRead = @($effective | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -ne 0 -and
        -not (Test-NgcdAclMutationRights $_.FileSystemRights)
    }).Count -ge 1
    $denies = @($effective | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny
    }).Count
    if (-not $allowsRead -or $denies -ne 0) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACL-READBACK-FAILED'
    }
    return $descriptor
}

function Set-NgcdReceiptSignerKeyAccess {
    param(
        [Parameter(Mandatory)][string]$ExpectedSignerSha256,
        [Parameter(Mandatory)][string]$ExpectedServiceSid
    )
    $descriptor = Get-NgcdReceiptSignerKeyDescriptor $ExpectedSignerSha256 $ExpectedServiceSid
    try { $acl = Get-Acl -LiteralPath $descriptor.KeyPath -ErrorAction Stop }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACL-UNREADABLE' }
    $sid = New-Object Security.Principal.SecurityIdentifier($ExpectedServiceSid)
    foreach ($rule in @($acl.Access)) {
        try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if ($ruleSid -ceq $ExpectedServiceSid -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACCESS-DENIED'
        }
        if ($ruleSid -ceq $ExpectedServiceSid -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            (Test-NgcdAclMutationRights $rule.FileSystemRights)) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACCESS-EXCESSIVE'
        }
    }
    $readRule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid,[Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($readRule)
    try { Set-Acl -LiteralPath $descriptor.KeyPath -AclObject $acl -ErrorAction Stop }
    catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-RECEIPT-KEY-ACL-WRITE-FAILED' }
    $verified = Test-NgcdReceiptSignerKeyAccess $ExpectedSignerSha256 $ExpectedServiceSid
    [pscustomobject][ordered]@{
        status = 'verified'; signerCertificateSha256 = $ExpectedSignerSha256
        serviceIdentitySid = $ExpectedServiceSid; keyProvider = [string]$verified.KeyProvider
    }
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
    param(
        [string]$ServiceHostPath, [string]$ReleaseRoot, [string]$ExpectedServiceSid,
        [string]$ExpectedSshSid, [bool]$InstallEnabled
    )
    if ((Get-NgcdServiceSid) -cne $ExpectedServiceSid) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-SID-MISMATCH' }
    $hostPath = Assert-NgcdPathWithin $ServiceHostPath $ReleaseRoot 'NGCOR-DEPLOYMENT-SERVICE-HOST-PATH-INVALID'
    $serviceScript = Assert-NgcdPathWithin (Join-Path $ReleaseRoot 'Start-NorthGateCreateOnlyPipeService.ps1') `
        $ReleaseRoot 'NGCOR-DEPLOYMENT-SERVICE-SCRIPT-PATH-INVALID'
    $binaryPath = '"' + $hostPath + '" --script "' + $serviceScript + '"'
    $startMode = if ($InstallEnabled) { 'Automatic' } else { 'Disabled' }
    $expectedStartMode = if ($InstallEnabled) { 'Auto' } else { 'Disabled' }
    $existing = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        try {
            $created = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
                Name = $script:ServiceName; DisplayName = $script:ServiceName; PathName = $binaryPath
                StartMode = $startMode; StartName = $script:ServiceAccount
            } -ErrorAction Stop
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        if ([int]$created.ReturnValue -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
    }
    else {
        if ($existing.State -ne 'Stopped') { $null = Invoke-NgcdSc @('stop',$script:ServiceName) }
        try {
            $changed = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{
                PathName = $binaryPath; StartMode = $startMode; StartName = $script:ServiceAccount
            } -ErrorAction Stop
        }
        catch { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
        if ([int]$changed.ReturnValue -ne 0) { Stop-Ngcd 'NGCOR-DEPLOYMENT-SERVICE-CONFIGURATION-FAILED' }
    }
    $null = Invoke-NgcdSc @('description',$script:ServiceName,'NorthGate create-only VM Factory control service')
    $null = Invoke-NgcdSc @('failure',$script:ServiceName,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')
    $null = Invoke-NgcdSc @('failureflag',$script:ServiceName,'1')
    # Hyper-V's management provider performs additional local authorization checks.
    # Keep the dedicated virtual service identity, but do not apply a restricted
    # service token that prevents its explicitly granted Hyper-V operator rights.
    $null = Invoke-NgcdSc @('sidtype',$script:ServiceName,'unrestricted')
    $null = Set-NgcdServiceQueryIdentity $ExpectedSshSid
    if ($InstallEnabled) {
        $null = Invoke-NgcdSc @('start',$script:ServiceName)
        Start-Sleep -Milliseconds 500
    }
    $readback = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") -ErrorAction Stop
    $expectedState = if ($InstallEnabled) { 'Running' } else { 'Stopped' }
    if ($readback.PathName -cne $binaryPath -or $readback.StartMode -cne $expectedStartMode -or
        $readback.StartName -cne $script:ServiceAccount -or $readback.State -cne $expectedState) {
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
        initialActivationSha256 = ''
        applyEnabled = [bool]$Authorization.initialPolicy.applyEnabled
        executableActions = [object[]]@($Authorization.initialPolicy.executableActions)
        canaryStage = [string]$Authorization.initialPolicy.canaryStage
    }
}

function ConvertFrom-NgcdStrictUtcTimestamp {
    param([string]$Value,[string]$Code)
    $parsed = [DateTimeOffset]::MinValue
    $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    if ($Value -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' -or
        -not [DateTimeOffset]::TryParseExact(
            $Value,"yyyy-MM-dd'T'HH:mm:ss'Z'",[Globalization.CultureInfo]::InvariantCulture,
            $style,[ref]$parsed
        )) { Stop-Ngcd $Code }
    $parsed
}

function Get-NgcdInitialActivationCurrentPath {
    param([object]$Context)
    Join-Path (Join-Path $Context.StateRoot 'initial-activation') 'current.json'
}

function Test-NgcdDetachedCmsBytes {
    param([byte[]]$ContentBytes,[byte[]]$SignatureBytes,[string]$ExpectedSignerSha256)
    if ($ContentBytes.Length -le 0 -or $ContentBytes.Length -gt 1048576 -or
        $SignatureBytes.Length -le 0 -or $SignatureBytes.Length -gt 1048576) {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNATURE-INVALID'
    }
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    try {
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($content,$true)
        $cms.Decode($SignatureBytes)
        if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1 -or
            $cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
            Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNATURE-INVALID'
        }
        $cms.CheckSignature($true)
        $certificate = $cms.SignerInfos[0].Certificate
        $null = Test-NgcdCertificatePin $certificate $ExpectedSignerSha256
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $certificate
        )
        try {
            if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
                Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNATURE-INVALID'
            }
        }
        finally { if ($null -ne $rsa) { $rsa.Dispose() } }
        [pscustomobject][ordered]@{
            signerCertificateSha256 = $ExpectedSignerSha256
            signatureSha256 = Get-NgcdSha256Bytes $SignatureBytes
        }
    }
    catch {
        if ($_.Exception.Message -cmatch '^NGCOR-') { throw }
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNATURE-INVALID'
    }
}

function New-NgcdAdministratorApprovalSignature {
    param([byte[]]$ContentBytes,[string]$ExpectedSignerSha256)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        $identity.User.Value -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-ADMIN-IDENTITY-REQUIRED'
    }
    $matches = @(
        foreach ($storePath in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
            Get-ChildItem -LiteralPath $storePath | Where-Object {
                $_.HasPrivateKey -and (Get-NgcdSha256Bytes $_.RawData) -ceq $ExpectedSignerSha256
            }
        }
    )
    if ($matches.Count -ne 1) { Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNING-KEY-UNAVAILABLE' }
    $certificate = $matches[0]
    $null = Test-NgcdCertificatePin $certificate $ExpectedSignerSha256
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
            Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNING-KEY-INVALID'
        }
        if ($rsa -is [Security.Cryptography.RSACng]) {
            $forbidden = [Security.Cryptography.CngExportPolicies]::AllowExport -bor
                [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
            if (($rsa.Key.ExportPolicy -band $forbidden) -ne 0) {
                Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNING-KEY-EXPORTABLE'
            }
        }
        elseif ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            if ($rsa.CspKeyContainerInfo.Exportable) {
                Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNING-KEY-EXPORTABLE'
            }
        }
        else { Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SIGNING-KEY-INVALID' }
        try { Add-Type -AssemblyName System.Security -ErrorAction Stop }
        catch { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
        $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,$ContentBytes)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms($content,$true)
        $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner($certificate)
        $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
        $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid(
            '2.16.840.1.101.3.4.2.1','SHA256'
        )
        $cms.ComputeSignature($signer,$true)
        $signature = $cms.Encode()
        $null = Test-NgcdDetachedCmsBytes $ContentBytes $signature $ExpectedSignerSha256
        return ,$signature
    }
    finally { if ($null -ne $rsa) { $rsa.Dispose() } }
}

function Assert-NgcdInitialActivationContract {
    param(
        [object]$Activation,[object]$Installed,[object]$Manifest,[object]$Authorization,
        [string]$AuthorizationSha256,[AllowEmptyString()][string]$RegisteredAtUtc=''
    )
    $code = 'NGCOR-INITIAL-ACTIVATION-CONTRACT-INVALID'
    Assert-NgcdExactProperties $Activation @(
        'schema','activationId','changeId','authorizationSha256','releaseManifestSha256',
        'backendPolicySha256','dataBundleSha256','repository','fromStage','toStage',
        'applyEnabled','executableActions','readinessEvidenceSha256','issuedAtUtc','expiresAtUtc',
        'approverSid','nonce'
    ) $code
    Assert-NgcdExactProperties $Activation.repository @('identity','commit','tree') $code
    if ($Activation.schema -cne $script:InitialActivationSchema -or
        $Activation.activationId -cnotmatch '^ngactivate-[a-f0-9]{64}$' -or
        $Activation.changeId -cnotmatch '^NG-CHG-[0-9]{8}-[A-Z0-9-]{3,32}$' -or
        $Activation.authorizationSha256 -cne $AuthorizationSha256 -or
        $Activation.releaseManifestSha256 -cne $Installed.releaseManifestSha256 -or
        $Activation.backendPolicySha256 -cne $Installed.backendPolicySha256 -or
        $Activation.dataBundleSha256 -cne $Installed.dataBundleSha256 -or
        $Activation.repository.identity -cne 'Beowxlf/northgate-vm-factory' -or
        $Activation.repository.commit -cne $Installed.repositoryCommit -or
        $Activation.repository.tree -cne $Installed.repositoryTree -or
        $Activation.repository.commit -cne $Manifest.repository.commit -or
        $Activation.repository.tree -cne $Manifest.repository.tree -or
        $Activation.fromStage -cne 'disabled' -or $Activation.toStage -cne 'debian-canary' -or
        $Activation.applyEnabled -ne $true -or
        (@($Activation.executableActions) -join '|') -cne 'Create' -or
        $Activation.readinessEvidenceSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $Activation.readinessEvidenceSha256 -ceq ('0' * 64) -or
        $Activation.approverSid -cnotmatch '^S-1-[0-9-]+$' -or
        $Activation.approverSid -in @('S-1-5-18','S-1-5-19','S-1-5-20') -or
        $Activation.nonce -cnotmatch '^[a-f0-9]{64}$' -or
        $Authorization.initialPolicy.applyEnabled -ne $false -or
        @($Authorization.initialPolicy.executableActions).Count -ne 0 -or
        $Authorization.initialPolicy.canaryStage -cne 'disabled') { Stop-Ngcd $code }
    $issued = ConvertFrom-NgcdStrictUtcTimestamp $Activation.issuedAtUtc $code
    $expires = ConvertFrom-NgcdStrictUtcTimestamp $Activation.expiresAtUtc $code
    if ($expires -le $issued -or ($expires - $issued).TotalSeconds -gt 300) { Stop-Ngcd $code }
    if (-not [string]::IsNullOrEmpty($RegisteredAtUtc)) {
        $registered = ConvertFrom-NgcdStrictUtcTimestamp $RegisteredAtUtc $code
        if ($registered -lt $issued -or $registered -gt $expires) { Stop-Ngcd $code }
    }
    $true
}

function Test-NgcdInitialActivationState {
    param(
        [object]$Context,[object]$Installed,[object]$Manifest,[object]$Authorization,
        [string]$AuthorizationSha256,[object]$Policy
    )
    $record = Read-NgcdProtectedRecord (Get-NgcdInitialActivationCurrentPath $Context) `
        $Context.MacKey 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID'
    Assert-NgcdExactProperties $record @(
        'schema','activation','activationSha256','detachedCmsSignatureBase64',
        'detachedCmsSignatureSha256','signerCertificateSha256','registeredAtUtc'
    ) 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID'
    if ($record.schema -cne $script:InitialActivationRecordSchema -or
        $record.activationSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $record.detachedCmsSignatureSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $record.signerCertificateSha256 -cne $Authorization.identity.approvalSignerCertificateSha256) {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID'
    }
    $null = Assert-NgcdInitialActivationContract $record.activation $Installed $Manifest $Authorization `
        $AuthorizationSha256 ([string]$record.registeredAtUtc)
    $activationBytes = [Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $record.activation)
    )
    if ((Get-NgcdSha256Bytes $activationBytes) -cne $record.activationSha256 -or
        $Policy.initialActivationSha256 -cne $record.activationSha256 -or
        $Policy.applyEnabled -ne $true -or
        (@($Policy.executableActions) -join '|') -cne 'Create' -or
        $Policy.canaryStage -cne 'debian-canary') {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID'
    }
    try { $signatureBytes = [Convert]::FromBase64String([string]$record.detachedCmsSignatureBase64) }
    catch { Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID' }
    $signatureEvidence = Test-NgcdDetachedCmsBytes $activationBytes $signatureBytes `
        ([string]$Authorization.identity.approvalSignerCertificateSha256)
    if ($signatureEvidence.signatureSha256 -cne $record.detachedCmsSignatureSha256) {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID'
    }
    [pscustomobject][ordered]@{
        status = 'verified'; activationId = [string]$record.activation.activationId
        activationSha256 = [string]$record.activationSha256
        registeredAtUtc = [string]$record.registeredAtUtc
    }
}

function Invoke-NorthGateCreateOnlyInitialActivationTransaction {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Installed,
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][object]$Authorization,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$AuthorizationSha256,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ReadinessEvidenceSha256,
        [Parameter(Mandatory)][ValidatePattern('^NG-CHG-[0-9]{8}-[A-Z0-9-]{3,32}$')][string]$ChangeId,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ApprovalCertificateSha256,
        [Parameter(Mandatory)][ValidateRange(30,300)][int]$LifetimeSeconds
    )
    Assert-NgcdContext $Context
    if ($Context.Mode -cne 'Production') { Stop-Ngcd 'NGCOR-DEPLOYMENT-PRODUCTION-CONTEXT-REQUIRED' }
    if ($ApprovalCertificateSha256 -cne $Authorization.identity.approvalSignerCertificateSha256 -or
        $ReadinessEvidenceSha256 -ceq ('0' * 64)) {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-BINDING-MISMATCH'
    }
    if (-not $PSCmdlet.ShouldProcess([string]$Authorization.host.hostId,
        'Activate the installed create-only service for Debian planning')) {
        Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-CONFIRMATION-REQUIRED'
    }
    $lock = Enter-NgcdDeploymentLock $Context.LockName
    $disabledPolicyBytes = $null
    $destinationRoot = Join-Path $Context.ReleaseParent ([string]$Manifest.releaseId)
    $serviceHostPath = Join-Path $destinationRoot ([string]$Context.ServiceHostFileName)
    try {
        $verified = Test-NorthGateCreateOnlyInstalledRelease $Context $Manifest $Authorization $AuthorizationSha256
        if ($verified.status -cne 'verified' -or $verified.releaseRoot -cne $destinationRoot -or
            $Installed.releaseId -cne $Manifest.releaseId -or
            $Installed.releaseManifestSha256 -cne $Authorization.releaseManifestSha256 -or
            $Installed.deploymentAuthorizationSha256 -cne $AuthorizationSha256) {
            Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-BINDING-MISMATCH'
        }
        $disabledPolicyBytes = Read-NgcdExclusiveBytes $Context.PolicyPath 1048576 `
            'NGCOR-INITIAL-ACTIVATION-POLICY-INVALID'
        try {
            $disabledPolicy = (ConvertFrom-NorthGateCreateOnlyCanonicalJsonBytes `
                -Bytes $disabledPolicyBytes -MaximumBytes 1048576).Value
        }
        catch { Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-POLICY-INVALID' }
        Assert-NgcdExactProperties $disabledPolicy @(
            'schema','releaseId','releaseManifestSha256','pipeName','sshIdentitySid',
            'serviceIdentitySid','serviceName','serviceHostSignerCertificateSha256',
            'backendPolicySha256','dataBundleSha256','initialActivationSha256',
            'applyEnabled','executableActions','canaryStage'
        ) 'NGCOR-INITIAL-ACTIVATION-POLICY-INVALID'
        if ((ConvertTo-NorthGateCreateOnlyCanonicalJson $disabledPolicy) -cne
                ([Text.Encoding]::UTF8.GetString($disabledPolicyBytes)) -or
            $disabledPolicy.releaseId -cne $Installed.releaseId -or
            $disabledPolicy.releaseManifestSha256 -cne $Installed.releaseManifestSha256 -or
            $disabledPolicy.backendPolicySha256 -cne $Installed.backendPolicySha256 -or
            $disabledPolicy.dataBundleSha256 -cne $Installed.dataBundleSha256 -or
            $disabledPolicy.initialActivationSha256 -cne '' -or
            $disabledPolicy.applyEnabled -ne $false -or
            @($disabledPolicy.executableActions).Count -ne 0 -or
            $disabledPolicy.canaryStage -cne 'disabled') {
            Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-POLICY-INVALID'
        }
        $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $script:ServiceName + "'") `
            -ErrorAction Stop
        if ($service.State -cne 'Stopped' -or $service.StartMode -cne 'Disabled') {
            Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-SERVICE-NOT-DISABLED'
        }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $issued = [DateTimeOffset]::UtcNow
        $activation = [pscustomobject][ordered]@{
            schema = $script:InitialActivationSchema
            activationId = 'ngactivate-' + (New-NgcdRandomHex 32)
            changeId = $ChangeId
            authorizationSha256 = $AuthorizationSha256
            releaseManifestSha256 = [string]$Installed.releaseManifestSha256
            backendPolicySha256 = [string]$Installed.backendPolicySha256
            dataBundleSha256 = [string]$Installed.dataBundleSha256
            repository = [pscustomobject][ordered]@{
                identity = 'Beowxlf/northgate-vm-factory'
                commit = [string]$Installed.repositoryCommit
                tree = [string]$Installed.repositoryTree
            }
            fromStage = 'disabled'; toStage = 'debian-canary'; applyEnabled = $true
            executableActions = [object[]]@('Create')
            readinessEvidenceSha256 = $ReadinessEvidenceSha256
            issuedAtUtc = $issued.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            expiresAtUtc = $issued.AddSeconds($LifetimeSeconds).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            approverSid = [string]$identity.User.Value
            nonce = New-NgcdRandomHex 32
        }
        $null = Assert-NgcdInitialActivationContract $activation $Installed $Manifest $Authorization `
            $AuthorizationSha256
        $activationBytes = [Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-NorthGateCreateOnlyCanonicalJson $activation)
        )
        $signatureBytes = New-NgcdAdministratorApprovalSignature $activationBytes $ApprovalCertificateSha256
        $activationSha256 = Get-NgcdSha256Bytes $activationBytes
        $registeredAtUtc = Get-NgcdUtcTimestamp
        $null = Assert-NgcdInitialActivationContract $activation $Installed $Manifest $Authorization `
            $AuthorizationSha256 $registeredAtUtc
        $activationRoot = Set-NgcdProtectedDirectoryAcl (Join-Path $Context.StateRoot 'initial-activation') `
            ([string]$Authorization.identity.serviceIdentitySid) `
            ([string]$Authorization.identity.sshIdentitySid) $false `
            ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
        $record = [pscustomobject][ordered]@{
            schema = $script:InitialActivationRecordSchema
            activation = $activation
            activationSha256 = $activationSha256
            detachedCmsSignatureBase64 = [Convert]::ToBase64String($signatureBytes)
            detachedCmsSignatureSha256 = Get-NgcdSha256Bytes $signatureBytes
            signerCertificateSha256 = $ApprovalCertificateSha256
            registeredAtUtc = $registeredAtUtc
        }
        Write-NgcdProtectedRecord (Join-Path $activationRoot 'current.json') $record $Context.MacKey
        $activePolicy = New-NgcdInstalledPolicy $Authorization $Installed.releaseId `
            $Installed.releaseManifestSha256 $Installed.backendPolicySha256 $Installed.dataBundleSha256
        $activePolicy.initialActivationSha256 = $activationSha256
        $activePolicy.applyEnabled = $true
        $activePolicy.executableActions = [object[]]@('Create')
        $activePolicy.canaryStage = 'debian-canary'
        Write-NgcdAtomicCanonicalJson $Context.PolicyPath $activePolicy
        $null = Set-NgcdWindowsService $serviceHostPath $destinationRoot `
            ([string]$Authorization.identity.serviceIdentitySid) `
            ([string]$Authorization.identity.sshIdentitySid) $true
        $validated = Test-NgcdInitialActivationState $Context $Installed $Manifest $Authorization `
            $AuthorizationSha256 $activePolicy
        [pscustomobject][ordered]@{
            status = 'activated-for-planning'; activationId = [string]$validated.activationId
            activationSha256 = [string]$validated.activationSha256
            canaryStage = 'debian-canary'; executableActions = [object[]]@('Create')
        }
    }
    catch {
        $failureCode = [string]$_.Exception.Message
        if ($failureCode -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') {
            $failureCode = 'NGCOR-INITIAL-ACTIVATION-FAILED'
        }
        if ($null -ne $disabledPolicyBytes) {
            try {
                Write-NgcdAtomicBytes $Context.PolicyPath $disabledPolicyBytes
                $null = Set-NgcdWindowsService $serviceHostPath $destinationRoot `
                    ([string]$Authorization.identity.serviceIdentitySid) `
                    ([string]$Authorization.identity.sshIdentitySid) $false
            }
            catch { Stop-Ngcd 'NGCOR-INITIAL-ACTIVATION-OUTCOME-UNKNOWN' }
        }
        Stop-Ngcd $failureCode
    }
    finally { Exit-NgcdDeploymentLock $lock }
}

function New-NgcdManagedSshConfiguration {
    param([string]$ExistingConfiguration, [string]$SshUserName, [string]$ReleaseRoot)
    if ($SshUserName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-CONFIGURATION-INVALID'
    }
    $beginCount = ([regex]::Matches(
        $ExistingConfiguration, [regex]::Escape($script:ManagedSshBegin)
    )).Count
    $endCount = ([regex]::Matches(
        $ExistingConfiguration, [regex]::Escape($script:ManagedSshEnd)
    )).Count
    if ($beginCount -ne $endCount -or $beginCount -gt 1) {
        Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-CONFIGURATION-INVALID'
    }
    $baseConfiguration = $ExistingConfiguration
    if ($beginCount -eq 1) {
        $beginIndex = $ExistingConfiguration.IndexOf(
            $script:ManagedSshBegin, [StringComparison]::Ordinal
        )
        $endIndex = $ExistingConfiguration.IndexOf(
            $script:ManagedSshEnd, [StringComparison]::Ordinal
        )
        if ($beginIndex -lt 0 -or $endIndex -le $beginIndex) {
            Stop-Ngcd 'NGCOR-DEPLOYMENT-SSH-CONFIGURATION-INVALID'
        }
        $endExclusive = $endIndex + $script:ManagedSshEnd.Length
        $prefix = $ExistingConfiguration.Substring(0, $beginIndex).TrimEnd("`r","`n")
        $suffix = $ExistingConfiguration.Substring($endExclusive).TrimStart("`r","`n")
        $baseConfiguration = if ([string]::IsNullOrEmpty($prefix)) { $suffix }
        elseif ([string]::IsNullOrEmpty($suffix)) { $prefix }
        else { $prefix + "`r`n" + $suffix }
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
    $baseConfiguration.TrimEnd("`r","`n") + "`r`n`r`n" + $block + "`r`n"
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
    'Invoke-NorthGateCreateOnlyInitialActivationTransaction',
    'Invoke-NorthGateCreateOnlyRollbackTransaction',
    'Test-NorthGateCreateOnlyInstalledRelease'
)

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXeJvcOieI7Lhl
# K3oKQ12hEkqXuaOtms14X7PC1kfrv6CCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIMLn/MzsSTqUZwGjHqmowPEUMJG9gyHxdbgz2REgu/9wMA0GCSqG
# SIb3DQEBAQUABIIBgJVM+wkdo2YbJ7whnKsBuc4kZa4rm2kuSlA4XxVD1pHhTjL/
# naAsMFacnkNCh0okrQIt+eZ1ZvwSP5ISmGP90STbVH1Sb8wThmWoW5Wp0ZiugkRn
# plr1PdvB0qi1F63Nzup8ivY0fcMc7ryGXJxiE1fD37t7F8BF9zpHccJ+ifjxdleS
# nTHkWdZ0wF1Ut8ADS9LP8lZg8XKtNTv7jniMJoloCNpKzp2fdc36PBj0NZ3DDNQ8
# u2VSqmtQuSb40lm/K/oC7pbbhsa2IN5TVboHaGyTAhqsB7p2IrZLGOKBDabIfDzC
# 4/U4fnurMbey35TB+TgcReO1cfN5dymHeNL0nn0D8MH2Iahe1BDhrFKgGCPVfA3I
# R970sYGNbj9kimuDRJLSqgAJkfvPh8NZZ/ylrto9lcmpKtBf/IUOQ8fO/rgwUDce
# fos1hV+YGHGbl+KylzHTZi63+DwDuEl6lfCXyzPSjAO2kuLFvKg6a2/OlF71pwsx
# GVHwp87FiSpbOfRejA==
# SIG # End signature block
