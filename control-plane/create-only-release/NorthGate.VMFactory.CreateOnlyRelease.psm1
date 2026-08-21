Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1') -Force -ErrorAction Stop

$script:ReleaseVersion = '0.1.0'
$script:ReleaseStatus = 'production-release-candidate-hard-disabled'
$script:ProductionLockName = 'Global\NorthGateVmFactoryCreateOnlyRelease-v1'
$script:MaximumStateBytes = 1048576
$script:PlanTtlMinutes = 5

function Throw-NgcorError {
    param([Parameter(Mandatory)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function ConvertFrom-NgcorReleaseJsonText {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $converter = Microsoft.PowerShell.Core\Get-Command `
        -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String
    }
    return Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json
}

function Get-NgcorSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgcorStringSha256Hex {
    param([Parameter(Mandatory)][string]$Value)
    Get-NgcorSha256Hex ([System.Text.Encoding]::UTF8.GetBytes($Value))
}

function Get-NgcorHmacHex {
    param([byte[]]$Key, [string]$Domain, [string]$Value)
    $algorithm = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Domain + "`n" + $Value)) }
    finally { $algorithm.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-NgcorRandomHex {
    param([ValidateRange(16, 64)][int]$ByteCount = 32)
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) }
    finally { $generator.Dispose() }
    (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-NgcorFixedHexEquals {
    param([string]$Left, [string]$Right)
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    $difference -eq 0
}

function New-NgcorFleetEntry {
    param(
        [string]$AssetId, [string]$Name, [string]$DeploymentClass,
        [int]$Processors, [int]$MinimumMiB, [int]$StartupMiB, [int]$MaximumMiB,
        [int]$DiskGiB, [string]$ImageId, [string]$ImageHash, [long]$ImageSize,
        [string]$Firmware, [string]$VolumeId, [string]$Network, [int]$Vlan,
        [string]$Bootstrap, [string]$Recovery, [string]$Access
    )
    [pscustomobject][ordered]@{
        assetId = $AssetId
        name = $Name
        deploymentClass = $DeploymentClass
        desired = [pscustomobject][ordered]@{
            generation = 2
            processors = $Processors
            memory = [pscustomobject][ordered]@{
                mode = 'dynamic'; minimumMiB = $MinimumMiB
                startupMiB = $StartupMiB; maximumMiB = $MaximumMiB
            }
            osDisk = [pscustomobject][ordered]@{
                type = 'dynamic-vhdx'; sizeGiB = $DiskGiB; volumeId = $VolumeId
            }
            image = [pscustomobject][ordered]@{
                imageId = $ImageId; sha256 = $ImageHash; sizeBytes = $ImageSize
            }
            firmwareProfile = $Firmware
            secureBootRequired = $true
            vtpmRequired = ($Firmware -ceq 'windows-gen2')
            network = [pscustomobject][ordered]@{
                switchPolicyId = 'northgate-app-trunk'; profile = $Network; vlanId = $Vlan
            }
            bootstrapProfile = $Bootstrap
            recoveryProfile = $Recovery
            accessProfile = $Access
            desiredPowerState = 'off'
            destroyProtection = $true
        }
    }
}

function Get-NorthGateCreateOnlyFixedCatalog {
    [CmdletBinding()]
    param()
    $debian = 'dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531'
    $windows = 'd141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
    $kali = 'd32f929dacc48134a31461a09f2160d13ad1d26b820cee920446813ca979b39b'
    $fleet = @(
        New-NgcorFleetEntry 'NG-VM-018' 'NG-DEB-CAN01' 'canary' 2 2048 2048 4096 40 'debian-12.12.0-amd64-netinst' $debian 704643072 'linux-gen2' 'volume-d' 'business-apps' 150 'debian12-disposable-canary' 'none-canary' 'disposable-canary-keyonly-admin'
        New-NgcorFleetEntry 'NG-VM-010' 'NG-CANARY-01' 'canary' 2 4096 4096 8192 80 'windows-11-25h2-english-x64' $windows 7736125440 'windows-gen2' 'volume-f' 'users-workstations' 110 'windows11-disposable-canary' 'none-canary' 'windows-disposable-canary'
        New-NgcorFleetEntry 'NG-VM-014' 'NG-MAIL-EXT01' 'persistent' 2 2048 2048 4096 40 'debian-12.12.0-amd64-netinst' $debian 704643072 'linux-gen2' 'volume-d' 'external-mail' 240 'debian12-mail-external' 'bronze' 'linux-server-keyonly-admin'
        New-NgcorFleetEntry 'NG-VM-013' 'NG-MAIL-INT01' 'persistent' 2 2048 4096 8192 80 'debian-12.12.0-amd64-netinst' $debian 704643072 'linux-gen2' 'volume-d' 'mail-internal' 120 'debian12-mail-internal' 'silver' 'linux-server-keyonly-admin'
        New-NgcorFleetEntry 'NG-VM-011' 'NG-WRK-01' 'persistent' 2 4096 4096 6144 80 'windows-11-25h2-english-x64' $windows 7736125440 'windows-gen2' 'volume-f' 'users-workstations' 110 'windows11-worker' 'bronze' 'windows-domain-managed'
        New-NgcorFleetEntry 'NG-VM-012' 'NG-WRK-02' 'persistent' 2 4096 4096 6144 80 'windows-11-25h2-english-x64' $windows 7736125440 'windows-gen2' 'volume-f' 'users-workstations' 110 'windows11-worker' 'bronze' 'windows-domain-managed'
        New-NgcorFleetEntry 'NG-VM-019' 'NG-MGR-01' 'persistent' 2 4096 4096 6144 80 'windows-11-25h2-english-x64' $windows 7736125440 'windows-gen2' 'volume-f' 'users-workstations' 110 'windows11-manager' 'bronze' 'windows-domain-managed'
        New-NgcorFleetEntry 'NG-VM-020' 'NG-IT-01' 'persistent' 4 4096 8192 12288 100 'windows-11-25h2-english-x64' $windows 7736125440 'windows-gen2' 'volume-f' 'it-admin-workstations' 130 'windows11-it-admin' 'silver' 'windows-privileged-workstation'
        New-NgcorFleetEntry 'NG-VM-021' 'NG-CYBER-01' 'persistent' 4 4096 8192 12288 120 'windows-11-25h2-english-x64' $windows 7736125440 'windows-gen2' 'volume-f' 'cyber-workstations' 140 'windows11-cyber' 'silver' 'windows-privileged-workstation'
        New-NgcorFleetEntry 'NG-VM-016' 'NG-HR-APP01' 'persistent' 2 2048 4096 8192 100 'debian-12.12.0-amd64-netinst' $debian 704643072 'linux-gen2' 'volume-d' 'business-apps' 150 'debian12-employee-hub' 'aegis-app-protected' 'debian-app-keyonly-admin'
        New-NgcorFleetEntry 'NG-VM-017' 'NG-PLAT-APP01' 'persistent' 4 4096 8192 16384 120 'debian-12.12.0-amd64-netinst' $debian 704643072 'linux-gen2' 'volume-d' 'commercial-dmz' 160 'debian12-sentinel-atlas' 'aegis-app-protected' 'debian-app-keyonly-admin'
        New-NgcorFleetEntry 'NG-VM-015' 'NG-KALI-EXT01' 'persistent' 4 4096 4096 12288 100 'kali-2026.2-installer-netinst-amd64' $kali 779091968 'linux-gen2' 'volume-d' 'sim-wan' 250 'kali-external-lab' 'bronze' 'kali-lab-keyonly-admin'
    )
    $core = [pscustomobject][ordered]@{
        schema = 'northgate/create-only-fixed-catalog/v1'
        releaseVersion = $script:ReleaseVersion
        operation = 'Create'
        maximumOperationsPerPlan = 1
        initialPowerState = 'off'
        fixedSwitchPolicyId = 'northgate-app-trunk'
        volumePolicies = @(
            [pscustomobject][ordered]@{ volumeId = 'volume-d'; persistentCeilingGiB = 440; canaryCeilingGiB = 40 },
            [pscustomobject][ordered]@{ volumeId = 'volume-f'; persistentCeilingGiB = 460; canaryCeilingGiB = 80 }
        )
        minimumFreePolicy = [pscustomobject][ordered]@{ fixedGiB = 100; percentage = 15; chooseGreater = $true }
        deniedOperations = @('Start','Stop','Delete','Replace','Adopt','Update','GuestCommand','HostCommand','SwitchCreate','VlanCreate')
        fleet = $fleet
    }
    $canonical = ConvertTo-NorthGateCreateOnlyCanonicalJson $core
    [pscustomobject][ordered]@{
        schema = $core.schema
        releaseVersion = $core.releaseVersion
        operation = $core.operation
        maximumOperationsPerPlan = $core.maximumOperationsPerPlan
        initialPowerState = $core.initialPowerState
        fixedSwitchPolicyId = $core.fixedSwitchPolicyId
        volumePolicies = $core.volumePolicies
        minimumFreePolicy = $core.minimumFreePolicy
        deniedOperations = $core.deniedOperations
        fleet = $core.fleet
        catalogHash = Get-NgcorStringSha256Hex $canonical
    }
}

function Assert-NgcorNoRepositoryAncestor {
    param([string]$Path)
    $item = New-Object System.IO.DirectoryInfo([System.IO.Path]::GetFullPath($Path))
    while ($null -ne $item) {
        if (Test-Path -LiteralPath (Join-Path $item.FullName '.git')) {
            Throw-NgcorError 'NGCOR-STATE-ROOT-IN-REPOSITORY'
        }
        $item = $item.Parent
    }
}

function New-NgcorTestContext {
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][byte[]]$HmacKey,
        [ValidateSet('disabled','debian-canary','windows-canary','fleet')][string]$CanaryStage = 'disabled',
        [string[]]$AcceptedCanaries = @(),
        [bool]$ApplyEnabled = $false
    )
    if ($HmacKey.Length -lt 32) { Throw-NgcorError 'NGCOR-TEST-KEY-INVALID' }
    Assert-NgcorNoRepositoryAncestor $StateRoot
    $root = [System.IO.Path]::GetFullPath($StateRoot)
    $null = [System.IO.Directory]::CreateDirectory($root)
    if ((Get-Item -LiteralPath $root -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Throw-NgcorError 'NGCOR-STATE-REPARSE-FORBIDDEN'
    }
    [pscustomobject][ordered]@{
        Mode = 'SimulationOnly'
        StateRoot = $root
        LedgerPath = Join-Path $root 'plan-ledger.json'
        HmacKey = [byte[]]$HmacKey.Clone()
        LockName = 'Local\NorthGateCreateOnlyReleaseTest-' + [guid]::NewGuid().ToString('N')
        ApplyEnabled = $ApplyEnabled
        ExecutableActions = if ($ApplyEnabled) { @('Create') } else { @() }
        CanaryStage = $CanaryStage
        AcceptedCanaries = @($AcceptedCanaries)
        NowUtc = [DateTimeOffset]::UtcNow
        ObservedState = [pscustomobject][ordered]@{
            schema = 'northgate/create-only-observed-state/v1'
            collectorVersion = 'simulation-0.1.0'
            hostIdentity = 'simulation-host'
            maintenanceBlocked = $false
            switchPolicyId = 'northgate-app-trunk'
            switchIdentityHash = ('1' * 64)
            volumeStateHash = ('2' * 64)
            imageStateHash = ('3' * 64)
            inventoryStateHash = ('4' * 64)
            reservationEpoch = 0
        }
    }
}

function Enter-NgcorWriterLock {
    param([string]$Name)
    try {
        $semaphore = New-Object System.Threading.Semaphore(1, 1, $Name)
        if (-not $semaphore.WaitOne(0)) {
            $semaphore.Dispose()
            Throw-NgcorError 'NGCOR-WRITER-LOCK-BUSY'
        }
        $semaphore
    }
    catch {
        if ($_.Exception.Message -eq 'NGCOR-WRITER-LOCK-BUSY') { throw }
        Throw-NgcorError 'NGCOR-WRITER-LOCK-UNAVAILABLE'
    }
}

function Exit-NgcorWriterLock {
    param([System.Threading.Semaphore]$Semaphore)
    try { $null = $Semaphore.Release() }
    finally { $Semaphore.Dispose() }
}

function New-NgcorEmptyLedger {
    [pscustomobject][ordered]@{
        formatVersion = 1
        sequence = 0
        previousHead = ('0' * 64)
        reservations = @()
    }
}

function Protect-NgcorLedger {
    param([object]$Record, [byte[]]$Key)
    $canonical = ConvertTo-NorthGateCreateOnlyCanonicalJson $Record
    $head = Get-NgcorStringSha256Hex ("northgate-create-only-ledger-head-v1`n" + $canonical)
    [pscustomobject][ordered]@{
        record = $Record
        head = $head
        mac = Get-NgcorHmacHex $Key 'northgate-create-only-ledger-mac-v1' ($head + "`n" + $canonical)
    }
}

function Read-NgcorLedger {
    param([object]$Context)
    if (-not (Test-Path -LiteralPath $Context.LedgerPath -PathType Leaf)) { return New-NgcorEmptyLedger }
    $item = Get-Item -LiteralPath $Context.LedgerPath -Force
    if ($item.Length -gt $script:MaximumStateBytes -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Throw-NgcorError 'NGCOR-LEDGER-CORRUPT'
    }
    try { $raw = [System.IO.File]::ReadAllText($item.FullName) }
    catch { Throw-NgcorError 'NGCOR-LEDGER-READ-FAILED' }
    try { $envelope = ConvertFrom-NgcorReleaseJsonText $raw }
    catch { Throw-NgcorError 'NGCOR-LEDGER-CORRUPT' }
    if ((ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope) -cne $raw) {
        Throw-NgcorError 'NGCOR-LEDGER-NONCANONICAL'
    }
    $properties = @($envelope.PSObject.Properties.Name | Sort-Object)
    if (($properties -join '|') -cne 'head|mac|record' -or
        $envelope.head -cnotmatch '^[a-f0-9]{64}$' -or $envelope.mac -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgcorError 'NGCOR-LEDGER-CORRUPT'
    }
    $canonical = ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope.record
    $expectedHead = Get-NgcorStringSha256Hex ("northgate-create-only-ledger-head-v1`n" + $canonical)
    $expectedMac = Get-NgcorHmacHex $Context.HmacKey 'northgate-create-only-ledger-mac-v1' `
        ($expectedHead + "`n" + $canonical)
    if (-not (Test-NgcorFixedHexEquals $expectedHead ([string]$envelope.head)) -or
        -not (Test-NgcorFixedHexEquals $expectedMac ([string]$envelope.mac))) {
        Throw-NgcorError 'NGCOR-LEDGER-AUTHENTICATION-FAILED'
    }
    $envelope.record
}

function Write-NgcorLedger {
    param([object]$Context, [object]$Record)
    $envelope = Protect-NgcorLedger $Record $Context.HmacKey
    $content = ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope
    $temporary = Join-Path $Context.StateRoot ('.ledger-' + (New-NgcorRandomHex 16) + '.tmp')
    try {
        [System.IO.File]::WriteAllText($temporary, $content, (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Context.LedgerPath) {
            [System.IO.File]::Replace($temporary, $Context.LedgerPath, $null, $true)
        }
        else { [System.IO.File]::Move($temporary, $Context.LedgerPath) }
    }
    catch {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        Throw-NgcorError 'NGCOR-LEDGER-WRITE-FAILED'
    }
}

function Assert-NgcorRolloutGate {
    param([object]$Context, [object]$Asset, [object]$Ledger)
    if (-not $Context.ApplyEnabled -or 'Create' -cnotin @($Context.ExecutableActions)) {
        Throw-NgcorError 'NGCOR-POLICY-DISABLED'
    }
    $openCanary = @($Ledger.reservations | Where-Object {
        $_.deploymentClass -ceq 'canary' -and $_.state -in @('Planned','Approved','Applying','OutcomeUnknown')
    })
    switch ($Context.CanaryStage) {
        'debian-canary' {
            if ($Asset.assetId -cne 'NG-VM-018' -or $openCanary.Count -ne 0) {
                Throw-NgcorError 'NGCOR-CANARY-GATE-BLOCKED'
            }
        }
        'windows-canary' {
            if ($Asset.assetId -cne 'NG-VM-010' -or 'NG-VM-018' -cnotin @($Context.AcceptedCanaries) -or
                $openCanary.Count -ne 0) { Throw-NgcorError 'NGCOR-CANARY-GATE-BLOCKED' }
        }
        'fleet' {
            if ($Asset.deploymentClass -ceq 'canary' -or
                'NG-VM-018' -cnotin @($Context.AcceptedCanaries) -or
                'NG-VM-010' -cnotin @($Context.AcceptedCanaries)) {
                Throw-NgcorError 'NGCOR-CANARY-GATE-BLOCKED'
            }
        }
        default { Throw-NgcorError 'NGCOR-CANARY-STAGE-DISABLED' }
    }
}

function Register-NgcorSimulationPlan {
    param([object]$Context, [object]$ParsedRequest, [string]$ActorSid)
    if ($Context.Mode -cne 'SimulationOnly' -or $ActorSid -cnotmatch '^S-1-[0-9-]+$') {
        Throw-NgcorError 'NGCOR-SIMULATION-CONTEXT-INVALID'
    }
    $catalog = Get-NorthGateCreateOnlyFixedCatalog
    $matches = @($catalog.fleet | Where-Object { $_.assetId -ceq $ParsedRequest.Request.assetId })
    if ($matches.Count -ne 1) { Throw-NgcorError 'NGCOR-ASSET-NOT-IN-FIXED-FLEET' }
    $asset = $matches[0]
    $writerLock = Enter-NgcorWriterLock $Context.LockName
    try {
        $ledger = Read-NgcorLedger $Context
        Assert-NgcorRolloutGate $Context $asset $ledger
        if (@($ledger.reservations | Where-Object {
            $_.assetId -ceq $asset.assetId -or $_.name -ceq $asset.name
        }).Count -ne 0) { Throw-NgcorError 'NGCOR-IDENTITY-ALREADY-RESERVED' }
        if ($Context.ObservedState.maintenanceBlocked -ne $false) {
            Throw-NgcorError 'NGCOR-MAINTENANCE-BLOCKED'
        }
        $registered = $Context.NowUtc
        $expires = $registered.AddMinutes($script:PlanTtlMinutes)
        $planId = 'ngp-' + (New-NgcorRandomHex 32)
        $reservationId = 'ngrsv-' + (New-NgcorRandomHex 24)
        $observedCanonical = ConvertTo-NorthGateCreateOnlyCanonicalJson $Context.ObservedState
        $desiredCanonical = ConvertTo-NorthGateCreateOnlyCanonicalJson $asset.desired
        $plan = [pscustomobject][ordered]@{
            apiVersion = 'northgate/v1alpha1'
            kind = 'CreateOnlyHostPlan'
            planId = $planId
            changeId = $ParsedRequest.Request.changeId
            repository = $ParsedRequest.Request.repository
            actorSid = $ActorSid
            issuedAtUtc = $registered.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            expiresAtUtc = $expires.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            catalogHash = $catalog.catalogHash
            observedStateHash = Get-NgcorStringSha256Hex $observedCanonical
            observedReservationEpoch = [int64]$Context.ObservedState.reservationEpoch
            operation = [pscustomobject][ordered]@{
                sequence = 1; action = 'Create'; reservationId = $reservationId
                assetId = $asset.assetId; name = $asset.name
                desiredStateHash = Get-NgcorStringSha256Hex $desiredCanonical
                desired = $asset.desired
            }
        }
        $canonicalPlan = ConvertTo-NorthGateCreateOnlyCanonicalJson $plan
        $planHash = Get-NgcorStringSha256Hex $canonicalPlan
        $reservation = [pscustomobject][ordered]@{
            planId = $planId; planHash = $planHash; reservationId = $reservationId
            assetId = $asset.assetId; name = $asset.name; deploymentClass = $asset.deploymentClass
            state = 'Planned'; expiresAtUtc = $plan.expiresAtUtc; canonicalPlan = $canonicalPlan
        }
        $newReservations = @($ledger.reservations) + @($reservation)
        $newRecord = [pscustomobject][ordered]@{
            formatVersion = 1
            sequence = [int64]$ledger.sequence + 1
            previousHead = if ([int64]$ledger.sequence -eq 0) { ('0' * 64) } else {
                (Protect-NgcorLedger $ledger $Context.HmacKey).head
            }
            reservations = $newReservations
        }
        Write-NgcorLedger $Context $newRecord
        [pscustomobject][ordered]@{
            operation = 'plan'; accepted = $true; planId = $planId; planHash = $planHash
            expiresAtUtc = $plan.expiresAtUtc; assetId = $asset.assetId; action = 'Create'
            maximumOperations = 1; state = 'PlannedSimulationOnly'; productionApplicable = $false
        }
    }
    finally { Exit-NgcorWriterLock $writerLock }
}

function Get-NgcorReleaseStatus {
    $catalog = Get-NorthGateCreateOnlyFixedCatalog
    [pscustomobject][ordered]@{
        operation = 'status'
        releaseVersion = $script:ReleaseVersion
        releaseStatus = $script:ReleaseStatus
        fixedFleetAssetCount = @($catalog.fleet).Count
        fixedCatalogHash = $catalog.catalogHash
        forcedCommandProtocolImplemented = $true
        namedPipeServiceInstalled = $false
        planRegistryProductionEnabled = $false
        applyEnabled = $false
        executableActions = @()
        canaryStage = 'disabled'
        liveCollectorImplemented = $false
        liveHyperVBackendImplemented = $false
        approvalSignerPinned = $false
        receiptSignerPinned = $false
        rollbackAnchorImplemented = $false
        productionApplicable = $false
        reasonCode = 'NGCOR-PRODUCTION-GATES-INCOMPLETE'
    }
}

function Invoke-NorthGateCreateOnlyServiceRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$RequestBytes,
        [Parameter(Mandatory)][string]$ActorSid
    )
    if ($ActorSid -cnotmatch '^S-1-[0-9-]+$') { Throw-NgcorError 'NGCOR-ACTOR-INVALID' }
    $parsed = ConvertFrom-NorthGateCreateOnlyCommand $Command
    if ($parsed.operation -ceq 'plan') {
        $null = ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $RequestBytes
        Throw-NgcorError 'NGCOR-PRODUCTION-PLAN-REGISTRY-DISABLED'
    }
    if ($RequestBytes.Length -ne 0) { Throw-NgcorError 'NGCOR-STDIN-NOT-EMPTY' }
    switch ($parsed.operation) {
        'status' { Get-NgcorReleaseStatus; return }
        'apply' { Throw-NgcorError 'NGCOR-LIVE-APPLY-NOT-IMPLEMENTED' }
        'receipt' { Throw-NgcorError 'NGCOR-RECEIPT-SIGNING-NOT-IMPLEMENTED' }
        default { Throw-NgcorError 'NGCOR-COMMAND-NOT-ALLOWED' }
    }
}

Export-ModuleMember -Function @(
    'Get-NorthGateCreateOnlyFixedCatalog',
    'Invoke-NorthGateCreateOnlyServiceRequest'
)
