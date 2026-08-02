Set-StrictMode -Version Latest

$script:AdapterVersion = '0.1.0'
$script:ReleaseStatus = 'proposed'
$script:WriterLockName = 'Global\NorthGateVmFactoryWriter-v1'
$script:InertBackendIdentity = 'ngadapter-inert-fixed-v1'
$script:ProductionInvocationEnabled = $false
$script:InertInvocationCount = 0

class NorthGateHostAdapterCreateOperation {
    [string]$Action
    [string]$AssetId
    [string]$Name
    [string]$ChangeId
    [string]$ReservationId
    [string]$ImageRef
    [string]$ImageSha256
    [string]$FirmwareProfileRef
    [int]$Generation
    [int]$Processors
    [string]$MemoryMode
    [int]$MinimumMemoryMiB
    [int]$StartupMemoryMiB
    [int]$MaximumMemoryMiB
    [string]$StorageProfileRef
    [int]$OsDiskGiB
    [string]$NetworkProfileRef
    [string]$NetworkFingerprint
    [string]$BootstrapProfileRef
    [string]$RecoveryProfileRef
    [string]$DesiredPowerState
    [bool]$DestroyProtection
    [string]$ExpectedPolicyHash
    [string]$ExpectedPreflightHash
}

class NorthGateHostAdapterVmMemoryEvidence {
    [string]$VmIdentityHash
    [bool]$DynamicMemoryEnabled
    [int]$StartupMemoryMiB
    [int]$MaximumMemoryMiB
    [int]$AssignedMemoryMiB
    [int]$NormalizedReservationMiB
}

class NorthGateHostAdapterVmStorageEvidence {
    [string]$VmIdentityHash
    [int]$CheckpointCount
    [int]$DifferencingDiskCount
    [string]$ChainState
    [long]$AllocatedBytes
    [string]$RecoveryEvidenceHash
}

class NorthGateHostAdapterPreflight {
    [string]$ContractVersion
    [string]$ObservedAtUtc
    [long]$StateEpoch
    [string]$AssetId
    [string]$Name
    [string]$ReservationId
    [int]$AssetCollisionCount
    [int]$NameCollisionCount
    [int]$DiskIdentityCollisionCount
    [string]$MaintenanceState
    [int]$HostLogicalProcessorCount
    [int]$HostProcessorReserveCount
    [int]$NormalizedExistingProcessorCount
    [int]$PendingProcessorReservationCount
    [long]$HostMemoryCapacityMiB
    [long]$HostMemoryReserveMiB
    [long]$NormalizedExistingMemoryMiB
    [long]$PendingMemoryReservationMiB
    [NorthGateHostAdapterVmMemoryEvidence[]]$VmMemoryEvidence
    [string]$StorageProfileRef
    [string]$StorageResourceId
    [long]$StorageFreeBytes
    [long]$StorageReserveBytes
    [long]$PendingStorageReservationBytes
    [long]$NormalizedExistingStorageBytes
    [NorthGateHostAdapterVmStorageEvidence[]]$VmStorageEvidence
    [string]$ImageRef
    [string]$ImageResourceId
    [long]$ImageArtifactBytes
    [string]$ImageArtifactSha256
    [string]$ImageArtifactState
    [string]$NetworkProfileRef
    [string]$NetworkResourceId
    [string]$NetworkFingerprint
    [string]$NetworkState
    [string]$FirmwareProfileRef
    [string]$BootstrapProfileRef
    [string]$BootstrapArtifactHash
    [string]$RecoveryProfileRef
    [string]$RecoveryRouteHash
    [string]$NormalizedStateHash
}

class NorthGateHostAdapterOutcome {
    [string]$AdapterVersion
    [string]$BackendIdentity
    [string]$Action
    [string]$Status
    [string]$Outcome
    [string]$ReasonCode
    [string]$AssetId
    [string]$Name
    [string]$ChangeId
    [string]$ReservationId
    [string]$VmId
    [string]$AfterStateHash
    [bool]$AfterStateVerified
    [bool]$DestroyProtectionObserved
    [string]$QuarantineState
    [bool]$IdentityReuseBlocked
    [bool]$ReconciliationRequired
}

function Throw-NgvfAdapterError {
    param([Parameter(Mandatory)][string]$Code)

    throw [System.InvalidOperationException]::new($Code)
}

function Get-NgvfSha256Hex {
    param([Parameter(Mandatory)][string]$Value)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $algorithm.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Assert-NgvfExactTypeAndProperties {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$TypeName,
        [Parameter(Mandatory)][string[]]$Properties,
        [Parameter(Mandatory)][string]$Code
    )

    if ($InputObject.GetType().FullName -cne $TypeName) {
        Throw-NgvfAdapterError -Code $Code
    }
    $actual = @($InputObject.PSObject.Properties.Name)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    $expected = @($Properties)
    [array]::Sort($expected, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expected -join '|')) {
        Throw-NgvfAdapterError -Code $Code
    }
}

function Assert-NgvfOpaqueIdentifier {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Code
    )

    if ($Value -cnotmatch '^[a-z][a-z0-9._-]{2,63}$' -or
        $Value.Contains('..') -or
        $Value -match '[\\/:$%*?\[\]{}();&|<>@]' -or
        $Value -match '^[A-Za-z][A-Za-z0-9+.-]*://' -or
        $Value -match '[\x00-\x1f]') {
        Throw-NgvfAdapterError -Code $Code
    }
}

function Assert-NgvfHexHash {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Code
    )

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        Throw-NgvfAdapterError -Code $Code
    }
}

function Get-NgvfFixedPolicyBundle {
    $bundle = [pscustomobject][ordered]@{
        BundleType = 'NorthGateHostAdapterFixedPolicyBundle'
        PolicyVersion = 'phase3-test-policy-v1'
        HostMemoryReserveMiB = [long]8192
        HostProcessorReserveCount = 2
        StorageReserveBytes = [long](64GB)
        Image = [pscustomobject][ordered]@{
            ProfileRef = 'image-phase3-debian-canary-v1'
            ResourceId = 'ngimage-phase3-debian-v1'
            GuestFamily = 'linux'
            Generation = 2
            ArtifactBytes = [long]704643072
            ArtifactSha256 = ('a' * 64)
            FirmwareProfileRef = 'firmware-phase3-linux-gen2-v1'
        }
        Firmware = [pscustomobject][ordered]@{
            ProfileRef = 'firmware-phase3-linux-gen2-v1'
            GuestFamily = 'linux'
            Generation = 2
            SecureBootEnabled = $true
            SecureBootTemplateId = 'ngfirmware-linux-uefi-ca-v1'
            VtpmRequired = $false
        }
        Storage = [pscustomobject][ordered]@{
            ProfileRef = 'storage-phase3-primary-v1'
            ResourceId = 'ngstorage-phase3-primary-v1'
            MinimumOsDiskGiB = 20
            MaximumOsDiskGiB = 128
            DynamicVhdRequired = $true
        }
        Network = [pscustomobject][ordered]@{
            ProfileRef = 'network-phase3-canary-v1'
            ResourceId = 'ngnetwork-phase3-canary-v1'
            Fingerprint = ('b' * 64)
            AllowAttach = $true
            AllowCreate = $false
            AllowRebind = $false
        }
        Bootstrap = [pscustomobject][ordered]@{
            ProfileRef = 'bootstrap-phase3-linux-v1'
            GuestFamily = 'linux'
            ArtifactHash = ('c' * 64)
            Immutable = $true
        }
        Recovery = [pscustomobject][ordered]@{
            ProfileRef = 'recovery-phase3-disposable-v1'
            RouteHash = ('d' * 64)
            QuarantineOnFailure = $true
            BlockIdentityReuseOnUnknown = $true
        }
    }

    $bundle | Add-Member -NotePropertyName PolicyHash -NotePropertyValue (Get-NgvfSha256Hex -Value (
        @(
            $bundle.BundleType,
            $bundle.PolicyVersion,
            $bundle.HostMemoryReserveMiB,
            $bundle.HostProcessorReserveCount,
            $bundle.StorageReserveBytes,
            $bundle.Image.ProfileRef,
            $bundle.Image.ResourceId,
            $bundle.Image.GuestFamily,
            $bundle.Image.Generation,
            $bundle.Image.ArtifactBytes,
            $bundle.Image.ArtifactSha256,
            $bundle.Image.FirmwareProfileRef,
            $bundle.Firmware.ProfileRef,
            $bundle.Firmware.GuestFamily,
            $bundle.Firmware.Generation,
            $bundle.Firmware.SecureBootEnabled,
            $bundle.Firmware.SecureBootTemplateId,
            $bundle.Firmware.VtpmRequired,
            $bundle.Storage.ProfileRef,
            $bundle.Storage.ResourceId,
            $bundle.Storage.MinimumOsDiskGiB,
            $bundle.Storage.MaximumOsDiskGiB,
            $bundle.Storage.DynamicVhdRequired,
            $bundle.Network.ProfileRef,
            $bundle.Network.ResourceId,
            $bundle.Network.Fingerprint,
            $bundle.Network.AllowAttach,
            $bundle.Network.AllowCreate,
            $bundle.Network.AllowRebind,
            $bundle.Bootstrap.ProfileRef,
            $bundle.Bootstrap.GuestFamily,
            $bundle.Bootstrap.ArtifactHash,
            $bundle.Bootstrap.Immutable,
            $bundle.Recovery.ProfileRef,
            $bundle.Recovery.RouteHash,
            $bundle.Recovery.QuarantineOnFailure,
            $bundle.Recovery.BlockIdentityReuseOnUnknown
        ) -join '|'
    ))
    return $bundle
}

function Assert-NgvfCreateOperation {
    param(
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation,
        [Parameter(Mandatory)][object]$Policy
    )

    Assert-NgvfExactTypeAndProperties -InputObject $Operation `
        -TypeName 'NorthGateHostAdapterCreateOperation' -Properties @(
            'Action', 'AssetId', 'Name', 'ChangeId', 'ReservationId', 'ImageRef', 'ImageSha256',
            'FirmwareProfileRef', 'Generation', 'Processors', 'MemoryMode', 'MinimumMemoryMiB',
            'StartupMemoryMiB', 'MaximumMemoryMiB', 'StorageProfileRef', 'OsDiskGiB',
            'NetworkProfileRef', 'NetworkFingerprint', 'BootstrapProfileRef', 'RecoveryProfileRef',
            'DesiredPowerState', 'DestroyProtection', 'ExpectedPolicyHash', 'ExpectedPreflightHash'
        ) -Code 'NGVF-ADAPTER-OPERATION-TYPE-INVALID'

    if ($Operation.Action -cne 'Create') { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-CREATE-ONLY' }
    if ($Operation.AssetId -cnotmatch '^NG-VM-[0-9]{3,}$') { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-ASSET-ID-INVALID' }
    if ($Operation.Name -cnotmatch '^[A-Z0-9][A-Z0-9-]{0,14}$') { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-NAME-INVALID' }
    if ($Operation.ChangeId -cnotmatch '^NG-CHG-[A-Z0-9-]{8,48}$') { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-CHANGE-ID-INVALID' }
    if ($Operation.ReservationId -cnotmatch '^ngrsv-[a-z0-9-]{8,58}$') { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-RESERVATION-INVALID' }
    foreach ($identifier in @(
        $Operation.ImageRef, $Operation.FirmwareProfileRef, $Operation.StorageProfileRef,
        $Operation.NetworkProfileRef, $Operation.BootstrapProfileRef, $Operation.RecoveryProfileRef
    )) {
        Assert-NgvfOpaqueIdentifier -Value $identifier -Code 'NGVF-ADAPTER-OPAQUE-REFERENCE-INVALID'
    }
    foreach ($hash in @(
        $Operation.ImageSha256, $Operation.NetworkFingerprint,
        $Operation.ExpectedPolicyHash, $Operation.ExpectedPreflightHash
    )) {
        Assert-NgvfHexHash -Value $hash -Code 'NGVF-ADAPTER-HASH-INVALID'
    }

    if ($Operation.Generation -ne 2) { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-GENERATION-INVALID' }
    if (-not $Operation.DestroyProtection) { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-DESTROY-PROTECTION-REQUIRED' }
    if ($Operation.DesiredPowerState -cne 'Off') { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-POWER-STATE-INVALID' }
    if ($Operation.Processors -lt 1 -or $Operation.Processors -gt 8) { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PROCESSOR-INVALID' }
    if ($Operation.MinimumMemoryMiB -lt 512 -or $Operation.StartupMemoryMiB -lt 1024 -or
        $Operation.MaximumMemoryMiB -lt 1024 -or
        ($Operation.MinimumMemoryMiB % 128) -ne 0 -or
        ($Operation.StartupMemoryMiB % 128) -ne 0 -or
        ($Operation.MaximumMemoryMiB % 128) -ne 0 -or
        $Operation.MinimumMemoryMiB -gt $Operation.StartupMemoryMiB -or
        $Operation.StartupMemoryMiB -gt $Operation.MaximumMemoryMiB) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MEMORY-INVALID'
    }
    if ($Operation.MemoryMode -cnotin @('Static', 'Dynamic')) { Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MEMORY-MODE-INVALID' }
    if ($Operation.MemoryMode -ceq 'Static' -and
        ($Operation.MinimumMemoryMiB -ne $Operation.StartupMemoryMiB -or
         $Operation.MaximumMemoryMiB -ne $Operation.StartupMemoryMiB)) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-STATIC-MEMORY-INVALID'
    }

    if ($Operation.ImageRef -cne $Policy.Image.ProfileRef -or
        $Operation.ImageSha256 -cne $Policy.Image.ArtifactSha256 -or
        $Operation.FirmwareProfileRef -cne $Policy.Firmware.ProfileRef -or
        $Operation.StorageProfileRef -cne $Policy.Storage.ProfileRef -or
        $Operation.NetworkProfileRef -cne $Policy.Network.ProfileRef -or
        $Operation.NetworkFingerprint -cne $Policy.Network.Fingerprint -or
        $Operation.BootstrapProfileRef -cne $Policy.Bootstrap.ProfileRef -or
        $Operation.RecoveryProfileRef -cne $Policy.Recovery.ProfileRef -or
        $Operation.ExpectedPolicyHash -cne $Policy.PolicyHash) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-POLICY-BINDING-MISMATCH'
    }
    if ($Policy.Image.Generation -ne 2 -or $Policy.Firmware.Generation -ne 2 -or
        $Policy.Image.GuestFamily -cne $Policy.Firmware.GuestFamily -or
        $Policy.Image.GuestFamily -cne $Policy.Bootstrap.GuestFamily -or
        $Policy.Image.FirmwareProfileRef -cne $Policy.Firmware.ProfileRef -or
        -not $Policy.Firmware.SecureBootEnabled -or $Policy.Firmware.VtpmRequired -or
        -not $Policy.Storage.DynamicVhdRequired -or
        -not $Policy.Network.AllowAttach -or $Policy.Network.AllowCreate -or $Policy.Network.AllowRebind -or
        -not $Policy.Bootstrap.Immutable -or
        -not $Policy.Recovery.QuarantineOnFailure -or
        -not $Policy.Recovery.BlockIdentityReuseOnUnknown) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-FIXED-POLICY-INELIGIBLE'
    }
    if ($Operation.OsDiskGiB -lt $Policy.Storage.MinimumOsDiskGiB -or
        $Operation.OsDiskGiB -gt $Policy.Storage.MaximumOsDiskGiB) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-DISK-SIZE-INVALID'
    }
}

function Get-NgvfNormalizedPreflightHash {
    param([Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight)

    $memoryRecords = @(
        $Preflight.VmMemoryEvidence |
            Sort-Object -Property VmIdentityHash |
            ForEach-Object {
                @(
                    $_.VmIdentityHash,
                    $_.DynamicMemoryEnabled,
                    $_.StartupMemoryMiB,
                    $_.MaximumMemoryMiB,
                    $_.AssignedMemoryMiB,
                    $_.NormalizedReservationMiB
                ) -join ','
            }
    )
    $storageRecords = @(
        $Preflight.VmStorageEvidence |
            Sort-Object -Property VmIdentityHash |
            ForEach-Object {
                @(
                    $_.VmIdentityHash,
                    $_.CheckpointCount,
                    $_.DifferencingDiskCount,
                    $_.ChainState,
                    $_.AllocatedBytes,
                    $_.RecoveryEvidenceHash
                ) -join ','
            }
    )
    $record = @(
        $Preflight.ContractVersion,
        $Preflight.ObservedAtUtc,
        $Preflight.StateEpoch,
        $Preflight.AssetId,
        $Preflight.Name,
        $Preflight.ReservationId,
        $Preflight.AssetCollisionCount,
        $Preflight.NameCollisionCount,
        $Preflight.DiskIdentityCollisionCount,
        $Preflight.MaintenanceState,
        $Preflight.HostLogicalProcessorCount,
        $Preflight.HostProcessorReserveCount,
        $Preflight.NormalizedExistingProcessorCount,
        $Preflight.PendingProcessorReservationCount,
        $Preflight.HostMemoryCapacityMiB,
        $Preflight.HostMemoryReserveMiB,
        $Preflight.NormalizedExistingMemoryMiB,
        $Preflight.PendingMemoryReservationMiB,
        ($memoryRecords -join ';'),
        $Preflight.StorageProfileRef,
        $Preflight.StorageResourceId,
        $Preflight.StorageFreeBytes,
        $Preflight.StorageReserveBytes,
        $Preflight.PendingStorageReservationBytes,
        $Preflight.NormalizedExistingStorageBytes,
        ($storageRecords -join ';'),
        $Preflight.ImageRef,
        $Preflight.ImageResourceId,
        $Preflight.ImageArtifactBytes,
        $Preflight.ImageArtifactSha256,
        $Preflight.ImageArtifactState,
        $Preflight.NetworkProfileRef,
        $Preflight.NetworkResourceId,
        $Preflight.NetworkFingerprint,
        $Preflight.NetworkState,
        $Preflight.FirmwareProfileRef,
        $Preflight.BootstrapProfileRef,
        $Preflight.BootstrapArtifactHash,
        $Preflight.RecoveryProfileRef,
        $Preflight.RecoveryRouteHash
    ) -join '|'
    return (Get-NgvfSha256Hex -Value $record)
}

function Assert-NgvfMemoryEvidence {
    param([Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight)

    $expectedProperties = @(
        'VmIdentityHash', 'DynamicMemoryEnabled', 'StartupMemoryMiB', 'MaximumMemoryMiB',
        'AssignedMemoryMiB', 'NormalizedReservationMiB'
    )
    $identities = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    [long]$sum = 0
    foreach ($item in @($Preflight.VmMemoryEvidence)) {
        Assert-NgvfExactTypeAndProperties -InputObject $item `
            -TypeName 'NorthGateHostAdapterVmMemoryEvidence' -Properties $expectedProperties `
            -Code 'NGVF-ADAPTER-MEMORY-EVIDENCE-INVALID'
        Assert-NgvfHexHash -Value $item.VmIdentityHash -Code 'NGVF-ADAPTER-MEMORY-EVIDENCE-INVALID'
        if (-not $identities.Add($item.VmIdentityHash) -or
            $item.StartupMemoryMiB -lt 1 -or $item.MaximumMemoryMiB -lt $item.StartupMemoryMiB -or
            $item.AssignedMemoryMiB -lt 0 -or
            ($item.DynamicMemoryEnabled -and $item.AssignedMemoryMiB -gt $item.MaximumMemoryMiB)) {
            Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MEMORY-EVIDENCE-INVALID'
        }
        $expectedReservation = if ($item.DynamicMemoryEnabled) {
            $item.MaximumMemoryMiB
        }
        else {
            # Hyper-V may report a meaningless 1 TiB Maximum for static VMs.
            $item.StartupMemoryMiB
        }
        if ($item.NormalizedReservationMiB -ne $expectedReservation) {
            Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MEMORY-NORMALIZATION-MISMATCH'
        }
        $sum += [long]$expectedReservation
    }
    if ($sum -ne $Preflight.NormalizedExistingMemoryMiB) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MEMORY-SUMMARY-MISMATCH'
    }
}

function Assert-NgvfStorageEvidence {
    param([Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight)

    $expectedProperties = @(
        'VmIdentityHash', 'CheckpointCount', 'DifferencingDiskCount', 'ChainState',
        'AllocatedBytes', 'RecoveryEvidenceHash'
    )
    $identities = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    [long]$sum = 0
    foreach ($item in @($Preflight.VmStorageEvidence)) {
        Assert-NgvfExactTypeAndProperties -InputObject $item `
            -TypeName 'NorthGateHostAdapterVmStorageEvidence' -Properties $expectedProperties `
            -Code 'NGVF-ADAPTER-STORAGE-EVIDENCE-INVALID'
        Assert-NgvfHexHash -Value $item.VmIdentityHash -Code 'NGVF-ADAPTER-STORAGE-EVIDENCE-INVALID'
        Assert-NgvfHexHash -Value $item.RecoveryEvidenceHash -Code 'NGVF-ADAPTER-RECOVERY-EVIDENCE-INVALID'
        if (-not $identities.Add($item.VmIdentityHash) -or
            $item.CheckpointCount -lt 0 -or $item.DifferencingDiskCount -lt 0 -or
            $item.AllocatedBytes -lt 0) {
            Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-STORAGE-EVIDENCE-INVALID'
        }
        if ($item.ChainState -ceq 'BaseOnly') {
            if ($item.CheckpointCount -ne 0 -or $item.DifferencingDiskCount -ne 0) {
                Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-DISK-CHAIN-AMBIGUOUS'
            }
        }
        elseif ($item.ChainState -ceq 'ValidatedDifferencing') {
            if ($item.CheckpointCount -lt 1 -or
                $item.DifferencingDiskCount -lt $item.CheckpointCount -or
                $item.AllocatedBytes -lt 1) {
                Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-DISK-CHAIN-AMBIGUOUS'
            }
        }
        else {
            Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-DISK-CHAIN-AMBIGUOUS'
        }
        $sum += $item.AllocatedBytes
    }
    if ($sum -ne $Preflight.NormalizedExistingStorageBytes) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-STORAGE-SUMMARY-MISMATCH'
    }
}

function Assert-NgvfPreflight {
    param(
        [Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight,
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation,
        [Parameter(Mandatory)][object]$Policy
    )

    Assert-NgvfExactTypeAndProperties -InputObject $Preflight `
        -TypeName 'NorthGateHostAdapterPreflight' -Properties @(
            'ContractVersion', 'ObservedAtUtc', 'StateEpoch', 'AssetId', 'Name', 'ReservationId',
            'AssetCollisionCount', 'NameCollisionCount', 'DiskIdentityCollisionCount', 'MaintenanceState',
            'HostLogicalProcessorCount', 'HostProcessorReserveCount', 'NormalizedExistingProcessorCount',
            'PendingProcessorReservationCount', 'HostMemoryCapacityMiB', 'HostMemoryReserveMiB',
            'NormalizedExistingMemoryMiB', 'PendingMemoryReservationMiB', 'VmMemoryEvidence',
            'StorageProfileRef', 'StorageResourceId', 'StorageFreeBytes', 'StorageReserveBytes',
            'PendingStorageReservationBytes', 'NormalizedExistingStorageBytes', 'VmStorageEvidence',
            'ImageRef', 'ImageResourceId', 'ImageArtifactBytes', 'ImageArtifactSha256', 'ImageArtifactState',
            'NetworkProfileRef', 'NetworkResourceId', 'NetworkFingerprint', 'NetworkState',
            'FirmwareProfileRef', 'BootstrapProfileRef', 'BootstrapArtifactHash',
            'RecoveryProfileRef', 'RecoveryRouteHash', 'NormalizedStateHash'
        ) -Code 'NGVF-ADAPTER-PREFLIGHT-TYPE-INVALID'

    if ($Preflight.ContractVersion -cne 'northgate-host-preflight/v1' -or $Preflight.StateEpoch -lt 1) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PREFLIGHT-CONTRACT-INVALID'
    }
    $observedAt = [System.DateTimeOffset]::MinValue
    if (-not [System.DateTimeOffset]::TryParseExact(
        $Preflight.ObservedAtUtc,
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$observedAt
    )) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PREFLIGHT-TIME-INVALID'
    }
    $ageSeconds = ([System.DateTimeOffset]::UtcNow - $observedAt.ToUniversalTime()).TotalSeconds
    if ($ageSeconds -lt -5 -or $ageSeconds -gt 300) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PREFLIGHT-STALE'
    }
    if ($Preflight.AssetId -cne $Operation.AssetId -or
        $Preflight.Name -cne $Operation.Name -or
        $Preflight.ReservationId -cne $Operation.ReservationId) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-IDENTITY-BINDING-MISMATCH'
    }
    if ($Preflight.AssetCollisionCount -ne 0 -or $Preflight.NameCollisionCount -ne 0 -or
        $Preflight.DiskIdentityCollisionCount -ne 0) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-IDENTITY-COLLISION'
    }
    if ($Preflight.MaintenanceState -cne 'Clear') {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MAINTENANCE-BLOCKED'
    }

    Assert-NgvfMemoryEvidence -Preflight $Preflight
    Assert-NgvfStorageEvidence -Preflight $Preflight

    if ($Preflight.HostMemoryReserveMiB -ne $Policy.HostMemoryReserveMiB -or
        $Preflight.HostProcessorReserveCount -ne $Policy.HostProcessorReserveCount -or
        $Preflight.StorageReserveBytes -ne $Policy.StorageReserveBytes) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-RESERVE-POLICY-MISMATCH'
    }
    [long]$requestedMemory = if ($Operation.MemoryMode -ceq 'Dynamic') {
        $Operation.MaximumMemoryMiB
    }
    else {
        $Operation.StartupMemoryMiB
    }
    if ($Preflight.HostMemoryCapacityMiB -lt 1 -or
        $Preflight.NormalizedExistingMemoryMiB -lt 0 -or
        $Preflight.PendingMemoryReservationMiB -lt 0 -or
        ($Preflight.NormalizedExistingMemoryMiB + $Preflight.PendingMemoryReservationMiB +
         $Preflight.HostMemoryReserveMiB + $requestedMemory) -gt $Preflight.HostMemoryCapacityMiB) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-MEMORY-CAPACITY-INSUFFICIENT'
    }
    if ($Preflight.HostLogicalProcessorCount -lt 1 -or
        $Preflight.NormalizedExistingProcessorCount -lt 0 -or
        $Preflight.PendingProcessorReservationCount -lt 0 -or
        ($Preflight.NormalizedExistingProcessorCount + $Preflight.PendingProcessorReservationCount +
         $Preflight.HostProcessorReserveCount + $Operation.Processors) -gt $Preflight.HostLogicalProcessorCount) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PROCESSOR-CAPACITY-INSUFFICIENT'
    }

    [long]$requestedDiskBytes = [long]$Operation.OsDiskGiB * [long](1GB)
    if ($Preflight.StorageFreeBytes -lt 0 -or $Preflight.PendingStorageReservationBytes -lt 0 -or
        ($Preflight.StorageReserveBytes + $Preflight.PendingStorageReservationBytes + $requestedDiskBytes) -gt
        $Preflight.StorageFreeBytes) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-STORAGE-CAPACITY-INSUFFICIENT'
    }
    if ($Preflight.StorageProfileRef -cne $Policy.Storage.ProfileRef -or
        $Preflight.StorageResourceId -cne $Policy.Storage.ResourceId) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-STORAGE-BINDING-MISMATCH'
    }
    if ($Preflight.ImageRef -cne $Policy.Image.ProfileRef -or
        $Preflight.ImageResourceId -cne $Policy.Image.ResourceId -or
        $Preflight.ImageArtifactBytes -ne $Policy.Image.ArtifactBytes -or
        $Preflight.ImageArtifactSha256 -cne $Policy.Image.ArtifactSha256 -or
        $Preflight.ImageArtifactState -cne 'ImmutableVerified') {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-IMAGE-HASH-MISMATCH'
    }
    if ($Preflight.NetworkProfileRef -cne $Policy.Network.ProfileRef -or
        $Preflight.NetworkResourceId -cne $Policy.Network.ResourceId -or
        $Preflight.NetworkFingerprint -cne $Policy.Network.Fingerprint -or
        $Preflight.NetworkState -cne 'ExistingExactMatch') {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-SWITCH-FINGERPRINT-MISMATCH'
    }
    if ($Preflight.FirmwareProfileRef -cne $Policy.Firmware.ProfileRef -or
        $Preflight.BootstrapProfileRef -cne $Policy.Bootstrap.ProfileRef -or
        $Preflight.BootstrapArtifactHash -cne $Policy.Bootstrap.ArtifactHash -or
        $Preflight.RecoveryProfileRef -cne $Policy.Recovery.ProfileRef -or
        $Preflight.RecoveryRouteHash -cne $Policy.Recovery.RouteHash) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PROFILE-BINDING-MISMATCH'
    }

    $normalizedHash = Get-NgvfNormalizedPreflightHash -Preflight $Preflight
    Assert-NgvfHexHash -Value $Preflight.NormalizedStateHash -Code 'NGVF-ADAPTER-PREFLIGHT-HASH-INVALID'
    if ($normalizedHash -cne $Preflight.NormalizedStateHash -or
        $normalizedHash -cne $Operation.ExpectedPreflightHash) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-PREFLIGHT-HASH-MISMATCH'
    }
}

function Enter-NgvfWriterLock {
    $lock = New-Object System.Threading.Semaphore(1, 1, $script:WriterLockName)
    if (-not $lock.WaitOne(0)) {
        $lock.Dispose()
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-WRITER-LOCK-BUSY'
    }
    return $lock
}

function Exit-NgvfWriterLock {
    param([Parameter(Mandatory)][System.Threading.Semaphore]$Lock)

    try { $null = $Lock.Release() }
    finally { $Lock.Dispose() }
}

function New-NgvfOutcome {
    param(
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Outcome,
        [Parameter(Mandatory)][string]$ReasonCode,
        [Parameter(Mandatory)][string]$VmId,
        [Parameter(Mandatory)][string]$AfterStateHash,
        [Parameter(Mandatory)][bool]$AfterStateVerified,
        [Parameter(Mandatory)][bool]$DestroyProtectionObserved,
        [Parameter(Mandatory)][string]$QuarantineState,
        [Parameter(Mandatory)][bool]$IdentityReuseBlocked,
        [Parameter(Mandatory)][bool]$ReconciliationRequired
    )

    $result = [NorthGateHostAdapterOutcome]::new()
    $result.AdapterVersion = $script:AdapterVersion
    $result.BackendIdentity = $script:InertBackendIdentity
    $result.Action = 'Create'
    $result.Status = $Status
    $result.Outcome = $Outcome
    $result.ReasonCode = $ReasonCode
    $result.AssetId = $Operation.AssetId
    $result.Name = $Operation.Name
    $result.ChangeId = $Operation.ChangeId
    $result.ReservationId = $Operation.ReservationId
    $result.VmId = $VmId
    $result.AfterStateHash = $AfterStateHash
    $result.AfterStateVerified = $AfterStateVerified
    $result.DestroyProtectionObserved = $DestroyProtectionObserved
    $result.QuarantineState = $QuarantineState
    $result.IdentityReuseBlocked = $IdentityReuseBlocked
    $result.ReconciliationRequired = $ReconciliationRequired
    return $result
}

function Assert-NgvfBackendResult {
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation
    )

    $actual = @($Result.PSObject.Properties.Name)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    $expected = @('Status', 'VmId', 'AfterStateHash', 'AfterStateVerified', 'DestroyProtectionObserved', 'IdentityTagsObserved')
    [array]::Sort($expected, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expected -join '|')) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-BACKEND-RESULT-INVALID'
    }
    if ($Result.Status -cnotin @('Created', 'Failed') -or
        $Result.VmId -isnot [string] -or $Result.AfterStateHash -isnot [string] -or
        $Result.AfterStateVerified -isnot [bool] -or $Result.DestroyProtectionObserved -isnot [bool] -or
        $Result.IdentityTagsObserved -isnot [bool]) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-BACKEND-RESULT-INVALID'
    }
    Assert-NgvfHexHash -Value $Result.AfterStateHash -Code 'NGVF-ADAPTER-BACKEND-RESULT-INVALID'
    if ($Result.Status -ceq 'Created') {
        $parsedVmId = [guid]::Empty
        if (-not [guid]::TryParse($Result.VmId, [ref]$parsedVmId) -or $parsedVmId -eq [guid]::Empty -or
            -not $Result.AfterStateVerified -or -not $Result.DestroyProtectionObserved -or
            -not $Result.IdentityTagsObserved -or -not $Operation.DestroyProtection) {
            Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-BACKEND-RESULT-INVALID'
        }
    }
    elseif ($Result.VmId -cne ([guid]::Empty.ToString()) -or $Result.AfterStateVerified) {
        Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-BACKEND-RESULT-INVALID'
    }
}

function Invoke-NgvfFixedInertBackend {
    param(
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation,
        [Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight,
        [Parameter(Mandatory)][ValidateSet('Success', 'ReportedFailure', 'Throw', 'Malformed')][string]$Scenario
    )

    $null = $Preflight
    $script:InertInvocationCount++
    if ($Scenario -ceq 'Throw') {
        Throw-NgvfAdapterError -Code 'NGVF-INERT-BACKEND-THROW'
    }
    if ($Scenario -ceq 'Malformed') {
        return [pscustomobject]@{ Status = 'Created' }
    }
    if ($Scenario -ceq 'ReportedFailure') {
        return [pscustomobject][ordered]@{
            Status = 'Failed'
            VmId = [guid]::Empty.ToString()
            AfterStateHash = Get-NgvfSha256Hex -Value ('failed|' + $Operation.AssetId + '|' + $Operation.ChangeId)
            AfterStateVerified = $false
            DestroyProtectionObserved = $false
            IdentityTagsObserved = $false
        }
    }

    $identityBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($Operation.AssetId + '|' + $Operation.ReservationId)
    )
    $guidBytes = New-Object byte[] 16
    [System.Array]::Copy($identityBytes, $guidBytes, 16)
    return [pscustomobject][ordered]@{
        Status = 'Created'
        VmId = ([guid]::new($guidBytes)).ToString()
        AfterStateHash = Get-NgvfSha256Hex -Value (
            'created|' + $Operation.AssetId + '|' + $Operation.ChangeId + '|' + $Operation.ExpectedPreflightHash
        )
        AfterStateVerified = $true
        DestroyProtectionObserved = $true
        IdentityTagsObserved = $true
    }
}

function Invoke-NgvfInertTestCreate {
    param(
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation,
        [Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight,
        [Parameter(Mandatory)][ValidateSet('Success', 'ReportedFailure', 'Throw', 'Malformed')][string]$Scenario
    )

    $lock = Enter-NgvfWriterLock
    try {
        $policy = Get-NgvfFixedPolicyBundle
        Assert-NgvfCreateOperation -Operation $Operation -Policy $policy
        Assert-NgvfPreflight -Preflight $Preflight -Operation $Operation -Policy $policy

        try {
            $backendResult = Invoke-NgvfFixedInertBackend -Operation $Operation -Preflight $Preflight -Scenario $Scenario
            Assert-NgvfBackendResult -Result $backendResult -Operation $Operation
        }
        catch {
            return (New-NgvfOutcome -Operation $Operation -Status 'OutcomeUnknown' -Outcome 'Unknown' `
                -ReasonCode 'NGVF-ADAPTER-OUTCOME-UNKNOWN' -VmId ([guid]::Empty.ToString()) `
                -AfterStateHash (Get-NgvfSha256Hex -Value ('unknown|' + $Operation.AssetId + '|' + $Operation.ChangeId)) `
                -AfterStateVerified $false -DestroyProtectionObserved $false -QuarantineState 'required' `
                -IdentityReuseBlocked $true -ReconciliationRequired $true)
        }

        if ($backendResult.Status -ceq 'Failed') {
            return (New-NgvfOutcome -Operation $Operation -Status 'Failed' -Outcome 'NotCreated' `
                -ReasonCode 'NGVF-ADAPTER-CREATE-FAILED' -VmId $backendResult.VmId `
                -AfterStateHash $backendResult.AfterStateHash -AfterStateVerified $false `
                -DestroyProtectionObserved $false -QuarantineState 'required' `
                -IdentityReuseBlocked $true -ReconciliationRequired $true)
        }

        return (New-NgvfOutcome -Operation $Operation -Status 'Succeeded' -Outcome 'Created' `
            -ReasonCode 'NGVF-ADAPTER-CREATE-VERIFIED' -VmId $backendResult.VmId `
            -AfterStateHash $backendResult.AfterStateHash -AfterStateVerified $true `
            -DestroyProtectionObserved $true -QuarantineState 'not-required' `
            -IdentityReuseBlocked $false -ReconciliationRequired $false)
    }
    finally {
        Exit-NgvfWriterLock -Lock $lock
    }
}

function Invoke-NgvfProductionCreate {
    param(
        [Parameter(Mandatory)][NorthGateHostAdapterCreateOperation]$Operation,
        [Parameter(Mandatory)][NorthGateHostAdapterPreflight]$Preflight
    )

    $null = $Operation
    $null = $Preflight
    Throw-NgvfAdapterError -Code 'NGVF-ADAPTER-NOT-INDEPENDENTLY-PROMOTED'
}

function New-NgvfInertTestFixture {
    $policy = Get-NgvfFixedPolicyBundle

    $memoryStatic = [NorthGateHostAdapterVmMemoryEvidence]::new()
    $memoryStatic.VmIdentityHash = ('1' * 64)
    $memoryStatic.DynamicMemoryEnabled = $false
    $memoryStatic.StartupMemoryMiB = 4096
    $memoryStatic.MaximumMemoryMiB = 1048576
    $memoryStatic.AssignedMemoryMiB = 4096
    $memoryStatic.NormalizedReservationMiB = 4096

    $memoryDynamic = [NorthGateHostAdapterVmMemoryEvidence]::new()
    $memoryDynamic.VmIdentityHash = ('2' * 64)
    $memoryDynamic.DynamicMemoryEnabled = $true
    $memoryDynamic.StartupMemoryMiB = 2048
    $memoryDynamic.MaximumMemoryMiB = 8192
    $memoryDynamic.AssignedMemoryMiB = 3072
    $memoryDynamic.NormalizedReservationMiB = 8192

    $storageBase = [NorthGateHostAdapterVmStorageEvidence]::new()
    $storageBase.VmIdentityHash = ('1' * 64)
    $storageBase.CheckpointCount = 0
    $storageBase.DifferencingDiskCount = 0
    $storageBase.ChainState = 'BaseOnly'
    $storageBase.AllocatedBytes = [long](20GB)
    $storageBase.RecoveryEvidenceHash = ('e' * 64)

    $storageCheckpoint = [NorthGateHostAdapterVmStorageEvidence]::new()
    $storageCheckpoint.VmIdentityHash = ('2' * 64)
    $storageCheckpoint.CheckpointCount = 1
    $storageCheckpoint.DifferencingDiskCount = 1
    $storageCheckpoint.ChainState = 'ValidatedDifferencing'
    $storageCheckpoint.AllocatedBytes = [long](24GB)
    $storageCheckpoint.RecoveryEvidenceHash = ('f' * 64)

    $preflight = [NorthGateHostAdapterPreflight]::new()
    $preflight.ContractVersion = 'northgate-host-preflight/v1'
    $preflight.ObservedAtUtc = [System.DateTimeOffset]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $preflight.StateEpoch = 1
    $preflight.AssetId = 'NG-VM-900'
    $preflight.Name = 'NG-P3-CANARY'
    $preflight.ReservationId = 'ngrsv-phase3-test-900'
    $preflight.AssetCollisionCount = 0
    $preflight.NameCollisionCount = 0
    $preflight.DiskIdentityCollisionCount = 0
    $preflight.MaintenanceState = 'Clear'
    $preflight.HostLogicalProcessorCount = 32
    $preflight.HostProcessorReserveCount = $policy.HostProcessorReserveCount
    $preflight.NormalizedExistingProcessorCount = 12
    $preflight.PendingProcessorReservationCount = 0
    $preflight.HostMemoryCapacityMiB = 65536
    $preflight.HostMemoryReserveMiB = $policy.HostMemoryReserveMiB
    $preflight.NormalizedExistingMemoryMiB = 12288
    $preflight.PendingMemoryReservationMiB = 0
    $preflight.VmMemoryEvidence = @($memoryStatic, $memoryDynamic)
    $preflight.StorageProfileRef = $policy.Storage.ProfileRef
    $preflight.StorageResourceId = $policy.Storage.ResourceId
    $preflight.StorageFreeBytes = [long](512GB)
    $preflight.StorageReserveBytes = $policy.StorageReserveBytes
    $preflight.PendingStorageReservationBytes = 0
    $preflight.NormalizedExistingStorageBytes = [long](44GB)
    $preflight.VmStorageEvidence = @($storageBase, $storageCheckpoint)
    $preflight.ImageRef = $policy.Image.ProfileRef
    $preflight.ImageResourceId = $policy.Image.ResourceId
    $preflight.ImageArtifactBytes = $policy.Image.ArtifactBytes
    $preflight.ImageArtifactSha256 = $policy.Image.ArtifactSha256
    $preflight.ImageArtifactState = 'ImmutableVerified'
    $preflight.NetworkProfileRef = $policy.Network.ProfileRef
    $preflight.NetworkResourceId = $policy.Network.ResourceId
    $preflight.NetworkFingerprint = $policy.Network.Fingerprint
    $preflight.NetworkState = 'ExistingExactMatch'
    $preflight.FirmwareProfileRef = $policy.Firmware.ProfileRef
    $preflight.BootstrapProfileRef = $policy.Bootstrap.ProfileRef
    $preflight.BootstrapArtifactHash = $policy.Bootstrap.ArtifactHash
    $preflight.RecoveryProfileRef = $policy.Recovery.ProfileRef
    $preflight.RecoveryRouteHash = $policy.Recovery.RouteHash
    $preflight.NormalizedStateHash = Get-NgvfNormalizedPreflightHash -Preflight $preflight

    $operation = [NorthGateHostAdapterCreateOperation]::new()
    $operation.Action = 'Create'
    $operation.AssetId = $preflight.AssetId
    $operation.Name = $preflight.Name
    $operation.ChangeId = 'NG-CHG-PHASE3-TEST-900'
    $operation.ReservationId = $preflight.ReservationId
    $operation.ImageRef = $policy.Image.ProfileRef
    $operation.ImageSha256 = $policy.Image.ArtifactSha256
    $operation.FirmwareProfileRef = $policy.Firmware.ProfileRef
    $operation.Generation = 2
    $operation.Processors = 2
    $operation.MemoryMode = 'Dynamic'
    $operation.MinimumMemoryMiB = 1024
    $operation.StartupMemoryMiB = 2048
    $operation.MaximumMemoryMiB = 4096
    $operation.StorageProfileRef = $policy.Storage.ProfileRef
    $operation.OsDiskGiB = 40
    $operation.NetworkProfileRef = $policy.Network.ProfileRef
    $operation.NetworkFingerprint = $policy.Network.Fingerprint
    $operation.BootstrapProfileRef = $policy.Bootstrap.ProfileRef
    $operation.RecoveryProfileRef = $policy.Recovery.ProfileRef
    $operation.DesiredPowerState = 'Off'
    $operation.DestroyProtection = $true
    $operation.ExpectedPolicyHash = $policy.PolicyHash
    $operation.ExpectedPreflightHash = $preflight.NormalizedStateHash

    return [pscustomobject][ordered]@{
        Operation = $operation
        Preflight = $preflight
        Policy = $policy
    }
}

function Get-NorthGateVmFactoryHostAdapterState {
    [CmdletBinding()]
    param()

    [pscustomobject][ordered]@{
        candidateVersion = $script:AdapterVersion
        releaseStatus = $script:ReleaseStatus
        deployed = $false
        independentlySignedInstalledRelease = $false
        productionInvocationEnabled = $script:ProductionInvocationEnabled
        routineInvocationExported = $false
        effectiveActions = @()
        implementedTestAction = 'Create'
        fixedBackend = $script:InertBackendIdentity
        generation = 2
        destroyProtectionRequired = $true
        writerLockContractHash = Get-NgvfSha256Hex -Value $script:WriterLockName
        outcomeUnknownRequiresQuarantine = $true
        identityReuseBlockedOnUnknown = $true
        reasonCode = 'NGVF-ADAPTER-NOT-INDEPENDENTLY-PROMOTED'
    }
}

Export-ModuleMember -Function 'Get-NorthGateVmFactoryHostAdapterState'
