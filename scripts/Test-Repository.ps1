[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$schemaValidationCount = 0
$negativeTestCount = 0

function ConvertFrom-RepositoryJsonText {
    param([Parameter(Mandatory)][string]$Json)

    $converter = Get-Command -Name 'Microsoft.PowerShell.Utility\ConvertFrom-Json' -ErrorAction Stop
    if ($converter.Parameters.ContainsKey('DateKind')) {
        return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json -DateKind String)
    }
    return (Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $Json)
}

function Test-IsUnderRepository {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $prefix = $repositoryRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$MaximumBytes = 1048576
    )

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -gt $MaximumBytes) {
        throw "JSON document exceeds the $MaximumBytes byte limit: $Path"
    }

    $raw = [System.IO.File]::ReadAllText($item.FullName)
    if ($raw -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
        throw "Unescaped control character detected in JSON: $Path"
    }

    $testJson = Get-Command Test-Json -ErrorAction SilentlyContinue
    if ($testJson) {
        if (-not (Test-Json -Json $raw -ErrorAction SilentlyContinue)) {
            throw "JSON is not strictly conformant: $Path"
        }
    }

    try {
        $object = ConvertFrom-RepositoryJsonText -Json $raw
    }
    catch {
        throw "Invalid JSON: $Path`n$($_.Exception.Message)"
    }

    $schemaProperty = $object.PSObject.Properties['$schema']
    if ($testJson -and $schemaProperty -and $schemaProperty.Value -is [string] -and $schemaProperty.Value.StartsWith('.')) {
        $schemaPath = [System.IO.Path]::GetFullPath((Join-Path $item.DirectoryName $schemaProperty.Value))
        if (-not (Test-IsUnderRepository -Path $schemaPath) -or -not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
            throw "Local schema reference escapes the repository or does not exist: $Path"
        }
        if (-not (Test-Json -Json $raw -SchemaFile $schemaPath -ErrorAction SilentlyContinue)) {
            throw "JSON Schema validation failed: $Path"
        }
        $script:schemaValidationCount++
    }

    return $object
}

function Get-DuplicateValues {
    param([object[]]$Values)

    return @(
        $Values |
            Where-Object { $null -ne $_ } |
            Group-Object -Property { ([string]$_).ToUpperInvariant() } |
            Where-Object Count -gt 1 |
            Select-Object -ExpandProperty Name
    )
}

function Get-CatalogProfile {
    param(
        [Parameter(Mandatory)][object]$Catalog,
        [Parameter(Mandatory)][string]$Id,
        [string]$RequiredStatus = 'approved'
    )

    return @($Catalog.profiles | Where-Object { $_.id -ieq $Id -and $_.approvalStatus -eq $RequiredStatus })
}

function Test-CatalogIdentities {
    param(
        [Parameter(Mandatory)][object]$Catalog,
        [Parameter(Mandatory)][string]$Name
    )

    $duplicateIds = Get-DuplicateValues -Values @($Catalog.profiles.id)
    $duplicateServerIds = Get-DuplicateValues -Values @($Catalog.profiles.serverPolicyId)
    if ($duplicateIds.Count -or $duplicateServerIds.Count) {
        throw "$Name catalog identifiers must be case-insensitively unique. Ids=[$($duplicateIds -join ',')], ServerPolicyIds=[$($duplicateServerIds -join ',')]"
    }
}

function Assert-ExactPropertySet {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$ExpectedProperties,
        [Parameter(Mandatory)][string]$Location
    )

    $actual = @($InputObject.PSObject.Properties.Name | Sort-Object)
    $expected = @($ExpectedProperties | Sort-Object)
    if (($actual -join '|') -cne ($expected -join '|')) {
        throw "$Location must contain exactly [$($expected -join ', ')]."
    }
}

function Assert-PlanOnlyResourcePolicy {
    param([Parameter(Mandatory)][object]$Policy)

    if ($Policy.applyEnabled -ne $false -or $Policy.status -ne 'proposed' -or @($Policy.executableActions).Count -ne 0) {
        throw 'Resource policy must remain proposed with applyEnabled=false and no executable actions.'
    }
}

function Assert-CanaryExecutionStageProposal {
    param([Parameter(Mandatory)][object]$Stage)

    Assert-ExactPropertySet -InputObject $Stage -ExpectedProperties @(
        '$schema', 'apiVersion', 'kind', 'stageVersion', 'status', 'effectiveState', 'proposedStage'
    ) -Location 'Canary execution-stage proposal'
    Assert-ExactPropertySet -InputObject $Stage.effectiveState -ExpectedProperties @(
        'applyEnabled', 'executableActions'
    ) -Location 'Canary effective state'
    Assert-ExactPropertySet -InputObject $Stage.proposedStage -ExpectedProperties @(
        'activationMode',
        'authorizationClass',
        'requestKind',
        'plannerAction',
        'maximumConcurrent',
        'normalVirtualMachineManifestsAllowed',
        'requestMaySharePromotion',
        'requiredGates'
    ) -Location 'Proposed canary stage'

    if ($Stage.'$schema' -cne '../schemas/canary-execution-stage.schema.json' -or
        $Stage.apiVersion -cne 'northgate/v1alpha1' -or
        $Stage.kind -cne 'CanaryExecutionStageProposal' -or
        $Stage.status -cne 'proposed') {
        throw 'Only the proposed CanaryExecutionStageProposal contract is permitted.'
    }
    if ($Stage.stageVersion -cnotmatch '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$') {
        throw 'Canary execution-stage version is invalid.'
    }
    if ($Stage.effectiveState.applyEnabled -ne $false -or @($Stage.effectiveState.executableActions).Count -ne 0) {
        throw 'The canary proposal is non-operative: effective apply must be false and effective actions empty.'
    }

    $proposal = $Stage.proposedStage
    if ($proposal.activationMode -cne 'separate-reviewed-change' -or
        $proposal.authorizationClass -cne 'disposable-canary-only' -or
        $proposal.requestKind -cne 'DisposableCanaryRequest' -or
        $proposal.plannerAction -cne 'Create' -or
        $proposal.maximumConcurrent -ne 1 -or
        $proposal.normalVirtualMachineManifestsAllowed -ne $false -or
        $proposal.requestMaySharePromotion -ne $false) {
        throw 'The proposed stage must remain a separate, single disposable-canary Create path that rejects normal VM manifests.'
    }

    $expectedGates = @(
        'control-plane-negative-tests-passed',
        'installed-canary-policy-promoted',
        'immutable-canary-image-promoted',
        'opaque-profiles-approved',
        'identity-ledger-reservation',
        'host-issued-plan-registered',
        'exact-plan-human-approval',
        'quarantine-route-proven',
        'signed-receipt-ready'
    )
    if ((@($proposal.requiredGates) -join '|') -cne ($expectedGates -join '|')) {
        throw 'The proposed canary stage gate set was changed from the reviewed fail-closed contract.'
    }
}

function Assert-ControlPlaneCandidateProposal {
    param([Parameter(Mandatory)][object]$Candidate)

    Assert-ExactPropertySet -InputObject $Candidate -ExpectedProperties @(
        '$schema', 'apiVersion', 'kind', 'candidateVersion', 'status', 'effectiveState', 'interface', 'promotion'
    ) -Location 'Control-plane candidate proposal'
    Assert-ExactPropertySet -InputObject $Candidate.effectiveState -ExpectedProperties @(
        'deployed',
        'applicationAuthenticationConfigured',
        'planRegistrationEnabled',
        'applyEnabled',
        'executableActions',
        'writerLockConfigured',
        'receiptSigningConfigured',
        'directMutationMethodsExposed'
    ) -Location 'Control-plane candidate effective state'
    Assert-ExactPropertySet -InputObject $Candidate.interface -ExpectedProperties @(
        'stateOperation', 'registerOperation', 'getPlanOperation', 'applyOperation', 'applyInputFields'
    ) -Location 'Control-plane candidate interface'
    Assert-ExactPropertySet -InputObject $Candidate.promotion -ExpectedProperties @(
        'repositorySourceMayExecuteOnHost',
        'installedSignedReleaseRequired',
        'separateReviewedChangeRequired',
        'requiredGates'
    ) -Location 'Control-plane candidate promotion policy'

    if ($Candidate.'$schema' -cne '../../schemas/control-plane-candidate.schema.json' -or
        $Candidate.apiVersion -cne 'northgate/v1alpha1' -or
        $Candidate.kind -cne 'VmFactoryControlPlaneCandidate' -or
        $Candidate.status -cne 'proposed' -or
        $Candidate.candidateVersion -cnotmatch '^0\.[0-9]+\.[0-9]+$') {
        throw 'Only a proposed pre-1.0 control-plane candidate contract is permitted.'
    }

    $state = $Candidate.effectiveState
    if ($state.deployed -ne $false -or
        $state.applicationAuthenticationConfigured -ne $false -or
        $state.planRegistrationEnabled -ne $false -or
        $state.applyEnabled -ne $false -or
        @($state.executableActions).Count -ne 0 -or
        $state.writerLockConfigured -ne $false -or
        $state.receiptSigningConfigured -ne $false -or
        $state.directMutationMethodsExposed -ne $false) {
        throw 'The repository control-plane candidate must remain undeployed, unconfigured, and non-operative.'
    }

    $interface = $Candidate.interface
    if ($interface.stateOperation -cne 'vm_factory_get_state' -or
        $interface.registerOperation -cne 'vm_factory_register_plan' -or
        $interface.getPlanOperation -cne 'vm_factory_get_plan' -or
        $interface.applyOperation -cne 'vm_factory_apply_plan' -or
        (@($interface.applyInputFields) -join '|') -cne 'planId') {
        throw 'The candidate interface must remain the four typed factory operations with plan-ID-only apply.'
    }

    $promotion = $Candidate.promotion
    if ($promotion.repositorySourceMayExecuteOnHost -ne $false -or
        $promotion.installedSignedReleaseRequired -ne $true -or
        $promotion.separateReviewedChangeRequired -ne $true) {
        throw 'Repository source must not become an installed or activated control-plane release.'
    }
    $expectedGates = @(
        'restrictive-acls-proven',
        'immutable-signed-release-promoted',
        'forwarding-only-identity-proven',
        'application-authentication-proven',
        'data-only-fetcher-proven',
        'protected-branch-reachability-proven',
        'strict-plan-validation-proven',
        'identity-ledger-proven',
        'host-writer-lock-proven',
        'audit-fail-closed-proven',
        'receipt-signing-proven',
        'rollback-tested',
        'direct-mutators-disabled'
    )
    if ((@($promotion.requiredGates) -join '|') -cne ($expectedGates -join '|')) {
        throw 'The control-plane candidate promotion gate set was changed from the fail-closed contract.'
    }
}

function Assert-ImageCatalogSafety {
    param([Parameter(Mandatory)][object]$Catalog)

    if ($Catalog.promotedOnly -ne $true -or $Catalog.status -notin @('inventory-required', 'active')) {
        throw 'The image catalog must permit manifest consumption only from promoted image records.'
    }

    foreach ($image in @($Catalog.images)) {
        switch ($image.approvalStatus) {
            'proposed' {
                if ($image.retirementStatus -cne 'proposed') {
                    throw "Proposed image '$($image.id)' must remain non-consumable."
                }
            }
            'promoted' {
                if ($image.retirementStatus -cne 'active' -or
                    $image.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                    $null -eq $image.sizeBytes -or
                    [int64]$image.sizeBytes -lt 1) {
                    throw "Promoted image '$($image.id)' lacks immutable active artifact evidence."
                }
            }
            'rejected' {
                if ($image.retirementStatus -cne 'retired') {
                    throw "Rejected image '$($image.id)' must remain retired."
                }
            }
            default {
                throw "Unknown image approval state for '$($image.id)'."
            }
        }
    }

    if ($Catalog.status -ceq 'inventory-required' -and
        @($Catalog.images | Where-Object { $_.approvalStatus -eq 'promoted' }).Count -gt 0) {
        throw 'An inventory-required image catalog may not contain promoted images.'
    }
}

function Assert-WorkloadProvisioningProposal {
    param([Parameter(Mandatory)][object]$Proposal)

    Assert-ExactPropertySet -InputObject $Proposal -ExpectedProperties @(
        '$schema', 'apiVersion', 'kind', 'proposalVersion', 'status', 'execution', 'governance',
        'catalogPromotion', 'promotionSequence', 'workloads'
    ) -Location 'Workload provisioning proposal'
    Assert-ExactPropertySet -InputObject $Proposal.execution -ExpectedProperties @(
        'deployable', 'hostPlanRequired', 'standardManifestsIncluded',
        'resourcePolicyMustRemainDisabled', 'promotionMode'
    ) -Location 'Workload proposal execution boundary'
    Assert-ExactPropertySet -InputObject $Proposal.governance -ExpectedProperties @(
        'assetIdentityState', 'changeReferenceState', 'catalogState', 'applicationReleaseState'
    ) -Location 'Workload proposal governance state'
    Assert-ExactPropertySet -InputObject $Proposal.catalogPromotion -ExpectedProperties @(
        'imageRef', 'firmwareProfileRef', 'storageProfileRef', 'recoveryProfileRef',
        'accessProfileRef', 'networkProfileRefs', 'bootstrapProfileRefs'
    ) -Location 'Workload proposal catalog bundle'

    if ($Proposal.'$schema' -cne '../schemas/workload-provisioning-proposal.schema.json' -or
        $Proposal.apiVersion -cne 'northgate/v1alpha1' -or
        $Proposal.kind -cne 'WorkloadProvisioningProposal' -or
        $Proposal.status -cne 'proposed' -or
        $Proposal.proposalVersion -cnotmatch '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$') {
        throw 'Only the proposed workload provisioning contract is permitted.'
    }

    $execution = $Proposal.execution
    if ($execution.deployable -ne $false -or
        $execution.hostPlanRequired -ne $true -or
        $execution.standardManifestsIncluded -ne $false -or
        $execution.resourcePolicyMustRemainDisabled -ne $true -or
        $execution.promotionMode -cne 'separate-reviewed-stages') {
        throw 'The workload proposal must remain non-deployable and separated from manifests and host-issued plans.'
    }

    if ($Proposal.governance.assetIdentityState -cne 'candidate-unreserved' -or
        $Proposal.governance.changeReferenceState -cne 'required-before-manifest' -or
        $Proposal.governance.catalogState -cne 'proposed' -or
        $Proposal.governance.applicationReleaseState -cne 'external-promotion-required') {
        throw 'The workload proposal may not claim identity, catalog, change, or application-release approval.'
    }

    $expectedSequence = @(
        'catalog-and-fabric-policy',
        'employee-hub-manifest',
        'employee-hub-host-plan',
        'sentinel-atlas-manifest',
        'sentinel-atlas-host-plan'
    )
    if ((@($Proposal.promotionSequence) -join '|') -cne ($expectedSequence -join '|')) {
        throw 'Catalog/fabric promotion and each first workload must remain separate promotion and plan units.'
    }

    if (@($Proposal.workloads).Count -ne 2) {
        throw 'The Aegis proposal must contain exactly the two reviewed workload candidates.'
    }
    $assetIds = @($Proposal.workloads.assetId)
    $names = @($Proposal.workloads.name)
    if ((Get-DuplicateValues -Values $assetIds).Count -or (Get-DuplicateValues -Values $names).Count) {
        throw 'Proposed workload identities must be unique.'
    }

    foreach ($workload in @($Proposal.workloads)) {
        Assert-ExactPropertySet -InputObject $workload -ExpectedProperties @(
            'assetId', 'name', 'ownerRef', 'purpose', 'environment', 'criticality',
            'dataClassification', 'lifecycle', 'reviewOrRetirementDate', 'dependencies',
            'imageRef', 'firmwareProfileRef', 'processors', 'memory', 'storageProfileRef',
            'osDiskGiB', 'networkProfileRef', 'bootstrapProfileRef', 'recoveryProfileRef',
            'accessProfileRef', 'desiredPowerState', 'destroyProtection'
        ) -Location "Workload proposal '$($workload.assetId)'"
        Assert-ExactPropertySet -InputObject $workload.memory -ExpectedProperties @(
            'mode', 'minimumMiB', 'startupMiB', 'maximumMiB'
        ) -Location "Workload proposal '$($workload.assetId)' memory"
        if ($workload.lifecycle -cne 'proposed' -or $workload.destroyProtection -ne $true) {
            throw "Workload proposal '$($workload.assetId)' must remain proposed and destroy-protected."
        }
        if ($workload.assetId -in @($workload.dependencies)) {
            throw "Workload proposal '$($workload.assetId)' cannot depend on itself."
        }
        if (-not ($workload.memory.minimumMiB -le $workload.memory.startupMiB -and
            $workload.memory.startupMiB -le $workload.memory.maximumMiB)) {
            throw "Workload proposal '$($workload.assetId)' has an invalid dynamic-memory range."
        }
    }

    Test-ForbiddenManifestData -InputObject $Proposal
}

function Assert-FullFleetProvisioningProposal {
    param([Parameter(Mandatory)][object]$Proposal)

    Assert-ExactPropertySet -InputObject $Proposal -ExpectedProperties @(
        '$schema', 'apiVersion', 'kind', 'proposalVersion', 'status', 'execution', 'governance',
        'blockingFindings', 'catalogPromotion', 'capacity', 'rollout', 'workloads'
    ) -Location 'Full-fleet provisioning proposal'
    Assert-ExactPropertySet -InputObject $Proposal.execution -ExpectedProperties @(
        'deployable', 'hostPlanRequired', 'standardManifestsIncluded',
        'resourcePolicyMustRemainDisabled', 'promotionMode', 'overallState'
    ) -Location 'Full-fleet execution boundary'
    Assert-ExactPropertySet -InputObject $Proposal.governance -ExpectedProperties @(
        'assetIdentityState', 'addressReservationState', 'dnsRegistrationState',
        'catalogState', 'changeReferenceState'
    ) -Location 'Full-fleet governance state'
    Assert-ExactPropertySet -InputObject $Proposal.catalogPromotion -ExpectedProperties @(
        'candidateImageRefs', 'blockedImageRefs', 'firmwareProfileRefs', 'storageProfileRefs',
        'networkProfileRefs', 'bootstrapProfileRefs', 'recoveryProfileRefs', 'accessProfileRefs'
    ) -Location 'Full-fleet catalog bundle'
    Assert-ExactPropertySet -InputObject $Proposal.capacity -ExpectedProperties @(
        'persistentFleet', 'largestDisposableCanary', 'policyHostReserveMemoryMiB',
        'configuredMaximumReductionMiB', 'reserveMarginMiBAtLastRead',
        'assessmentState', 'liveRevalidationRequired'
    ) -Location 'Full-fleet capacity gate'
    Assert-ExactPropertySet -InputObject $Proposal.capacity.persistentFleet -ExpectedProperties @(
        'processors', 'startupMemoryMiB', 'maximumMemoryMiB', 'osDiskGiB'
    ) -Location 'Persistent-fleet capacity totals'
    Assert-ExactPropertySet -InputObject $Proposal.capacity.largestDisposableCanary -ExpectedProperties @(
        'processors', 'startupMemoryMiB', 'maximumMemoryMiB', 'osDiskGiB'
    ) -Location 'Disposable-canary capacity envelope'
    Assert-ExactPropertySet -InputObject $Proposal.rollout -ExpectedProperties @(
        'maximumConcurrentCanaries', 'canariesRetiredBeforePersistentCompletion', 'orderedAssetIds'
    ) -Location 'Full-fleet rollout'

    if ($Proposal.'$schema' -cne '../schemas/full-fleet-provisioning-proposal.schema.json' -or
        $Proposal.apiVersion -cne 'northgate/v1alpha1' -or
        $Proposal.kind -cne 'FullFleetProvisioningProposal' -or
        $Proposal.status -cne 'proposed' -or
        $Proposal.proposalVersion -cnotmatch '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$') {
        throw 'Only the proposed full-fleet provisioning contract is permitted.'
    }

    $execution = $Proposal.execution
    if ($execution.deployable -ne $false -or
        $execution.hostPlanRequired -ne $true -or
        $execution.standardManifestsIncluded -ne $false -or
        $execution.resourcePolicyMustRemainDisabled -ne $true -or
        $execution.promotionMode -cne 'separate-reviewed-stages' -or
        $execution.overallState -cne 'blocked') {
        throw 'The full-fleet proposal must remain blocked, non-deployable, and separate from standard manifests and plans.'
    }

    if ($Proposal.governance.assetIdentityState -cne 'candidate-unreserved' -or
        $Proposal.governance.addressReservationState -cne 'proposed-unallocated' -or
        $Proposal.governance.dnsRegistrationState -cne 'proposed-unregistered' -or
        $Proposal.governance.catalogState -cne 'proposed' -or
        $Proposal.governance.changeReferenceState -cne 'required-before-manifest') {
        throw 'The full-fleet proposal may not claim identity, address, DNS, catalog, or change approval.'
    }

    $expectedOrder = @(
        'NG-VM-018',
        'NG-VM-010',
        'NG-VM-019',
        'NG-VM-020',
        'NG-VM-011',
        'NG-VM-012',
        'NG-VM-013',
        'NG-VM-014',
        'NG-VM-015',
        'NG-VM-016',
        'NG-VM-017',
        'NG-VM-021'
    )
    if ($Proposal.rollout.maximumConcurrentCanaries -ne 1 -or
        $Proposal.rollout.canariesRetiredBeforePersistentCompletion -ne $true -or
        (@($Proposal.rollout.orderedAssetIds) -join '|') -cne ($expectedOrder -join '|')) {
        throw 'The full-fleet rollout must remain serialized, Debian-canary first, and retire canaries before persistent completion.'
    }

    if (@($Proposal.workloads).Count -ne 12 -or
        (@($Proposal.workloads.assetId) -join '|') -cne ($expectedOrder -join '|')) {
        throw 'The full-fleet proposal must contain exactly the twelve reviewed candidate identities in rollout order.'
    }
    if ((Get-DuplicateValues -Values @($Proposal.workloads.assetId)).Count -or
        (Get-DuplicateValues -Values @($Proposal.workloads.name)).Count) {
        throw 'Full-fleet candidate identities and names must be unique.'
    }

    $requiredBlockers = @(
        'control-plane-not-promoted',
        'protected-branch-unavailable',
        'prerequisite-profiles-unpromoted',
        'identities-and-change-unapproved',
        'network-reservations-unallocated',
        'standard-manifests-not-authored'
    )
    $findingIds = @($Proposal.blockingFindings.id)
    if ((Get-DuplicateValues -Values $findingIds).Count -or
        (@($requiredBlockers | Where-Object { $_ -notin $findingIds }).Count -ne 0)) {
        throw 'The full-fleet proposal must retain every reviewed blocking finding exactly once.'
    }
    foreach ($finding in @($Proposal.blockingFindings)) {
        Assert-ExactPropertySet -InputObject $finding -ExpectedProperties @(
            'id', 'state', 'resolutionClass'
        ) -Location "Full-fleet blocker '$($finding.id)'"
        if ($finding.state -cne 'blocked') {
            throw "Full-fleet blocker '$($finding.id)' may not be marked ready."
        }
    }

    foreach ($workload in @($Proposal.workloads)) {
        Assert-ExactPropertySet -InputObject $workload -ExpectedProperties @(
            'assetId', 'name', 'deploymentClass', 'ownerRef', 'purpose', 'environment',
            'criticality', 'dataClassification', 'lifecycle', 'reviewOrRetirementDate',
            'dependencies', 'imageRef', 'imageState', 'firmwareProfileRef', 'processors',
            'memory', 'storageProfileRef', 'osDiskGiB', 'networkProfileRef',
            'bootstrapProfileRef', 'recoveryProfileRef', 'accessProfileRef',
            'desiredPowerState', 'destroyProtection', 'readinessState', 'blockingFindingRefs'
        ) -Location "Full-fleet workload '$($workload.assetId)'"
        Assert-ExactPropertySet -InputObject $workload.memory -ExpectedProperties @(
            'mode', 'minimumMiB', 'startupMiB', 'maximumMiB'
        ) -Location "Full-fleet workload '$($workload.assetId)' memory"
        if ($workload.lifecycle -cne 'proposed' -or
            $workload.destroyProtection -ne $true -or
            $workload.readinessState -cne 'blocked') {
            throw "Full-fleet workload '$($workload.assetId)' must remain proposed, blocked, and destroy-protected."
        }
        if ($workload.assetId -in @($workload.dependencies) -or
            @($workload.dependencies | Where-Object { $_ -notin $expectedOrder }).Count -ne 0) {
            throw "Full-fleet workload '$($workload.assetId)' has an invalid dependency."
        }
        if (-not ($workload.memory.minimumMiB -le $workload.memory.startupMiB -and
            $workload.memory.startupMiB -le $workload.memory.maximumMiB)) {
            throw "Full-fleet workload '$($workload.assetId)' has an invalid dynamic-memory range."
        }
        if (@($workload.blockingFindingRefs | Where-Object { $_ -notin $findingIds }).Count -ne 0) {
            throw "Full-fleet workload '$($workload.assetId)' cites an unknown blocking finding."
        }
        foreach ($commonBlocker in @('control-plane-not-promoted', 'protected-branch-unavailable', 'prerequisite-profiles-unpromoted', 'identities-and-change-unapproved', 'network-reservations-unallocated')) {
            if ($commonBlocker -notin @($workload.blockingFindingRefs)) {
                throw "Full-fleet workload '$($workload.assetId)' omits common blocker '$commonBlocker'."
            }
        }
    }

    $canaries = @($Proposal.workloads | Where-Object { $_.deploymentClass -eq 'disposable-canary' })
    $persistent = @($Proposal.workloads | Where-Object { $_.deploymentClass -eq 'persistent' })
    if ($canaries.Count -ne 2 -or $persistent.Count -ne 10) {
        throw 'The full fleet must remain two disposable canaries and ten persistent workloads.'
    }

    $persistentTotals = [ordered]@{
        processors = [int](($persistent | Measure-Object -Property processors -Sum).Sum)
        startupMemoryMiB = [int](($persistent.memory | Measure-Object -Property startupMiB -Sum).Sum)
        maximumMemoryMiB = [int](($persistent.memory | Measure-Object -Property maximumMiB -Sum).Sum)
        osDiskGiB = [int](($persistent | Measure-Object -Property osDiskGiB -Sum).Sum)
    }
    foreach ($property in @('processors', 'startupMemoryMiB', 'maximumMemoryMiB', 'osDiskGiB')) {
        if ([int]$Proposal.capacity.persistentFleet.$property -ne [int]$persistentTotals.$property) {
            throw "Full-fleet persistent capacity total '$property' does not match its workloads."
        }
    }

    $largestCanary = [ordered]@{
        processors = [int](($canaries | Measure-Object -Property processors -Maximum).Maximum)
        startupMemoryMiB = [int](($canaries.memory | Measure-Object -Property startupMiB -Maximum).Maximum)
        maximumMemoryMiB = [int](($canaries.memory | Measure-Object -Property maximumMiB -Maximum).Maximum)
        osDiskGiB = [int](($canaries | Measure-Object -Property osDiskGiB -Maximum).Maximum)
    }
    foreach ($property in @('processors', 'startupMemoryMiB', 'maximumMemoryMiB', 'osDiskGiB')) {
        if ([int]$Proposal.capacity.largestDisposableCanary.$property -ne [int]$largestCanary.$property) {
            throw "Full-fleet disposable-canary capacity value '$property' does not match the largest canary."
        }
    }

    $originalPersistentMaximumMiB = 106496
    $minimumReductionMiBAtLastRead = 8448
    $derivedReductionMiB = $originalPersistentMaximumMiB - [int]$Proposal.capacity.persistentFleet.maximumMemoryMiB
    $derivedReserveMarginMiB = $derivedReductionMiB - $minimumReductionMiBAtLastRead
    if ($Proposal.capacity.assessmentState -cne 'clear-at-last-read-reduced-maxima' -or
        $Proposal.capacity.liveRevalidationRequired -ne $true -or
        [int]$Proposal.capacity.configuredMaximumReductionMiB -ne $derivedReductionMiB -or
        [int]$Proposal.capacity.configuredMaximumReductionMiB -lt $minimumReductionMiBAtLastRead -or
        ([int]$Proposal.capacity.configuredMaximumReductionMiB % 128) -ne 0 -or
        [int]$Proposal.capacity.reserveMarginMiBAtLastRead -ne $derivedReserveMarginMiB -or
        [int]$Proposal.capacity.reserveMarginMiBAtLastRead -lt 128 -or
        ([int]$Proposal.capacity.reserveMarginMiBAtLastRead % 128) -ne 0) {
        throw 'The full-fleet reduced maximum-memory envelope must retain a positive reserve margin and require fresh live revalidation.'
    }

    $kali = @($Proposal.workloads | Where-Object { $_.assetId -ceq 'NG-VM-021' })
    if ($kali.Count -ne 1 -or
        $kali[0].imageRef -cne 'kali-2026.2-installer-netinst-amd64' -or
        $kali[0].imageState -cne 'candidate-unpromoted') {
        throw 'The Kali workload must remain bound to the exact non-consumable verified-image candidate.'
    }
    foreach ($workload in @($Proposal.workloads)) {
        if ($workload.imageState -cne 'candidate-unpromoted') {
            throw "Workload '$($workload.assetId)' must use a non-consumable candidate image."
        }
    }

    Test-ForbiddenManifestData -InputObject $Proposal
}

function Assert-MutationRejected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Baseline,
        [Parameter(Mandatory)][scriptblock]$Mutate,
        [Parameter(Mandatory)][scriptblock]$Assert
    )

    $candidateJson = $Baseline | ConvertTo-Json -Depth 20
    $candidate = ConvertFrom-RepositoryJsonText -Json $candidateJson
    & $Mutate $candidate
    $rejected = $false
    try {
        & $Assert $candidate
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Negative policy test '$Name' did not fail closed."
    }
    $script:negativeTestCount++
}

function Test-ForbiddenManifestData {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [string]$Location = '$',
        [string]$PropertyName = ''
    )

    if ($null -eq $InputObject) {
        throw "Null is not permitted in a manifest at $Location"
    }

    if ($InputObject -is [string]) {
        if ($PropertyName -ne '$schema') {
            if ($InputObject -match '(?i)(^[a-z]:[\\/]|^\\\\|^//|^\\\\[?.]\\|(^|[\\/])\.\.([\\/]|$)|^(file|https?|smb|ssh)://|%[a-z_][a-z0-9_]*%|\$\{?[a-z_][a-z0-9_]*\}?|\*)') {
                throw "Path-, URI-, environment-, or wildcard-shaped data is forbidden at $Location"
            }
            if ($InputObject -match '(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|\b[A-Za-z0-9+/]{80,}={0,2}\b)') {
                throw "Secret-like content is forbidden at $Location"
            }
        }
        return
    }

    if ($InputObject -is [ValueType]) {
        return
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        $index = 0
        foreach ($item in $InputObject) {
            Test-ForbiddenManifestData -InputObject $item -Location "$Location[$index]"
            $index++
        }
        return
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Name -match '(?i)(password|secret|token|credential|private.?key|api.?key|connection.?string|sas|unattend|domain.?join|command|script|raw.?path|switch.?name|vlan|mac.?address|ip.?address|uri|url|hyper.?v.?vm.?id)') {
            throw "Forbidden manifest property '$($property.Name)' at $Location"
        }
        Test-ForbiddenManifestData -InputObject $property.Value -Location "$Location.$($property.Name)" -PropertyName $property.Name
    }
}

$jsonFiles = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File -Filter '*.json' | Where-Object FullName -NotMatch '[\\/]\.git[\\/]')
foreach ($jsonFile in $jsonFiles) {
    $maximumBytes = if ($jsonFile.FullName -match '[\\/]manifests[\\/]') { 262144 } else { 1048576 }
    $null = Read-JsonFile -Path $jsonFile.FullName -MaximumBytes $maximumBytes
}

$networkCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\networks.json')
$storageCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\storage-profiles.json')
$imageCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\images.json')
$ownerCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\owners.json')
$bootstrapCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\bootstrap-profiles.json')
$recoveryCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\recovery-profiles.json')
$firmwareCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\firmware-profiles.json')
$accessCatalog = Read-JsonFile -Path (Join-Path $repositoryRoot 'catalog\access-profiles.json')
$resourcePolicy = Read-JsonFile -Path (Join-Path $repositoryRoot 'policy\resource-limits.json')
$canaryStage = Read-JsonFile -Path (Join-Path $repositoryRoot 'policy\canary-execution-stage.proposed.json')
$controlPlaneCandidate = Read-JsonFile -Path (Join-Path $repositoryRoot 'control-plane\candidate\release.proposed.json')
$workloadProposal = Read-JsonFile -Path (Join-Path $repositoryRoot 'proposals\aegis-debian-workloads.proposed.json')
$fullFleetProposal = Read-JsonFile -Path (Join-Path $repositoryRoot 'proposals\full-fleet.proposed.json')

Test-CatalogIdentities -Catalog $networkCatalog -Name 'Network'
Test-CatalogIdentities -Catalog $storageCatalog -Name 'Storage'
Test-CatalogIdentities -Catalog $ownerCatalog -Name 'Owner'
Test-CatalogIdentities -Catalog $bootstrapCatalog -Name 'Bootstrap'
Test-CatalogIdentities -Catalog $recoveryCatalog -Name 'Recovery'
Test-CatalogIdentities -Catalog $firmwareCatalog -Name 'Firmware'
Test-CatalogIdentities -Catalog $accessCatalog -Name 'Access'

$duplicateImages = Get-DuplicateValues -Values @($imageCatalog.images.id)
if ($duplicateImages.Count) {
    throw "Image catalog identifiers must be case-insensitively unique: $($duplicateImages -join ', ')"
}
Assert-ImageCatalogSafety -Catalog $imageCatalog

Assert-MutationRejected -Name 'proposed image active state' -Baseline $imageCatalog `
    -Mutate { param($catalog) $catalog.images[0].retirementStatus = 'active' } `
    -Assert { param($catalog) Assert-ImageCatalogSafety -Catalog $catalog }
Assert-MutationRejected -Name 'image promotion while catalog is inventory-required' -Baseline $imageCatalog `
    -Mutate { param($catalog) $catalog.images[0].approvalStatus = 'promoted'; $catalog.images[0].retirementStatus = 'active' } `
    -Assert { param($catalog) Assert-ImageCatalogSafety -Catalog $catalog }

foreach ($network in $networkCatalog.profiles) {
    if ($network.allowCreate -ne $false -or $network.allowRebind -ne $false) {
        throw "Network profile '$($network.id)' may not authorize switch creation or rebinding."
    }
}

Assert-PlanOnlyResourcePolicy -Policy $resourcePolicy
Assert-CanaryExecutionStageProposal -Stage $canaryStage
Assert-ControlPlaneCandidateProposal -Candidate $controlPlaneCandidate
Assert-WorkloadProvisioningProposal -Proposal $workloadProposal
Assert-FullFleetProvisioningProposal -Proposal $fullFleetProposal

if ([int]$fullFleetProposal.capacity.policyHostReserveMemoryMiB -ne [int]$resourcePolicy.hostReserveMemoryMiB) {
    throw 'The full-fleet proposal must use the current plan-only host memory reserve policy.'
}

$proposedImage = @($imageCatalog.images | Where-Object { $_.id -ieq $workloadProposal.catalogPromotion.imageRef -and $_.approvalStatus -eq 'proposed' })
$proposedFirmware = @(Get-CatalogProfile -Catalog $firmwareCatalog -Id $workloadProposal.catalogPromotion.firmwareProfileRef -RequiredStatus 'proposed')
$proposedStorage = @(Get-CatalogProfile -Catalog $storageCatalog -Id $workloadProposal.catalogPromotion.storageProfileRef -RequiredStatus 'proposed')
$proposedRecovery = @(Get-CatalogProfile -Catalog $recoveryCatalog -Id $workloadProposal.catalogPromotion.recoveryProfileRef -RequiredStatus 'proposed')
$proposedAccess = @(Get-CatalogProfile -Catalog $accessCatalog -Id $workloadProposal.catalogPromotion.accessProfileRef -RequiredStatus 'proposed')
if ($proposedImage.Count -ne 1 -or $proposedFirmware.Count -ne 1 -or $proposedStorage.Count -ne 1 -or
    $proposedRecovery.Count -ne 1 -or $proposedAccess.Count -ne 1) {
    throw 'The workload proposal must resolve exactly once to non-consumable proposed prerequisite records.'
}
if ($proposedStorage[0].allowProvision -ne $true -or $proposedStorage[0].criticalWorkloadsAllowed -ne $true) {
    throw 'The proposed application storage profile must be eligible for high-criticality planning before promotion.'
}
foreach ($networkRef in @($workloadProposal.catalogPromotion.networkProfileRefs)) {
    $network = @(Get-CatalogProfile -Catalog $networkCatalog -Id $networkRef -RequiredStatus 'proposed')
    if ($network.Count -ne 1 -or $network[0].allowAttach -ne $true -or
        $network[0].allowCreate -ne $false -or $network[0].allowRebind -ne $false) {
        throw "Proposed network profile '$networkRef' may not create or rebind fabric."
    }
}
foreach ($bootstrapRef in @($workloadProposal.catalogPromotion.bootstrapProfileRefs)) {
    if (@(Get-CatalogProfile -Catalog $bootstrapCatalog -Id $bootstrapRef -RequiredStatus 'proposed').Count -ne 1) {
        throw "Proposed bootstrap profile '$bootstrapRef' does not resolve exactly once."
    }
}
foreach ($workload in @($workloadProposal.workloads)) {
    if (@(Get-CatalogProfile -Catalog $ownerCatalog -Id $workload.ownerRef -RequiredStatus 'proposed').Count -ne 1 -or
        $workload.imageRef -cne $workloadProposal.catalogPromotion.imageRef -or
        $workload.firmwareProfileRef -cne $workloadProposal.catalogPromotion.firmwareProfileRef -or
        $workload.storageProfileRef -cne $workloadProposal.catalogPromotion.storageProfileRef -or
        $workload.recoveryProfileRef -cne $workloadProposal.catalogPromotion.recoveryProfileRef -or
        $workload.accessProfileRef -cne $workloadProposal.catalogPromotion.accessProfileRef -or
        $workload.networkProfileRef -notin @($workloadProposal.catalogPromotion.networkProfileRefs) -or
        $workload.bootstrapProfileRef -notin @($workloadProposal.catalogPromotion.bootstrapProfileRefs)) {
        throw "Workload '$($workload.assetId)' is not bound to the reviewed proposed prerequisite set."
    }
}

$fullFleetCandidateImageRefs = @($fullFleetProposal.catalogPromotion.candidateImageRefs)
$fullFleetBlockedImageRefs = @($fullFleetProposal.catalogPromotion.blockedImageRefs)
foreach ($imageRef in $fullFleetCandidateImageRefs) {
    if (@($imageCatalog.images | Where-Object {
        $_.id -ieq $imageRef -and $_.approvalStatus -eq 'proposed' -and $_.retirementStatus -eq 'proposed'
    }).Count -ne 1) {
        throw "Full-fleet candidate image '$imageRef' must resolve exactly once to a non-consumable proposed catalog record."
    }
}
foreach ($imageRef in $fullFleetBlockedImageRefs) {
    if (@($imageCatalog.images | Where-Object { $_.id -ieq $imageRef }).Count -ne 0) {
        throw "Blocked full-fleet image '$imageRef' must remain absent until immutable artifact evidence exists."
    }
}

$fullFleetProfileCatalogs = @{
    firmwareProfileRefs = $firmwareCatalog
    storageProfileRefs = $storageCatalog
    networkProfileRefs = $networkCatalog
    bootstrapProfileRefs = $bootstrapCatalog
    recoveryProfileRefs = $recoveryCatalog
    accessProfileRefs = $accessCatalog
}
foreach ($referenceProperty in $fullFleetProfileCatalogs.Keys) {
    foreach ($profileRef in @($fullFleetProposal.catalogPromotion.$referenceProperty)) {
        if (@(Get-CatalogProfile -Catalog $fullFleetProfileCatalogs[$referenceProperty] -Id $profileRef -RequiredStatus 'proposed').Count -ne 1) {
            throw "Full-fleet proposed profile '$profileRef' in '$referenceProperty' must resolve exactly once."
        }
    }
}

foreach ($networkRef in @($fullFleetProposal.catalogPromotion.networkProfileRefs)) {
    $network = @(Get-CatalogProfile -Catalog $networkCatalog -Id $networkRef -RequiredStatus 'proposed')
    if ($network.Count -ne 1 -or $network[0].allowAttach -ne $true -or
        $network[0].allowCreate -ne $false -or $network[0].allowRebind -ne $false) {
        throw "Full-fleet network profile '$networkRef' may not create or rebind fabric."
    }
}

foreach ($workload in @($fullFleetProposal.workloads)) {
    if (@(Get-CatalogProfile -Catalog $ownerCatalog -Id $workload.ownerRef -RequiredStatus 'proposed').Count -ne 1 -or
        @(Get-CatalogProfile -Catalog $firmwareCatalog -Id $workload.firmwareProfileRef -RequiredStatus 'proposed').Count -ne 1 -or
        @(Get-CatalogProfile -Catalog $storageCatalog -Id $workload.storageProfileRef -RequiredStatus 'proposed').Count -ne 1 -or
        @(Get-CatalogProfile -Catalog $networkCatalog -Id $workload.networkProfileRef -RequiredStatus 'proposed').Count -ne 1 -or
        @(Get-CatalogProfile -Catalog $bootstrapCatalog -Id $workload.bootstrapProfileRef -RequiredStatus 'proposed').Count -ne 1 -or
        @(Get-CatalogProfile -Catalog $recoveryCatalog -Id $workload.recoveryProfileRef -RequiredStatus 'proposed').Count -ne 1 -or
        @(Get-CatalogProfile -Catalog $accessCatalog -Id $workload.accessProfileRef -RequiredStatus 'proposed').Count -ne 1) {
        throw "Full-fleet workload '$($workload.assetId)' is not bound to the reviewed proposed prerequisite set."
    }
    $storage = @(Get-CatalogProfile -Catalog $storageCatalog -Id $workload.storageProfileRef -RequiredStatus 'proposed')
    if ($storage[0].allowProvision -ne $true -or
        ($workload.criticality -in @('high', 'critical') -and $storage[0].criticalWorkloadsAllowed -ne $true)) {
        throw "Full-fleet workload '$($workload.assetId)' uses an ineligible proposed storage profile."
    }

    if ($workload.imageState -eq 'candidate-unpromoted') {
        if ($workload.imageRef -notin $fullFleetCandidateImageRefs -or
            @($imageCatalog.images | Where-Object {
                $_.id -ieq $workload.imageRef -and $_.approvalStatus -eq 'proposed' -and $_.retirementStatus -eq 'proposed'
            }).Count -ne 1) {
            throw "Full-fleet workload '$($workload.assetId)' lacks its exact proposed image record."
        }
    }
    elseif ($workload.imageState -eq 'artifact-missing') {
        if ($workload.imageRef -notin $fullFleetBlockedImageRefs -or
            @($imageCatalog.images | Where-Object { $_.id -ieq $workload.imageRef }).Count -ne 0) {
            throw "Full-fleet workload '$($workload.assetId)' may not claim a missing image that is already cataloged."
        }
    }
}

$fullFleetDerivedReferences = @{
    candidateImageRefs = @($fullFleetProposal.workloads | Where-Object imageState -eq 'candidate-unpromoted' | Select-Object -ExpandProperty imageRef -Unique)
    blockedImageRefs = @($fullFleetProposal.workloads | Where-Object imageState -eq 'artifact-missing' | Select-Object -ExpandProperty imageRef -Unique)
    firmwareProfileRefs = @($fullFleetProposal.workloads | Select-Object -ExpandProperty firmwareProfileRef -Unique)
    storageProfileRefs = @($fullFleetProposal.workloads | Select-Object -ExpandProperty storageProfileRef -Unique)
    networkProfileRefs = @($fullFleetProposal.workloads | Select-Object -ExpandProperty networkProfileRef -Unique)
    bootstrapProfileRefs = @($fullFleetProposal.workloads | Select-Object -ExpandProperty bootstrapProfileRef -Unique)
    recoveryProfileRefs = @($fullFleetProposal.workloads | Select-Object -ExpandProperty recoveryProfileRef -Unique)
    accessProfileRefs = @($fullFleetProposal.workloads | Select-Object -ExpandProperty accessProfileRef -Unique)
}
foreach ($referenceProperty in $fullFleetDerivedReferences.Keys) {
    $declared = @($fullFleetProposal.catalogPromotion.$referenceProperty | Sort-Object)
    $derived = @($fullFleetDerivedReferences[$referenceProperty] | Sort-Object)
    if (($declared -join '|') -cne ($derived -join '|')) {
        throw "Full-fleet catalog bundle '$referenceProperty' does not exactly match workload references."
    }
}

Assert-MutationRejected -Name 'normal resource policy Create enablement' -Baseline $resourcePolicy `
    -Mutate { param($policy) $policy.applyEnabled = $true; $policy.executableActions = @('Create') } `
    -Assert { param($policy) Assert-PlanOnlyResourcePolicy -Policy $policy }

$canaryNegativeCases = @(
    @{ Name = 'effective canary apply'; Mutate = { param($stage) $stage.effectiveState.applyEnabled = $true } },
    @{ Name = 'effective canary Create'; Mutate = { param($stage) $stage.effectiveState.executableActions = @('Create') } },
    @{ Name = 'approved status in proposal record'; Mutate = { param($stage) $stage.status = 'approved' } },
    @{ Name = 'automatic activation'; Mutate = { param($stage) $stage.proposedStage.activationMode = 'automatic' } },
    @{ Name = 'normal VirtualMachine request kind'; Mutate = { param($stage) $stage.proposedStage.requestKind = 'VirtualMachine' } },
    @{ Name = 'normal workload admission'; Mutate = { param($stage) $stage.proposedStage.normalVirtualMachineManifestsAllowed = $true } },
    @{ Name = 'broader online update action'; Mutate = { param($stage) $stage.proposedStage.plannerAction = 'UpdateOnline' } },
    @{ Name = 'more than one concurrent canary'; Mutate = { param($stage) $stage.proposedStage.maximumConcurrent = 2 } },
    @{ Name = 'co-promotion with canary request'; Mutate = { param($stage) $stage.proposedStage.requestMaySharePromotion = $true } },
    @{ Name = 'missing exact plan approval gate'; Mutate = { param($stage) $stage.proposedStage.requiredGates = @($stage.proposedStage.requiredGates | Where-Object { $_ -ne 'exact-plan-human-approval' }) } },
    @{ Name = 'missing quarantine gate'; Mutate = { param($stage) $stage.proposedStage.requiredGates = @($stage.proposedStage.requiredGates | Where-Object { $_ -ne 'quarantine-route-proven' }) } },
    @{ Name = 'missing receipt gate'; Mutate = { param($stage) $stage.proposedStage.requiredGates = @($stage.proposedStage.requiredGates | Where-Object { $_ -ne 'signed-receipt-ready' }) } }
)
foreach ($case in $canaryNegativeCases) {
    Assert-MutationRejected -Name $case.Name -Baseline $canaryStage -Mutate $case.Mutate `
        -Assert { param($stage) Assert-CanaryExecutionStageProposal -Stage $stage }
}

$controlPlaneNegativeCases = @(
    @{ Name = 'candidate deployed claim'; Mutate = { param($candidate) $candidate.effectiveState.deployed = $true } },
    @{ Name = 'candidate application authentication claim'; Mutate = { param($candidate) $candidate.effectiveState.applicationAuthenticationConfigured = $true } },
    @{ Name = 'candidate plan registration enablement'; Mutate = { param($candidate) $candidate.effectiveState.planRegistrationEnabled = $true } },
    @{ Name = 'candidate apply enablement'; Mutate = { param($candidate) $candidate.effectiveState.applyEnabled = $true } },
    @{ Name = 'candidate executable Create'; Mutate = { param($candidate) $candidate.effectiveState.executableActions = @('Create') } },
    @{ Name = 'candidate direct mutation exposure'; Mutate = { param($candidate) $candidate.effectiveState.directMutationMethodsExposed = $true } },
    @{ Name = 'candidate repository host execution'; Mutate = { param($candidate) $candidate.promotion.repositorySourceMayExecuteOnHost = $true } },
    @{ Name = 'candidate arbitrary apply input'; Mutate = { param($candidate) $candidate.interface.applyInputFields = @('planId', 'command') } },
    @{ Name = 'candidate missing application authentication gate'; Mutate = { param($candidate) $candidate.promotion.requiredGates = @($candidate.promotion.requiredGates | Where-Object { $_ -ne 'application-authentication-proven' }) } },
    @{ Name = 'candidate missing protected branch gate'; Mutate = { param($candidate) $candidate.promotion.requiredGates = @($candidate.promotion.requiredGates | Where-Object { $_ -ne 'protected-branch-reachability-proven' }) } },
    @{ Name = 'candidate missing direct mutator gate'; Mutate = { param($candidate) $candidate.promotion.requiredGates = @($candidate.promotion.requiredGates | Where-Object { $_ -ne 'direct-mutators-disabled' }) } }
)
foreach ($case in $controlPlaneNegativeCases) {
    Assert-MutationRejected -Name $case.Name -Baseline $controlPlaneCandidate -Mutate $case.Mutate `
        -Assert { param($candidate) Assert-ControlPlaneCandidateProposal -Candidate $candidate }
}

& (Join-Path $repositoryRoot 'control-plane\candidate\Test-Candidate.ps1')
& (Join-Path $repositoryRoot 'control-plane\engine-candidate\Test-Engine.ps1')
& (Join-Path $repositoryRoot 'control-plane\phase3-host-adapter\Test-HostAdapter.ps1')
& (Join-Path $repositoryRoot 'control-plane\create-only-operator\Test-CreateOnlyOperator.ps1')
& (Join-Path $repositoryRoot 'control-plane\create-only-release\Test-CreateOnlyRelease.ps1')

$proposalNegativeCases = @(
    @{ Name = 'workload proposal deployment enablement'; Mutate = { param($proposal) $proposal.execution.deployable = $true } },
    @{ Name = 'workload host-plan bypass'; Mutate = { param($proposal) $proposal.execution.hostPlanRequired = $false } },
    @{ Name = 'workload manifest co-promotion'; Mutate = { param($proposal) $proposal.execution.standardManifestsIncluded = $true } },
    @{ Name = 'workload policy enablement'; Mutate = { param($proposal) $proposal.execution.resourcePolicyMustRemainDisabled = $false } },
    @{ Name = 'workload catalog co-promotion'; Mutate = { param($proposal) $proposal.execution.promotionMode = 'single-stage' } },
    @{ Name = 'workload promotion sequence collapse'; Mutate = { param($proposal) $proposal.promotionSequence = @('catalog-and-fabric-policy', 'employee-hub-host-plan', 'sentinel-atlas-host-plan') } },
    @{ Name = 'workload identity approval claim'; Mutate = { param($proposal) $proposal.governance.assetIdentityState = 'reserved' } },
    @{ Name = 'workload raw VLAN field'; Mutate = { param($proposal) $proposal.workloads[0] | Add-Member -NotePropertyName vlan -NotePropertyValue 150 } },
    @{ Name = 'workload unexpected nested field'; Mutate = { param($proposal) $proposal.workloads[0] | Add-Member -NotePropertyName deploymentHint -NotePropertyValue 'none' } },
    @{ Name = 'workload secret-like content'; Mutate = { param($proposal) $proposal.workloads[0].purpose = ('-----BEGIN PRIVATE' + ' KEY-----') } }
)
foreach ($case in $proposalNegativeCases) {
    Assert-MutationRejected -Name $case.Name -Baseline $workloadProposal -Mutate $case.Mutate `
        -Assert { param($proposal) Assert-WorkloadProvisioningProposal -Proposal $proposal }
}

$fullFleetNegativeCases = @(
    @{ Name = 'full-fleet deployment enablement'; Mutate = { param($proposal) $proposal.execution.deployable = $true } },
    @{ Name = 'full-fleet standard manifest co-promotion'; Mutate = { param($proposal) $proposal.execution.standardManifestsIncluded = $true } },
    @{ Name = 'full-fleet identity reservation claim'; Mutate = { param($proposal) $proposal.governance.assetIdentityState = 'reserved' } },
    @{ Name = 'full-fleet address allocation claim'; Mutate = { param($proposal) $proposal.governance.addressReservationState = 'allocated' } },
    @{ Name = 'full-fleet ready claim'; Mutate = { param($proposal) $proposal.execution.overallState = 'ready' } },
    @{ Name = 'full-fleet workload ready claim'; Mutate = { param($proposal) $proposal.workloads[0].readinessState = 'ready' } },
    @{ Name = 'full-fleet blocked capacity claim'; Mutate = { param($proposal) $proposal.capacity.assessmentState = 'blocked-max-memory-reserve' } },
    @{ Name = 'full-fleet reserve-margin tamper'; Mutate = { param($proposal) $proposal.capacity.reserveMarginMiBAtLastRead = 128 } },
    @{ Name = 'full-fleet capacity total mismatch'; Mutate = { param($proposal) $proposal.capacity.persistentFleet.maximumMemoryMiB = 1024 } },
    @{ Name = 'full-fleet Kali artifact downgrade'; Mutate = { param($proposal) $proposal.workloads[11].imageState = 'artifact-missing' } },
    @{ Name = 'full-fleet Kali image identity drift'; Mutate = { param($proposal) $proposal.workloads[11].imageRef = 'kali-rolling-amd64-installer' } },
    @{ Name = 'full-fleet missing protected-branch blocker'; Mutate = { param($proposal) $proposal.blockingFindings = @($proposal.blockingFindings | Where-Object id -ne 'protected-branch-unavailable') } },
    @{ Name = 'full-fleet workload missing protected-branch blocker'; Mutate = { param($proposal) $proposal.workloads[0].blockingFindingRefs = @($proposal.workloads[0].blockingFindingRefs | Where-Object { $_ -ne 'protected-branch-unavailable' }) } },
    @{ Name = 'full-fleet reordered canary'; Mutate = { param($proposal) $proposal.rollout.orderedAssetIds[0] = 'NG-VM-010' } },
    @{ Name = 'full-fleet raw VLAN field'; Mutate = { param($proposal) $proposal.workloads[0] | Add-Member -NotePropertyName vlan -NotePropertyValue 150 } },
    @{ Name = 'full-fleet raw IP address field'; Mutate = { param($proposal) $proposal.workloads[0] | Add-Member -NotePropertyName ipAddress -NotePropertyValue '192.0.2.10' } },
    @{ Name = 'full-fleet secret-like content'; Mutate = { param($proposal) $proposal.workloads[0].purpose = ('-----BEGIN PRIVATE' + ' KEY-----') } }
)
foreach ($case in $fullFleetNegativeCases) {
    Assert-MutationRejected -Name $case.Name -Baseline $fullFleetProposal -Mutate $case.Mutate `
        -Assert { param($proposal) Assert-FullFleetProvisioningProposal -Proposal $proposal }
}

$expectedPlannerActions = @('NoOp', 'Create', 'UpdateOnline', 'UpdateOffline', 'ReplaceRequired', 'DecommissionRequired')
if ((@($resourcePolicy.plannerActions) -join '|') -ne ($expectedPlannerActions -join '|')) {
    throw 'Planner action enum was changed from the reviewed plan-only contract.'
}

$manifestDirectory = Join-Path $repositoryRoot 'manifests\vms'
$unexpectedManifestFiles = @(Get-ChildItem -LiteralPath $manifestDirectory -File | Where-Object { $_.Name -ne '.gitkeep' -and $_.Extension -ne '.json' })
if ($unexpectedManifestFiles.Count) {
    throw "Only JSON VM manifests are permitted: $($unexpectedManifestFiles.Name -join ', ')"
}

$manifestFiles = @(Get-ChildItem -LiteralPath $manifestDirectory -File -Filter '*.json')
$assetIds = @()
$vmNames = @()
foreach ($manifestFile in $manifestFiles) {
    $manifest = Read-JsonFile -Path $manifestFile.FullName -MaximumBytes 262144
    Test-ForbiddenManifestData -InputObject $manifest

    if ($manifest.'$schema' -ne '../../schemas/vm-manifest.schema.json' -or $manifest.apiVersion -ne 'northgate/v1alpha1' -or $manifest.kind -ne 'VirtualMachine') {
        throw "Unsupported manifest contract: $($manifestFile.FullName)"
    }
    if ($manifest.metadata.assetId -notmatch '^NG-VM-[0-9]{3,}$') {
        throw "Invalid immutable assetId in $($manifestFile.FullName)"
    }
    if ($manifest.metadata.name -cnotmatch '^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$') {
        throw "VM name must be 1-15 uppercase ASCII guest-safe characters in $($manifestFile.FullName)"
    }
    $expectedFileName = $manifest.metadata.assetId.ToLowerInvariant() + '.json'
    if ($manifestFile.Name -cne $expectedFileName) {
        throw "Manifest filename must be '$expectedFileName'."
    }
    if ($manifest.spec.intent -notin @('create', 'manage') -or $manifest.spec.generation -ne 2 -or $manifest.spec.destroyProtection -ne $true) {
        throw "Manifest intent, Generation 2, or destroy protection is invalid in $($manifestFile.FullName)"
    }
    if ($manifest.metadata.assetId -in @($manifest.metadata.dependencies)) {
        throw "A VM cannot depend on itself in $($manifestFile.FullName)"
    }

    $memory = $manifest.spec.compute.memory
    if ($memory.mode -eq 'dynamic' -and -not ($memory.minimumMiB -le $memory.startupMiB -and $memory.startupMiB -le $memory.maximumMiB)) {
        throw "Dynamic memory must satisfy minimumMiB <= startupMiB <= maximumMiB in $($manifestFile.FullName)"
    }

    $owner = Get-CatalogProfile -Catalog $ownerCatalog -Id $manifest.metadata.ownerRef
    $storage = Get-CatalogProfile -Catalog $storageCatalog -Id $manifest.spec.storage.profileRef
    $network = Get-CatalogProfile -Catalog $networkCatalog -Id $manifest.spec.network.profileRef
    $bootstrap = Get-CatalogProfile -Catalog $bootstrapCatalog -Id $manifest.spec.bootstrapProfileRef
    $recovery = Get-CatalogProfile -Catalog $recoveryCatalog -Id $manifest.spec.recoveryProfileRef
    $firmware = Get-CatalogProfile -Catalog $firmwareCatalog -Id $manifest.spec.firmwareProfileRef
    if ($owner.Count -ne 1 -or $storage.Count -ne 1 -or $network.Count -ne 1 -or $bootstrap.Count -ne 1 -or $recovery.Count -ne 1 -or $firmware.Count -ne 1) {
        throw "Every manifest reference must resolve exactly once to an approved profile in $($manifestFile.FullName)"
    }
    if ($network[0].allowAttach -ne $true -or $network[0].allowCreate -ne $false -or $network[0].allowRebind -ne $false) {
        throw "Network profile cannot be used safely in $($manifestFile.FullName)"
    }
    if ($storage[0].allowProvision -ne $true -or ($manifest.metadata.criticality -in @('high', 'critical') -and $storage[0].criticalWorkloadsAllowed -ne $true)) {
        throw "Storage profile is not approved for this workload in $($manifestFile.FullName)"
    }

    $image = @($imageCatalog.images | Where-Object { $_.id -ieq $manifest.spec.imageRef })
    if ($image.Count -ne 1 -or $image[0].approvalStatus -ne 'promoted' -or $image[0].retirementStatus -ne 'active' -or $image[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "Image reference is not an active immutable promoted image in $($manifestFile.FullName)"
    }
    if (2 -notin @($image[0].allowedGenerations) -or $manifest.spec.firmwareProfileRef -notin @($image[0].allowedFirmwareProfiles)) {
        throw "Image, generation, and firmware profile are incompatible in $($manifestFile.FullName)"
    }

    $assetIds += $manifest.metadata.assetId
    $vmNames += $manifest.metadata.name
}

$duplicateAssetIds = Get-DuplicateValues -Values $assetIds
$duplicateVmNames = Get-DuplicateValues -Values $vmNames
if ($duplicateAssetIds.Count -or $duplicateVmNames.Count) {
    throw "Manifest identities must be case-insensitively unique. AssetIds=[$($duplicateAssetIds -join ',')], Names=[$($duplicateVmNames -join ',')]"
}

$proposedWorkloadAssetIds = @($workloadProposal.workloads.assetId) + @($fullFleetProposal.workloads.assetId)
$prematureConsumers = @($proposedWorkloadAssetIds | Where-Object { $_ -in $assetIds } | Select-Object -Unique)
if ($prematureConsumers.Count) {
    throw "A proposed prerequisite bundle cannot be co-promoted with its first consuming manifests: $($prematureConsumers -join ', ')"
}

$unsafeFiles = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File | Where-Object {
    $_.FullName -notmatch '[\\/]\.git[\\/]' -and
    $_.Name -match '(?i)(\.tfstate($|\.)|id_rsa|id_ed25519|\.pfx$|\.p12$|\.key$|\.pem$|unattend\.generated\.xml$)'
})
if ($unsafeFiles.Count) {
    throw "Unsafe files detected: $($unsafeFiles.FullName -join ', ')"
}

$reparsePoints = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -Force | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
if ($reparsePoints.Count) {
    throw "Symlinks or reparse points are not permitted: $($reparsePoints.FullName -join ', ')"
}

$privateKeySignatures = @(Get-ChildItem -LiteralPath $repositoryRoot -Recurse -File | Where-Object FullName -NotMatch '[\\/]\.git[\\/]' | Where-Object {
    try { [System.IO.File]::ReadAllText($_.FullName) -match '-----BEGIN [A-Z ]*PRIVATE KEY-----' } catch { $false }
})
if ($privateKeySignatures.Count) {
    throw "Private-key signature detected: $($privateKeySignatures.FullName -join ', ')"
}

if (Test-Path -LiteralPath (Join-Path $repositoryRoot '.gitmodules')) {
    throw 'Git submodules are not permitted.'
}

$readme = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'README.md')
$architecture = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'docs\architecture.md')
if ($readme -notmatch '```mermaid' -or $readme -notmatch 'No GitHub Actions runner' -or $architecture -notmatch 'never infer deletion' -or $architecture -notmatch 'application.authenticat' -or $architecture -notmatch 'plan ID') {
    throw 'Architecture safety statements are missing or were weakened.'
}

Write-Host "Repository validation passed: $($jsonFiles.Count) JSON files; $($manifestFiles.Count) managed VM manifests; $schemaValidationCount schema validations; $negativeTestCount policy negative tests; plan-only apply disabled."
