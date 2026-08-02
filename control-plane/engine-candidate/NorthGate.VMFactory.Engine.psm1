Set-StrictMode -Version Latest

$script:EngineVersion = '0.2.0'
$script:ApprovedRepositoryIdentity = 'Beowxlf/northgate-vm-factory'
$script:MaximumPlanBytes = 262144
$script:MaximumJsonDepth = 32

function Throw-NgvfError {
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

function Get-NgvfHmacHex {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][string]$Value
    )

    $algorithm = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $algorithm.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Test-NgvfFixedHexEquals {
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ([int][char]$Left[$index] -bxor [int][char]$Right[$index])
    }
    return ($difference -eq 0)
}

function New-NgvfRandomHex {
    param([ValidateRange(16, 64)][int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NgvfNow {
    param([Parameter(Mandatory)][object]$Context)

    $clock = $Context.Clock
    try {
        $value = & $clock
        return [System.DateTimeOffset]$value
    }
    catch {
        Throw-NgvfError -Code 'NGVF-CLOCK-UNAVAILABLE'
    }
}

function Format-NgvfUtc {
    param([Parameter(Mandatory)][System.DateTimeOffset]$Value)

    return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Skip-NgvfJsonWhitespace {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ref]$Index
    )

    while ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -in @(' ', "`t", "`r", "`n")) {
        $Index.Value++
    }
}

function Read-NgvfJsonStringToken {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ref]$Index
    )

    if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -ne '"') {
        Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
    }

    $start = $Index.Value
    $Index.Value++
    while ($Index.Value -lt $Text.Length) {
        $character = $Text[$Index.Value]
        if ($character -eq '"') {
            $Index.Value++
            $token = $Text.Substring($start, $Index.Value - $start)
            try {
                return ($token | ConvertFrom-Json)
            }
            catch {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
        }
        if ([int][char]$character -lt 32) {
            Throw-NgvfError -Code 'NGVF-PLAN-CONTROL-CHARACTER'
        }
        if ($character -eq '\') {
            $Index.Value++
            if ($Index.Value -ge $Text.Length) {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
            $escape = $Text[$Index.Value]
            if ($escape -eq 'u') {
                if ($Index.Value + 4 -ge $Text.Length) {
                    Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
                }
                $hex = $Text.Substring($Index.Value + 1, 4)
                if ($hex -cnotmatch '^[0-9a-fA-F]{4}$') {
                    Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
                }
                $Index.Value += 4
            }
            elseif ($escape -notin @('"', '\', '/', 'b', 'f', 'n', 'r', 't')) {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
        }
        $Index.Value++
    }

    Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
}

function Read-NgvfJsonValue {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][ref]$Index,
        [int]$Depth = 0
    )

    if ($Depth -gt $script:MaximumJsonDepth) {
        Throw-NgvfError -Code 'NGVF-PLAN-DEPTH-EXCEEDED'
    }

    Skip-NgvfJsonWhitespace -Text $Text -Index $Index
    if ($Index.Value -ge $Text.Length) {
        Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
    }

    $character = $Text[$Index.Value]
    if ($character -eq '{') {
        $Index.Value++
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Skip-NgvfJsonWhitespace -Text $Text -Index $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -eq '}') {
            $Index.Value++
            return
        }
        while ($true) {
            Skip-NgvfJsonWhitespace -Text $Text -Index $Index
            $name = Read-NgvfJsonStringToken -Text $Text -Index $Index
            if (-not $names.Add([string]$name)) {
                Throw-NgvfError -Code 'NGVF-PLAN-DUPLICATE-PROPERTY'
            }
            Skip-NgvfJsonWhitespace -Text $Text -Index $Index
            if ($Index.Value -ge $Text.Length -or $Text[$Index.Value] -ne ':') {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
            $Index.Value++
            $null = Read-NgvfJsonValue -Text $Text -Index $Index -Depth ($Depth + 1)
            Skip-NgvfJsonWhitespace -Text $Text -Index $Index
            if ($Index.Value -ge $Text.Length) {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
            if ($Text[$Index.Value] -eq '}') {
                $Index.Value++
                return
            }
            if ($Text[$Index.Value] -ne ',') {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
            $Index.Value++
        }
    }

    if ($character -eq '[') {
        $Index.Value++
        Skip-NgvfJsonWhitespace -Text $Text -Index $Index
        if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -eq ']') {
            $Index.Value++
            return
        }
        while ($true) {
            $null = Read-NgvfJsonValue -Text $Text -Index $Index -Depth ($Depth + 1)
            Skip-NgvfJsonWhitespace -Text $Text -Index $Index
            if ($Index.Value -ge $Text.Length) {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
            if ($Text[$Index.Value] -eq ']') {
                $Index.Value++
                return
            }
            if ($Text[$Index.Value] -ne ',') {
                Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
            }
            $Index.Value++
        }
    }

    if ($character -eq '"') {
        $null = Read-NgvfJsonStringToken -Text $Text -Index $Index
        return
    }

    foreach ($literal in @('true', 'false')) {
        if ($Index.Value + $literal.Length -le $Text.Length -and
            $Text.Substring($Index.Value, $literal.Length) -ceq $literal) {
            $Index.Value += $literal.Length
            return
        }
    }
    if ($Index.Value + 4 -le $Text.Length -and $Text.Substring($Index.Value, 4) -ceq 'null') {
        Throw-NgvfError -Code 'NGVF-PLAN-NULL-FORBIDDEN'
    }

    $remaining = $Text.Substring($Index.Value)
    $numberMatch = [regex]::Match($remaining, '^-?(?:0|[1-9][0-9]*)')
    if (-not $numberMatch.Success) {
        Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
    }
    $Index.Value += $numberMatch.Length
    if ($Index.Value -lt $Text.Length -and $Text[$Index.Value] -in @('.', 'e', 'E')) {
        Throw-NgvfError -Code 'NGVF-PLAN-NONINTEGER-FORBIDDEN'
    }
}

function Assert-NgvfStrictJson {
    param([Parameter(Mandatory)][string]$Json)

    if ([System.Text.Encoding]::UTF8.GetByteCount($Json) -gt $script:MaximumPlanBytes) {
        Throw-NgvfError -Code 'NGVF-PLAN-SIZE-EXCEEDED'
    }
    if ($Json -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
        Throw-NgvfError -Code 'NGVF-PLAN-CONTROL-CHARACTER'
    }

    $position = 0
    $reference = [ref]$position
    $null = Read-NgvfJsonValue -Text $Json -Index $reference
    Skip-NgvfJsonWhitespace -Text $Json -Index $reference
    if ($reference.Value -ne $Json.Length) {
        Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
    }
}

function ConvertTo-NgvfJsonString {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $codePoint = [int][char]$character
        if ($codePoint -eq 8) { $null = $builder.Append('\b') }
        elseif ($codePoint -eq 9) { $null = $builder.Append('\t') }
        elseif ($codePoint -eq 10) { $null = $builder.Append('\n') }
        elseif ($codePoint -eq 12) { $null = $builder.Append('\f') }
        elseif ($codePoint -eq 13) { $null = $builder.Append('\r') }
        elseif ($codePoint -eq 34) { $null = $builder.Append('\"') }
        elseif ($codePoint -eq 92) { $null = $builder.Append('\\') }
        elseif ($codePoint -lt 32) {
            $null = $builder.Append(('\u{0:x4}' -f [int][char]$character))
        }
        else {
            $null = $builder.Append($character)
        }
    }
    $null = $builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-NgvfCanonicalJson {
    param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) {
        Throw-NgvfError -Code 'NGVF-CANONICAL-NULL-FORBIDDEN'
    }
    if ($InputObject -is [string]) {
        return (ConvertTo-NgvfJsonString -Value $InputObject)
    }
    if ($InputObject -is [bool]) {
        if ($InputObject) { return 'true' }
        return 'false'
    }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or
        $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int32] -or $InputObject -is [uint32] -or
        $InputObject -is [int64]) {
        return ([System.Convert]::ToString($InputObject, [System.Globalization.CultureInfo]::InvariantCulture))
    }
    if ($InputObject -is [single] -or $InputObject -is [double] -or
        $InputObject -is [decimal] -or $InputObject -is [uint64]) {
        Throw-NgvfError -Code 'NGVF-CANONICAL-NUMBER-FORBIDDEN'
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and
        $InputObject -isnot [System.Collections.IDictionary] -and
        $InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ConvertTo-NgvfCanonicalJson -InputObject $item
        }
        return ('[' + ($items -join ',') + ']')
    }

    $names = @()
    if ($InputObject -is [System.Collections.IDictionary]) {
        $names = @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    else {
        $names = @($InputObject.PSObject.Properties.Name)
    }
    [array]::Sort($names, [System.StringComparer]::Ordinal)
    $properties = @()
    foreach ($name in $names) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            $value = $InputObject[$name]
        }
        else {
            $value = $InputObject.PSObject.Properties[$name].Value
        }
        $properties += ((ConvertTo-NgvfJsonString -Value $name) + ':' + (ConvertTo-NgvfCanonicalJson -InputObject $value))
    }
    return ('{' + ($properties -join ',') + '}')
}

function Assert-NgvfExactProperties {
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Code
    )

    $actual = @($InputObject.PSObject.Properties.Name)
    [array]::Sort($actual, [System.StringComparer]::Ordinal)
    $expectedCopy = @($Expected)
    [array]::Sort($expectedCopy, [System.StringComparer]::Ordinal)
    if (($actual -join '|') -cne ($expectedCopy -join '|')) {
        Throw-NgvfError -Code $Code
    }
}

function Assert-NgvfRepositoryTrust {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Repository
    )

    $verifier = $Context.RepositoryVerifier
    try {
        $verification = & $verifier $Repository.identity $Repository.commit $Repository.tree
    }
    catch {
        Throw-NgvfError -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED'
    }
    if ($null -eq $verification) {
        Throw-NgvfError -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED'
    }
    Assert-NgvfExactProperties -InputObject $verification -Expected @(
        'verified', 'identity', 'commit', 'tree', 'protectedBranchReachable', 'verificationId'
    ) -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED'
    if ($verification.verified -isnot [bool] -or
        $verification.protectedBranchReachable -isnot [bool] -or
        $verification.identity -isnot [string] -or
        $verification.commit -isnot [string] -or
        $verification.tree -isnot [string] -or
        $verification.verificationId -isnot [string] -or
        $verification.verified -ne $true -or
        $verification.protectedBranchReachable -ne $true -or
        $verification.identity -cne $Repository.identity -or
        $verification.commit -cne $Repository.commit -or
        $verification.tree -cne $Repository.tree -or
        $verification.verificationId -cnotmatch '^ngrv-[a-z0-9-]{8,64}$') {
        Throw-NgvfError -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED'
    }
}

function ConvertFrom-NgvfCanonicalPlan {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$CanonicalPlanJson,
        [bool]$ValidateFreshness = $true
    )

    Assert-NgvfStrictJson -Json $CanonicalPlanJson
    try {
        $plan = $CanonicalPlanJson | ConvertFrom-Json
    }
    catch {
        Throw-NgvfError -Code 'NGVF-PLAN-JSON-INVALID'
    }
    if ($plan -isnot [System.Management.Automation.PSCustomObject]) {
        Throw-NgvfError -Code 'NGVF-PLAN-ROOT-INVALID'
    }
    $canonical = ConvertTo-NgvfCanonicalJson -InputObject $plan
    if ($canonical -cne $CanonicalPlanJson) {
        Throw-NgvfError -Code 'NGVF-PLAN-NONCANONICAL'
    }

    Assert-NgvfExactProperties -InputObject $plan -Expected @(
        'apiVersion', 'kind', 'repository', 'changeId', 'plannedAtUtc',
        'policyHash', 'catalogHash', 'observedStateHash', 'plannerVersion',
        'provisionerVersion', 'operations'
    ) -Code 'NGVF-PLAN-PROPERTIES-INVALID'
    Assert-NgvfExactProperties -InputObject $plan.repository -Expected @(
        'identity', 'commit', 'tree', 'protectedBranchVerified'
    ) -Code 'NGVF-PLAN-REPOSITORY-PROPERTIES-INVALID'

    if ($plan.apiVersion -isnot [string] -or $plan.kind -isnot [string] -or
        $plan.apiVersion -cne 'northgate/v1alpha1' -or $plan.kind -cne 'VmFactoryPlan') {
        Throw-NgvfError -Code 'NGVF-PLAN-CONTRACT-INVALID'
    }
    if ($plan.repository.identity -isnot [string] -or
        $plan.repository.commit -isnot [string] -or
        $plan.repository.tree -isnot [string] -or
        $plan.repository.protectedBranchVerified -isnot [bool] -or
        $plan.repository.identity -cne $script:ApprovedRepositoryIdentity -or
        $plan.repository.commit -cnotmatch '^[a-f0-9]{40}$' -or
        $plan.repository.tree -cnotmatch '^[a-f0-9]{40}$' -or
        $plan.repository.protectedBranchVerified -ne $true) {
        Throw-NgvfError -Code 'NGVF-REPOSITORY-TRUST-UNVERIFIED'
    }
    Assert-NgvfRepositoryTrust -Context $Context -Repository $plan.repository
    if ($plan.changeId -isnot [string] -or
        $plan.plannedAtUtc -isnot [string] -or
        $plan.policyHash -isnot [string] -or
        $plan.catalogHash -isnot [string] -or
        $plan.observedStateHash -isnot [string] -or
        $plan.plannerVersion -isnot [string] -or
        $plan.provisionerVersion -isnot [string] -or
        $plan.changeId -cnotmatch '^NG-CHG-[0-9]{8}-[A-Z0-9-]{3,32}$' -or
        $plan.policyHash -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.catalogHash -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.observedStateHash -cnotmatch '^[a-f0-9]{64}$' -or
        $plan.plannerVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $plan.provisionerVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        Throw-NgvfError -Code 'NGVF-PLAN-METADATA-INVALID'
    }

    $plannedAt = [System.DateTimeOffset]::MinValue
    $parsed = [System.DateTimeOffset]::TryParseExact(
        [string]$plan.plannedAtUtc,
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$plannedAt
    )
    if (-not $parsed) {
        Throw-NgvfError -Code 'NGVF-PLAN-TIMESTAMP-INVALID'
    }
    if ($ValidateFreshness) {
        $now = Get-NgvfNow -Context $Context
        if ($plannedAt -gt $now.AddMinutes(1) -or $plannedAt -lt $now.AddMinutes(-1 * $Context.MaximumPlanAgeMinutes)) {
            Throw-NgvfError -Code 'NGVF-PLAN-STALE'
        }
    }

    if ($plan.operations -isnot [System.Array]) {
        Throw-NgvfError -Code 'NGVF-PLAN-OPERATIONS-ARRAY-REQUIRED'
    }
    $operations = @($plan.operations)
    if ($operations.Count -lt 1 -or $operations.Count -gt 16) {
        Throw-NgvfError -Code 'NGVF-PLAN-OPERATION-COUNT-INVALID'
    }
    $assetIds = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $reservations = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    for ($operationIndex = 0; $operationIndex -lt $operations.Count; $operationIndex++) {
        $operation = $operations[$operationIndex]
        Assert-NgvfExactProperties -InputObject $operation -Expected @(
            'sequence', 'action', 'assetId', 'name', 'desiredStateHash',
            'imageHash', 'reservationId', 'quarantineMode'
        ) -Code 'NGVF-PLAN-OPERATION-PROPERTIES-INVALID'
        if ($operation.sequence -isnot [int] -and $operation.sequence -isnot [long]) {
            Throw-NgvfError -Code 'NGVF-PLAN-SEQUENCE-INVALID'
        }
        if ($operation.action -isnot [string] -or
            $operation.assetId -isnot [string] -or
            $operation.name -isnot [string] -or
            $operation.desiredStateHash -isnot [string] -or
            $operation.imageHash -isnot [string] -or
            $operation.reservationId -isnot [string] -or
            $operation.quarantineMode -isnot [string] -or
            [int64]$operation.sequence -ne ($operationIndex + 1) -or
            $operation.action -notin @('Create', 'NoOp') -or
            $operation.assetId -cnotmatch '^NG-VM-[0-9]{3,}$' -or
            $operation.name -cnotmatch '^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or
            $operation.desiredStateHash -cnotmatch '^[a-f0-9]{64}$' -or
            $operation.imageHash -cnotmatch '^[a-f0-9]{64}$' -or
            $operation.reservationId -cnotmatch '^ngrsv-[a-z0-9-]{8,64}$' -or
            $operation.quarantineMode -cne 'isolate-artifacts') {
            Throw-NgvfError -Code 'NGVF-PLAN-OPERATION-INVALID'
        }
        if (-not $assetIds.Add([string]$operation.assetId) -or
            -not $names.Add([string]$operation.name) -or
            -not $reservations.Add([string]$operation.reservationId)) {
            Throw-NgvfError -Code 'NGVF-PLAN-IDENTITY-DUPLICATE'
        }
    }

    [pscustomobject][ordered]@{
        Plan = $plan
        CanonicalJson = $canonical
    }
}

function Get-NgvfEnvelopeMac {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$RecordType,
        [Parameter(Mandatory)][object]$Record
    )

    $canonicalRecord = ConvertTo-NgvfCanonicalJson -InputObject $Record
    return (Get-NgvfHmacHex -Key $Context.MacKey -Value ("northgate-$RecordType-v1`n$canonicalRecord"))
}

function Write-NgvfAtomicFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        Throw-NgvfError -Code 'NGVF-STATE-ROOT-UNAVAILABLE'
    }
    $directoryItem = Get-Item -LiteralPath $directory -Force
    if ($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Throw-NgvfError -Code 'NGVF-STATE-ROOT-REPARSE-FORBIDDEN'
    }

    $temporaryPath = Join-Path $directory ('.ngvf-' + (New-NgvfRandomHex -ByteCount 16) + '.tmp')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Content, $encoding)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Move-Item -LiteralPath $temporaryPath -Destination $Path -Force -ErrorAction Stop
        }
        else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
        Throw-NgvfError -Code 'NGVF-STATE-WRITE-FAILED'
    }
}

function Save-NgvfEnvelope {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$RecordType,
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$Path
    )

    $mac = Get-NgvfEnvelopeMac -Context $Context -RecordType $RecordType -Record $Record
    $envelope = [pscustomobject][ordered]@{
        record = $Record
        recordMac = $mac
    }
    $canonicalEnvelope = ConvertTo-NgvfCanonicalJson -InputObject $envelope
    Write-NgvfAtomicFile -Path $Path -Content $canonicalEnvelope
    return $envelope
}

function Read-NgvfEnvelope {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$RecordType,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Throw-NgvfError -Code 'NGVF-RECORD-NOT-FOUND'
    }
    try {
        $raw = [System.IO.File]::ReadAllText($Path)
    }
    catch {
        Throw-NgvfError -Code 'NGVF-STATE-READ-FAILED'
    }
    Assert-NgvfStrictJson -Json $raw
    try {
        $envelope = $raw | ConvertFrom-Json
    }
    catch {
        Throw-NgvfError -Code 'NGVF-STATE-CORRUPT'
    }
    Assert-NgvfExactProperties -InputObject $envelope -Expected @('record', 'recordMac') -Code 'NGVF-STATE-CORRUPT'
    if ($envelope.recordMac -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgvfError -Code 'NGVF-RECORD-AUTHENTICATION-FAILED'
    }
    $canonicalEnvelope = ConvertTo-NgvfCanonicalJson -InputObject $envelope
    if ($canonicalEnvelope -cne $raw) {
        Throw-NgvfError -Code 'NGVF-STATE-NONCANONICAL'
    }
    $expectedMac = Get-NgvfEnvelopeMac -Context $Context -RecordType $RecordType -Record $envelope.record
    if (-not (Test-NgvfFixedHexEquals -Left $expectedMac -Right ([string]$envelope.recordMac))) {
        Throw-NgvfError -Code 'NGVF-RECORD-AUTHENTICATION-FAILED'
    }
    return $envelope
}

function Assert-NgvfLedgerRecord {
    param([Parameter(Mandatory)][object]$Ledger)

    Assert-NgvfExactProperties -InputObject $Ledger -Expected @('formatVersion', 'entries') -Code 'NGVF-LEDGER-CORRUPT'
    if ($Ledger.formatVersion -ne 1 -or $Ledger.entries -isnot [System.Array]) {
        Throw-NgvfError -Code 'NGVF-LEDGER-CORRUPT'
    }
    $assetIds = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $reservations = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $vmIds = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($Ledger.entries)) {
        Assert-NgvfExactProperties -InputObject $entry -Expected @(
            'assetId', 'canonicalName', 'reservationId', 'vmId', 'state'
        ) -Code 'NGVF-LEDGER-CORRUPT'
        if ($entry.assetId -isnot [string] -or
            $entry.canonicalName -isnot [string] -or
            $entry.reservationId -isnot [string] -or
            $entry.vmId -isnot [string] -or
            $entry.state -isnot [string] -or
            $entry.assetId -cnotmatch '^NG-VM-[0-9]{3,}$' -or
            $entry.canonicalName -cnotmatch '^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$' -or
            $entry.reservationId -cnotmatch '^ngrsv-[a-z0-9-]{8,64}$' -or
            $entry.state -notin @('Reserved', 'Bound', 'Quarantined', 'OutcomeUnknown') -or
            ($entry.vmId -cne '' -and $entry.vmId -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')) {
            Throw-NgvfError -Code 'NGVF-LEDGER-CORRUPT'
        }
        if ($entry.state -in @('Reserved', 'OutcomeUnknown') -and $entry.vmId -cne '') {
            Throw-NgvfError -Code 'NGVF-LEDGER-CORRUPT'
        }
        if ($entry.state -in @('Bound', 'Quarantined') -and $entry.vmId -ceq '') {
            Throw-NgvfError -Code 'NGVF-LEDGER-CORRUPT'
        }
        if (-not $assetIds.Add([string]$entry.assetId) -or
            -not $names.Add([string]$entry.canonicalName) -or
            -not $reservations.Add([string]$entry.reservationId)) {
            Throw-NgvfError -Code 'NGVF-LEDGER-DUPLICATE'
        }
        if ($entry.vmId -cne '' -and -not $vmIds.Add([string]$entry.vmId)) {
            Throw-NgvfError -Code 'NGVF-LEDGER-DUPLICATE'
        }
    }
}

function Read-NgvfLedger {
    param([Parameter(Mandatory)][object]$Context)

    $envelope = Read-NgvfEnvelope -Context $Context -RecordType 'identity-ledger' -Path $Context.LedgerPath
    Assert-NgvfLedgerRecord -Ledger $envelope.record
    return $envelope.record
}

function Save-NgvfLedger {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Ledger
    )

    Assert-NgvfLedgerRecord -Ledger $Ledger
    $null = Save-NgvfEnvelope -Context $Context -RecordType 'identity-ledger' -Record $Ledger -Path $Context.LedgerPath
}

function Assert-NgvfPlanLedgerBinding {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Plan
    )

    $ledger = Read-NgvfLedger -Context $Context
    foreach ($operation in @($Plan.operations)) {
        $matches = @($ledger.entries | Where-Object {
            $_.assetId -ieq $operation.assetId -and
            $_.canonicalName -ieq $operation.name -and
            $_.reservationId -ceq $operation.reservationId
        })
        if ($matches.Count -ne 1) {
            Throw-NgvfError -Code 'NGVF-LEDGER-BINDING-MISMATCH'
        }
        if ($operation.action -eq 'Create' -and $matches[0].state -cne 'Reserved') {
            Throw-NgvfError -Code 'NGVF-LEDGER-RESERVATION-INVALID'
        }
        if ($operation.action -eq 'NoOp' -and $matches[0].state -cne 'Bound') {
            Throw-NgvfError -Code 'NGVF-LEDGER-BINDING-MISMATCH'
        }
    }
}

function Test-NgvfPlanId {
    param([Parameter(Mandatory)][string]$PlanId)

    return ($PlanId -cmatch '^ngp-[a-f0-9]{64}$')
}

function Get-NgvfPlanPath {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$PlanId
    )

    if (-not (Test-NgvfPlanId -PlanId $PlanId)) {
        Throw-NgvfError -Code 'NGVF-PLAN-ID-INVALID'
    }
    return (Join-Path $Context.PlansRoot ($PlanId + '.json'))
}

function Get-NgvfReceiptPath {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$PlanId
    )

    if (-not (Test-NgvfPlanId -PlanId $PlanId)) {
        Throw-NgvfError -Code 'NGVF-PLAN-ID-INVALID'
    }
    return (Join-Path $Context.ReceiptsRoot ($PlanId + '.json'))
}

function Get-NgvfPlanAuthenticationHash {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$PlanId,
        [Parameter(Mandatory)][string]$ExpiresAtUtc,
        [Parameter(Mandatory)][string]$CanonicalPlan
    )

    return (Get-NgvfHmacHex -Key $Context.MacKey -Value ("northgate-plan-v1`n$PlanId`n$ExpiresAtUtc`n$CanonicalPlan"))
}

function Assert-NgvfPlanRecord {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$ExpectedPlanId
    )

    Assert-NgvfExactProperties -InputObject $Record -Expected @(
        'formatVersion', 'planId', 'planHash', 'canonicalPlan', 'registeredAtUtc',
        'expiresAtUtc', 'state', 'approvalState', 'approvalIdHash', 'executionId',
        'quarantineState', 'rollbackState'
    ) -Code 'NGVF-PLAN-RECORD-CORRUPT'
    if ($Record.formatVersion -ne 1 -or
        $Record.planId -cne $ExpectedPlanId -or
        $Record.planHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Record.state -notin @('Registered', 'Applying', 'Applied', 'FailedQuarantineRequired', 'OutcomeUnknownReconciliationRequired') -or
        $Record.approvalState -notin @('Pending', 'Consumed') -or
        $Record.approvalIdHash -cnotmatch '^(?:|[a-f0-9]{64})$' -or
        $Record.executionId -cnotmatch '^(?:|ngx-[a-f0-9]{32})$' -or
        $Record.quarantineState -notin @('not-required', 'required', 'completed') -or
        $Record.rollbackState -notin @('not-required', 'not-applicable', 'required', 'completed')) {
        Throw-NgvfError -Code 'NGVF-PLAN-RECORD-CORRUPT'
    }
    $null = ConvertFrom-NgvfCanonicalPlan -Context $Context -CanonicalPlanJson $Record.canonicalPlan -ValidateFreshness $false
    $expectedHash = Get-NgvfPlanAuthenticationHash -Context $Context -PlanId $Record.planId `
        -ExpiresAtUtc $Record.expiresAtUtc -CanonicalPlan $Record.canonicalPlan
    if (-not (Test-NgvfFixedHexEquals -Left $expectedHash -Right ([string]$Record.planHash))) {
        Throw-NgvfError -Code 'NGVF-PLAN-AUTHENTICATION-FAILED'
    }
}

function Read-NgvfPlanRecord {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$PlanId
    )

    $path = Get-NgvfPlanPath -Context $Context -PlanId $PlanId
    $envelope = Read-NgvfEnvelope -Context $Context -RecordType 'plan-registry' -Path $path
    Assert-NgvfPlanRecord -Context $Context -Record $envelope.record -ExpectedPlanId $PlanId
    return $envelope.record
}

function Save-NgvfPlanRecord {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Record
    )

    Assert-NgvfPlanRecord -Context $Context -Record $Record -ExpectedPlanId $Record.planId
    $path = Get-NgvfPlanPath -Context $Context -PlanId $Record.planId
    $null = Save-NgvfEnvelope -Context $Context -RecordType 'plan-registry' -Record $Record -Path $path
}

function Write-NgvfAudit {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$EventName,
        [Parameter(Mandatory)][string]$Outcome,
        [Parameter(Mandatory)][string]$ReasonCode,
        [string]$PlanId = '',
        [string]$PrincipalHash = ''
    )

    $safePlanId = if ($PlanId -and (Test-NgvfPlanId -PlanId $PlanId)) { $PlanId } else { '' }
    $safePrincipalHash = if ($PrincipalHash -cmatch '^[a-f0-9]{64}$') { $PrincipalHash } else { '' }
    $event = [pscustomobject][ordered]@{
        eventVersion = 1
        eventId = 'nge-' + (New-NgvfRandomHex -ByteCount 16)
        occurredAtUtc = Format-NgvfUtc -Value (Get-NgvfNow -Context $Context)
        operation = $Operation
        eventName = $EventName
        outcome = $Outcome
        reasonCode = $ReasonCode
        planId = $safePlanId
        principalHash = $safePrincipalHash
        simulated = $true
    }
    $eventAuthenticationHash = Get-NgvfHmacHex -Key $Context.MacKey `
        -Value ("northgate-audit-event-v1`n" + (ConvertTo-NgvfCanonicalJson -InputObject $event))
    $authenticatedEvent = [pscustomobject][ordered]@{
        event = $event
        eventAuthenticationHash = $eventAuthenticationHash
    }
    $line = ConvertTo-NgvfCanonicalJson -InputObject $authenticatedEvent
    $writer = $Context.AuditWriter
    try {
        $written = & $writer $line
        if ($written -isnot [bool] -or $written -ne $true) {
            Throw-NgvfError -Code 'NGVF-AUDIT-UNAVAILABLE'
        }
    }
    catch {
        Throw-NgvfError -Code 'NGVF-AUDIT-UNAVAILABLE'
    }
}

function Assert-NgvfSimulationBoundary {
    param([Parameter(Mandatory)][object]$Context)

    if ($Context.SimulationEnabled -isnot [bool] -or $Context.SimulationEnabled -ne $true -or
        $Context.LiveApplyEnabled -isnot [bool] -or $Context.LiveApplyEnabled -ne $false -or
        $Context.Deployed -isnot [bool] -or $Context.Deployed -ne $false -or
        $Context.SimulationAdapterId -isnot [string] -or
        $Context.SimulationAdapterId -cne 'fixed-engine-mock-v1') {
        Throw-NgvfError -Code 'NGVF-SCAFFOLD-NOT-SIMULATION-ONLY'
    }
    if ($Context.StateProtectionVerified -isnot [bool] -or $Context.StateProtectionVerified -ne $true) {
        Throw-NgvfError -Code 'NGVF-STATE-PROTECTION-UNVERIFIED'
    }
}

function Assert-NgvfAuthenticated {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][object]$AuthenticationContext,
        [Parameter(Mandatory)][string]$RequiredRole
    )

    $authenticator = $Context.Authenticator
    try {
        $result = & $authenticator $Operation $AuthenticationContext
    }
    catch {
        $result = $null
    }
    $valid = $false
    if ($null -ne $result) {
        $actualProperties = @($result.PSObject.Properties.Name)
        [array]::Sort($actualProperties, [System.StringComparer]::Ordinal)
        $valid = (($actualProperties -join '|') -ceq 'authenticated|principalId|roles') -and
            $result.authenticated -is [bool] -and $result.authenticated -eq $true -and
            $result.principalId -is [string] -and $result.principalId -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -and
            $result.roles -is [System.Array] -and @($result.roles).Count -gt 0
        if ($valid) {
            foreach ($role in @($result.roles)) {
                if ($role -isnot [string] -or $role -cnotmatch '^[a-z][a-z0-9-]{0,31}$') {
                    $valid = $false
                    break
                }
            }
        }
        if ($valid -and $RequiredRole -cnotin @($result.roles)) {
            $valid = $false
        }
    }
    if (-not $valid) {
        Write-NgvfAudit -Context $Context -Operation $Operation -EventName 'authentication-rejected' `
            -Outcome 'rejected' -ReasonCode 'NGVF-AUTHENTICATION-FAILED'
        Throw-NgvfError -Code 'NGVF-AUTHENTICATION-FAILED'
    }
    return [pscustomobject][ordered]@{
        principalHash = Get-NgvfSha256Hex -Value ([string]$result.principalId)
        requiredRole = $RequiredRole
    }
}

function Enter-NgvfWriterLock {
    param([Parameter(Mandatory)][object]$Context)

    $null = $Context
    try {
        $semaphore = New-Object System.Threading.Semaphore(1, 1, 'Global\NorthGateVmFactoryWriter-v1')
        if (-not $semaphore.WaitOne(0)) {
            $semaphore.Dispose()
            Throw-NgvfError -Code 'NGVF-WRITER-LOCK-BUSY'
        }
        return $semaphore
    }
    catch {
        if ($_.Exception.Message -ceq 'NGVF-WRITER-LOCK-BUSY') {
            throw
        }
        Throw-NgvfError -Code 'NGVF-WRITER-LOCK-UNAVAILABLE'
    }
}

function Exit-NgvfWriterLock {
    param([Parameter(Mandatory)][System.Threading.Semaphore]$Lock)

    try {
        $null = $Lock.Release()
    }
    finally {
        $Lock.Dispose()
    }
}

function New-NgvfEngineContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [Parameter(Mandatory)][byte[]]$MacKey,
        [Parameter(Mandatory)][scriptblock]$Authenticator,
        [Parameter(Mandatory)][scriptblock]$RepositoryVerifier,
        [Parameter(Mandatory)][scriptblock]$ApprovalProvider,
        [Parameter(Mandatory)][scriptblock]$Clock,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InitialLedgerEntries,
        [scriptblock]$AuditWriter,
        [bool]$StateProtectionVerified = $false,
        [bool]$SimulationEnabled = $false,
        [ValidateSet('Succeed', 'Fail', 'Throw', 'Invalid')][string]$SimulationScenario = 'Succeed',
        [ValidateRange(1, 15)][int]$PlanTtlMinutes = 10,
        [ValidateRange(1, 60)][int]$MaximumPlanAgeMinutes = 15
    )

    if ($MacKey.Length -lt 32) {
        Throw-NgvfError -Code 'NGVF-MAC-KEY-INVALID'
    }
    $fullRoot = [System.IO.Path]::GetFullPath($StateRoot)
    if (-not [System.IO.Path]::IsPathRooted($fullRoot)) {
        Throw-NgvfError -Code 'NGVF-STATE-ROOT-INVALID'
    }
    $ancestor = New-Object System.IO.DirectoryInfo($fullRoot)
    while ($null -ne $ancestor) {
        if (Test-Path -LiteralPath (Join-Path $ancestor.FullName '.git')) {
            Throw-NgvfError -Code 'NGVF-STATE-ROOT-REPOSITORY-FORBIDDEN'
        }
        $ancestor = $ancestor.Parent
    }
    $null = [System.IO.Directory]::CreateDirectory($fullRoot)
    $rootItem = Get-Item -LiteralPath $fullRoot -Force
    if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Throw-NgvfError -Code 'NGVF-STATE-ROOT-REPARSE-FORBIDDEN'
    }

    $plansRoot = Join-Path $fullRoot 'plans'
    $receiptsRoot = Join-Path $fullRoot 'receipts'
    $auditRoot = Join-Path $fullRoot 'audit'
    foreach ($directory in @($plansRoot, $receiptsRoot, $auditRoot)) {
        $null = [System.IO.Directory]::CreateDirectory($directory)
    }
    $auditPath = Join-Path $auditRoot 'events.ndjson'
    if ($null -eq $AuditWriter) {
        $defaultAuditPath = $auditPath
        $AuditWriter = {
            param([string]$CanonicalEvent)
            $encoding = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::AppendAllText($defaultAuditPath, $CanonicalEvent + [System.Environment]::NewLine, $encoding)
            return $true
        }.GetNewClosure()
    }

    $context = [pscustomobject][ordered]@{
        EngineVersion = $script:EngineVersion
        ReleaseStatus = 'scaffold'
        Deployed = $false
        LiveApplyEnabled = $false
        SimulationEnabled = $SimulationEnabled
        StateProtectionVerified = $StateProtectionVerified
        DirectMutationMethodsExposed = $false
        SimulationAdapterId = 'fixed-engine-mock-v1'
        SimulationScenario = $SimulationScenario
        SimulationInvocationCount = 0
        StateRoot = $fullRoot
        PlansRoot = $plansRoot
        ReceiptsRoot = $receiptsRoot
        LedgerPath = Join-Path $fullRoot 'identity-ledger.json'
        AuditPath = $auditPath
        MacKey = [byte[]]$MacKey.Clone()
        Authenticator = $Authenticator
        RepositoryVerifier = $RepositoryVerifier
        ApprovalProvider = $ApprovalProvider
        Clock = $Clock
        AuditWriter = $AuditWriter
        PlanTtlMinutes = $PlanTtlMinutes
        MaximumPlanAgeMinutes = $MaximumPlanAgeMinutes
    }

    if (-not (Test-Path -LiteralPath $context.LedgerPath -PathType Leaf)) {
        $ledger = [pscustomobject][ordered]@{
            formatVersion = 1
            entries = @($InitialLedgerEntries)
        }
        Save-NgvfLedger -Context $context -Ledger $ledger
    }
    else {
        $null = Read-NgvfLedger -Context $context
    }
    return $context
}

function Get-NgvfPublicPlan {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][object]$Plan
    )

    [pscustomobject][ordered]@{
        operation = 'vm_factory_get_plan'
        planId = $Record.planId
        planHash = $Record.planHash
        registeredAtUtc = $Record.registeredAtUtc
        expiresAtUtc = $Record.expiresAtUtc
        state = $Record.state
        approvalState = $Record.approvalState
        quarantineState = $Record.quarantineState
        rollbackState = $Record.rollbackState
        repository = $Plan.repository
        changeId = $Plan.changeId
        operations = $Plan.operations
        simulated = $true
    }
}

function Get-NorthGateVmFactoryEngineState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$AuthenticationContext
    )

    $principal = Assert-NgvfAuthenticated -Context $Context -Operation 'vm_factory_get_state' `
        -AuthenticationContext $AuthenticationContext -RequiredRole 'reader'
    Write-NgvfAudit -Context $Context -Operation 'vm_factory_get_state' -EventName 'state-read' `
        -Outcome 'succeeded' -ReasonCode 'NGVF-STATE-READ' -PrincipalHash $principal.principalHash
    [pscustomobject][ordered]@{
        operation = 'vm_factory_get_state'
        engineVersion = $Context.EngineVersion
        releaseStatus = $Context.ReleaseStatus
        deployed = $Context.Deployed
        liveApplyEnabled = $Context.LiveApplyEnabled
        simulationEnabled = $Context.SimulationEnabled
        repositoryVerification = 'exact-identity-commit-tree-and-protected-branch'
        stateProtectionVerified = $Context.StateProtectionVerified
        directMutationMethodsExposed = $Context.DirectMutationMethodsExposed
        applicationAuthenticationRequired = $true
        planAuthentication = 'HMAC-SHA-256'
        writerLock = 'host-wide-file-lock'
        adapter = $Context.SimulationAdapterId
        simulated = $true
    }
}

function Register-NorthGateVmFactoryEnginePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$AuthenticationContext,
        [Parameter(Mandatory)][string]$CanonicalPlanJson
    )

    $principal = Assert-NgvfAuthenticated -Context $Context -Operation 'vm_factory_register_plan' `
        -AuthenticationContext $AuthenticationContext -RequiredRole 'planner'
    Assert-NgvfSimulationBoundary -Context $Context
    $parsed = ConvertFrom-NgvfCanonicalPlan -Context $Context -CanonicalPlanJson $CanonicalPlanJson

    $lock = Enter-NgvfWriterLock -Context $Context
    try {
        Assert-NgvfPlanLedgerBinding -Context $Context -Plan $parsed.Plan
        Write-NgvfAudit -Context $Context -Operation 'vm_factory_register_plan' -EventName 'registration-preflight' `
            -Outcome 'permitted' -ReasonCode 'NGVF-REGISTRATION-PREFLIGHT-PASSED' -PrincipalHash $principal.principalHash
        $planId = ''
        for ($attempt = 0; $attempt -lt 4; $attempt++) {
            $candidatePlanId = 'ngp-' + (New-NgvfRandomHex -ByteCount 32)
            $candidatePath = Get-NgvfPlanPath -Context $Context -PlanId $candidatePlanId
            if (-not (Test-Path -LiteralPath $candidatePath)) {
                $planId = $candidatePlanId
                break
            }
        }
        if (-not $planId) {
            Throw-NgvfError -Code 'NGVF-PLAN-ID-COLLISION'
        }
        $registeredAt = Get-NgvfNow -Context $Context
        $registeredAtUtc = Format-NgvfUtc -Value $registeredAt
        $expiresAtUtc = Format-NgvfUtc -Value $registeredAt.AddMinutes($Context.PlanTtlMinutes)
        $planHash = Get-NgvfPlanAuthenticationHash -Context $Context -PlanId $planId `
            -ExpiresAtUtc $expiresAtUtc -CanonicalPlan $parsed.CanonicalJson
        $record = [pscustomobject][ordered]@{
            formatVersion = 1
            planId = $planId
            planHash = $planHash
            canonicalPlan = $parsed.CanonicalJson
            registeredAtUtc = $registeredAtUtc
            expiresAtUtc = $expiresAtUtc
            state = 'Registered'
            approvalState = 'Pending'
            approvalIdHash = ''
            executionId = ''
            quarantineState = 'not-required'
            rollbackState = 'not-required'
        }
        Save-NgvfPlanRecord -Context $Context -Record $record
        Write-NgvfAudit -Context $Context -Operation 'vm_factory_register_plan' -EventName 'plan-registered' `
            -Outcome 'succeeded' -ReasonCode 'NGVF-PLAN-REGISTERED' -PlanId $planId `
            -PrincipalHash $principal.principalHash
        return [pscustomobject][ordered]@{
            operation = 'vm_factory_register_plan'
            accepted = $true
            planId = $planId
            planHash = $planHash
            expiresAtUtc = $expiresAtUtc
            state = 'Registered'
            simulated = $true
        }
    }
    finally {
        Exit-NgvfWriterLock -Lock $lock
    }
}

function Get-NorthGateVmFactoryEnginePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$AuthenticationContext,
        [Parameter(Mandatory)][AllowEmptyString()][string]$PlanId
    )

    $principal = Assert-NgvfAuthenticated -Context $Context -Operation 'vm_factory_get_plan' `
        -AuthenticationContext $AuthenticationContext -RequiredRole 'reader'
    if (-not (Test-NgvfPlanId -PlanId $PlanId)) {
        Throw-NgvfError -Code 'NGVF-PLAN-ID-INVALID'
    }
    $record = Read-NgvfPlanRecord -Context $Context -PlanId $PlanId
    $parsed = ConvertFrom-NgvfCanonicalPlan -Context $Context -CanonicalPlanJson $record.canonicalPlan -ValidateFreshness $false
    Write-NgvfAudit -Context $Context -Operation 'vm_factory_get_plan' -EventName 'plan-read' `
        -Outcome 'succeeded' -ReasonCode 'NGVF-PLAN-READ' -PlanId $PlanId `
        -PrincipalHash $principal.principalHash
    return (Get-NgvfPublicPlan -Record $record -Plan $parsed.Plan)
}

function Assert-NgvfApproval {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Record
    )

    $provider = $Context.ApprovalProvider
    try {
        $approval = & $provider $Record.planId $Record.planHash
    }
    catch {
        Throw-NgvfError -Code 'NGVF-APPROVAL-UNAVAILABLE'
    }
    if ($null -eq $approval) {
        Throw-NgvfError -Code 'NGVF-EXACT-APPROVAL-REQUIRED'
    }
    Assert-NgvfExactProperties -InputObject $approval -Expected @(
        'approved', 'planId', 'planHash', 'approvalId', 'oneTime'
    ) -Code 'NGVF-EXACT-APPROVAL-REQUIRED'
    if ($approval.approved -isnot [bool] -or
        $approval.oneTime -isnot [bool] -or
        $approval.planId -isnot [string] -or
        $approval.planHash -isnot [string] -or
        $approval.approvalId -isnot [string] -or
        $approval.approved -ne $true -or
        $approval.oneTime -ne $true -or
        $approval.planId -cne $Record.planId -or
        $approval.planHash -cne $Record.planHash -or
        $approval.approvalId -cnotmatch '^nga-[A-Za-z0-9-]{8,64}$') {
        Throw-NgvfError -Code 'NGVF-EXACT-APPROVAL-REQUIRED'
    }
    return $approval
}

function Assert-NgvfApprovalNotConsumed {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ApprovalIdHash,
        [Parameter(Mandatory)][string]$CurrentPlanId
    )

    foreach ($planFile in @(Get-ChildItem -LiteralPath $Context.PlansRoot -File -Filter 'ngp-*.json')) {
        $registeredPlanId = [System.IO.Path]::GetFileNameWithoutExtension($planFile.Name)
        if (-not (Test-NgvfPlanId -PlanId $registeredPlanId)) {
            Throw-NgvfError -Code 'NGVF-PLAN-REGISTRY-CORRUPT'
        }
        $registeredRecord = Read-NgvfPlanRecord -Context $Context -PlanId $registeredPlanId
        if ($registeredPlanId -cne $CurrentPlanId -and
            $registeredRecord.approvalIdHash -cne '' -and
            (Test-NgvfFixedHexEquals -Left $registeredRecord.approvalIdHash -Right $ApprovalIdHash)) {
            Throw-NgvfError -Code 'NGVF-APPROVAL-ALREADY-CONSUMED'
        }
    }
}

function Invoke-NgvfFixedSimulationAdapter {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Request
    )

    Assert-NgvfSimulationBoundary -Context $Context
    $Context.SimulationInvocationCount = [int]$Context.SimulationInvocationCount + 1
    if ($Context.SimulationScenario -eq 'Throw') {
        Throw-NgvfError -Code 'NGVF-SIMULATION-ADAPTER-FAILURE'
    }
    if ($Context.SimulationScenario -eq 'Invalid') {
        return [pscustomobject]@{
            status = 'Succeeded'
            unexpected = 'fixed-invalid-test-result'
        }
    }

    $outcomes = @()
    foreach ($operation in @($Request.plan.operations)) {
        $digits = ([string]$operation.assetId).Substring(6).PadLeft(12, [char]'0')
        $vmId = '00000000-0000-0000-0000-' + $digits
        if ($Context.SimulationScenario -eq 'Fail') {
            $operationOutcome = 'Quarantined'
        }
        elseif ($operation.action -eq 'NoOp') {
            $operationOutcome = 'NoOp'
            $vmId = ''
        }
        else {
            $operationOutcome = 'Created'
        }
        $outcomes += [pscustomobject][ordered]@{
            assetId = $operation.assetId
            name = $operation.name
            vmId = $vmId
            outcome = $operationOutcome
        }
    }
    return [pscustomobject][ordered]@{
        status = if ($Context.SimulationScenario -eq 'Fail') { 'Failed' } else { 'Succeeded' }
        afterStateHash = ('2' * 64)
        outcomes = $outcomes
    }
}

function Assert-NgvfProvisionerResult {
    param(
        [Parameter(Mandatory)][object]$Result,
        [Parameter(Mandatory)][object]$Plan
    )

    Assert-NgvfExactProperties -InputObject $Result -Expected @('status', 'afterStateHash', 'outcomes') `
        -Code 'NGVF-PROVISIONER-RESULT-INVALID'
    if ($Result.status -isnot [string] -or $Result.afterStateHash -isnot [string] -or
        $Result.status -notin @('Succeeded', 'Failed') -or $Result.afterStateHash -cnotmatch '^[a-f0-9]{64}$') {
        Throw-NgvfError -Code 'NGVF-PROVISIONER-RESULT-INVALID'
    }
    if ($Result.outcomes -isnot [System.Array]) {
        Throw-NgvfError -Code 'NGVF-PROVISIONER-RESULT-INVALID'
    }
    $outcomes = @($Result.outcomes)
    if ($outcomes.Count -gt @($Plan.operations).Count) {
        Throw-NgvfError -Code 'NGVF-PROVISIONER-RESULT-INVALID'
    }
    if ($Result.status -eq 'Succeeded' -and $outcomes.Count -ne @($Plan.operations).Count) {
        Throw-NgvfError -Code 'NGVF-PROVISIONER-RESULT-INVALID'
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($outcome in $outcomes) {
        Assert-NgvfExactProperties -InputObject $outcome -Expected @('assetId', 'name', 'vmId', 'outcome') `
            -Code 'NGVF-PROVISIONER-RESULT-INVALID'
        $planOperation = @($Plan.operations | Where-Object {
            $_.assetId -ieq $outcome.assetId -and $_.name -ieq $outcome.name
        })
        if ($outcome.assetId -isnot [string] -or $outcome.name -isnot [string] -or
            $outcome.vmId -isnot [string] -or $outcome.outcome -isnot [string] -or
            $planOperation.Count -ne 1 -or -not $seen.Add([string]$outcome.assetId) -or
            $outcome.outcome -notin @('Created', 'NoOp', 'Failed', 'Quarantined') -or
            ($outcome.vmId -cne '' -and $outcome.vmId -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')) {
            Throw-NgvfError -Code 'NGVF-PROVISIONER-RESULT-INVALID'
        }
        if ($Result.status -eq 'Succeeded') {
            $expectedOutcome = if ($planOperation[0].action -eq 'Create') { 'Created' } else { 'NoOp' }
            if ($outcome.outcome -cne $expectedOutcome -or
                ($expectedOutcome -eq 'Created' -and $outcome.vmId -ceq '') -or
                ($expectedOutcome -eq 'NoOp' -and $outcome.vmId -cne '')) {
                Throw-NgvfError -Code 'NGVF-PROVISIONER-RESULT-INVALID'
            }
        }
    }
}

function Update-NgvfLedgerFromOutcome {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$ProvisionerResult
    )

    $ledger = Read-NgvfLedger -Context $Context
    if ($ProvisionerResult.status -eq 'OutcomeUnknown') {
        foreach ($operation in @($Plan.operations)) {
            $unknownEntry = @($ledger.entries | Where-Object {
                $_.assetId -ieq $operation.assetId -and $_.reservationId -ceq $operation.reservationId
            })[0]
            $unknownEntry.state = 'OutcomeUnknown'
            $unknownEntry.vmId = ''
        }
        Save-NgvfLedger -Context $Context -Ledger $ledger
        return
    }
    foreach ($outcome in @($ProvisionerResult.outcomes)) {
        $operation = @($Plan.operations | Where-Object { $_.assetId -ieq $outcome.assetId })[0]
        if ($operation.action -ne 'Create' -or $outcome.vmId -ceq '') {
            continue
        }
        $entry = @($ledger.entries | Where-Object {
            $_.assetId -ieq $operation.assetId -and $_.reservationId -ceq $operation.reservationId
        })[0]
        $entry.vmId = ([string]$outcome.vmId).ToLowerInvariant()
        if ($ProvisionerResult.status -eq 'Succeeded' -and $outcome.outcome -eq 'Created') {
            $entry.state = 'Bound'
        }
        else {
            $entry.state = 'Quarantined'
        }
    }
    Save-NgvfLedger -Context $Context -Ledger $ledger
}

function New-NgvfReceiptRecord {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$PlanRecord,
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$ProvisionerResult,
        [Parameter(Mandatory)][string]$ReasonCode,
        [Parameter(Mandatory)][string]$ExecutorPrincipalHash
    )

    $outcome = if ($ProvisionerResult.status -eq 'Succeeded') {
        'Succeeded'
    }
    elseif ($ProvisionerResult.status -eq 'OutcomeUnknown') {
        'OutcomeUnknown'
    }
    else {
        'Failed'
    }
    $quarantineState = if ($outcome -eq 'Succeeded') { 'not-required' } else { 'required' }
    $receiptIdMaterial = "northgate-receipt-v1`n$($PlanRecord.planId)`n$($PlanRecord.planHash)"
    $receiptId = 'ngr-' + (Get-NgvfHmacHex -Key $Context.MacKey -Value $receiptIdMaterial)
    [pscustomobject][ordered]@{
        formatVersion = 1
        receiptId = $receiptId
        planId = $PlanRecord.planId
        planHash = $PlanRecord.planHash
        executionId = $PlanRecord.executionId
        executorPrincipalHash = $ExecutorPrincipalHash
        approvalEvidenceHash = $PlanRecord.approvalIdHash
        repositoryIdentity = $Plan.repository.identity
        repositoryCommit = $Plan.repository.commit
        repositoryTree = $Plan.repository.tree
        policyHash = $Plan.policyHash
        catalogHash = $Plan.catalogHash
        plannerVersion = $Plan.plannerVersion
        provisionerVersion = $Plan.provisionerVersion
        receiptSignerId = 'host-hmac-scaffold-v1'
        outcome = $outcome
        reasonCode = $ReasonCode
        completedAtUtc = Format-NgvfUtc -Value (Get-NgvfNow -Context $Context)
        beforeStateHash = $Plan.observedStateHash
        afterStateHash = $ProvisionerResult.afterStateHash
        afterStateVerified = ($ProvisionerResult.status -ne 'OutcomeUnknown')
        rollbackState = 'not-applicable'
        quarantineState = $quarantineState
        operations = @($ProvisionerResult.outcomes)
        simulated = $true
    }
}

function Assert-NgvfReceiptRecord {
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$Receipt,
        [Parameter(Mandatory)][string]$ExpectedPlanId,
        [Parameter(Mandatory)][string]$ExpectedPlanHash
    )

    Assert-NgvfExactProperties -InputObject $Receipt -Expected @(
        'formatVersion', 'receiptId', 'planId', 'planHash', 'executionId',
        'executorPrincipalHash', 'approvalEvidenceHash', 'repositoryIdentity',
        'repositoryCommit', 'repositoryTree', 'policyHash', 'catalogHash',
        'plannerVersion', 'provisionerVersion', 'receiptSignerId', 'outcome',
        'reasonCode', 'completedAtUtc', 'beforeStateHash', 'afterStateHash',
        'afterStateVerified', 'rollbackState', 'quarantineState', 'operations', 'simulated'
    ) -Code 'NGVF-RECEIPT-CORRUPT'
    if ($Receipt.formatVersion -ne 1 -or
        $Receipt.receiptId -cnotmatch '^ngr-[a-f0-9]{64}$' -or
        $Receipt.planId -cne $ExpectedPlanId -or
        $Receipt.planHash -cne $ExpectedPlanHash -or
        $Receipt.executionId -cnotmatch '^ngx-[a-f0-9]{32}$' -or
        $Receipt.executorPrincipalHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Receipt.approvalEvidenceHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Receipt.repositoryIdentity -cne $script:ApprovedRepositoryIdentity -or
        $Receipt.repositoryCommit -cnotmatch '^[a-f0-9]{40}$' -or
        $Receipt.repositoryTree -cnotmatch '^[a-f0-9]{40}$' -or
        $Receipt.policyHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Receipt.catalogHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Receipt.plannerVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $Receipt.provisionerVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $Receipt.receiptSignerId -cne 'host-hmac-scaffold-v1' -or
        $Receipt.outcome -notin @('Succeeded', 'Failed', 'OutcomeUnknown') -or
        $Receipt.reasonCode -cnotmatch '^NGVF-[A-Z0-9-]+$' -or
        $Receipt.beforeStateHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Receipt.afterStateHash -cnotmatch '^[a-f0-9]{64}$' -or
        $Receipt.afterStateVerified -isnot [bool] -or
        ($Receipt.outcome -eq 'OutcomeUnknown' -and $Receipt.afterStateVerified -ne $false) -or
        $Receipt.rollbackState -notin @('not-applicable', 'required', 'completed') -or
        $Receipt.quarantineState -notin @('not-required', 'required', 'completed') -or
        $Receipt.simulated -ne $true -or
        $Receipt.operations -isnot [System.Array]) {
        Throw-NgvfError -Code 'NGVF-RECEIPT-CORRUPT'
    }
    $expectedReceiptId = 'ngr-' + (Get-NgvfHmacHex -Key $Context.MacKey `
        -Value ("northgate-receipt-v1`n$($Receipt.planId)`n$($Receipt.planHash)"))
    if (-not (Test-NgvfFixedHexEquals -Left $expectedReceiptId.Substring(4) -Right $Receipt.receiptId.Substring(4))) {
        Throw-NgvfError -Code 'NGVF-RECEIPT-CORRUPT'
    }
}

function Assert-NgvfReceiptPlanBinding {
    param(
        [Parameter(Mandatory)][object]$Receipt,
        [Parameter(Mandatory)][object]$Plan
    )

    if ($Receipt.repositoryIdentity -cne $Plan.repository.identity -or
        $Receipt.repositoryCommit -cne $Plan.repository.commit -or
        $Receipt.repositoryTree -cne $Plan.repository.tree -or
        $Receipt.policyHash -cne $Plan.policyHash -or
        $Receipt.catalogHash -cne $Plan.catalogHash -or
        $Receipt.plannerVersion -cne $Plan.plannerVersion -or
        $Receipt.provisionerVersion -cne $Plan.provisionerVersion -or
        $Receipt.beforeStateHash -cne $Plan.observedStateHash) {
        Throw-NgvfError -Code 'NGVF-RECEIPT-PLAN-BINDING-FAILED'
    }
}

function Get-NgvfPublicReceipt {
    param([Parameter(Mandatory)][object]$Envelope)

    $receipt = $Envelope.record
    [pscustomobject][ordered]@{
        operation = 'vm_factory_apply_plan'
        receiptId = $receipt.receiptId
        planId = $receipt.planId
        planHash = $receipt.planHash
        executionId = $receipt.executionId
        executorPrincipalHash = $receipt.executorPrincipalHash
        approvalEvidenceHash = $receipt.approvalEvidenceHash
        repositoryIdentity = $receipt.repositoryIdentity
        repositoryCommit = $receipt.repositoryCommit
        repositoryTree = $receipt.repositoryTree
        policyHash = $receipt.policyHash
        catalogHash = $receipt.catalogHash
        plannerVersion = $receipt.plannerVersion
        provisionerVersion = $receipt.provisionerVersion
        receiptSignerId = $receipt.receiptSignerId
        outcome = $receipt.outcome
        reasonCode = $receipt.reasonCode
        completedAtUtc = $receipt.completedAtUtc
        beforeStateHash = $receipt.beforeStateHash
        afterStateHash = $receipt.afterStateHash
        afterStateVerified = $receipt.afterStateVerified
        rollbackState = $receipt.rollbackState
        quarantineState = $receipt.quarantineState
        operations = $receipt.operations
        receiptAuthenticationHash = $Envelope.recordMac
        simulated = $true
    }
}

function Invoke-NorthGateVmFactoryEngineApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][object]$AuthenticationContext,
        [Parameter(Mandatory)][AllowEmptyString()][string]$PlanId
    )

    $principal = Assert-NgvfAuthenticated -Context $Context -Operation 'vm_factory_apply_plan' `
        -AuthenticationContext $AuthenticationContext -RequiredRole 'executor'
    Assert-NgvfSimulationBoundary -Context $Context
    if (-not (Test-NgvfPlanId -PlanId $PlanId)) {
        Throw-NgvfError -Code 'NGVF-PLAN-ID-INVALID'
    }

    $lock = Enter-NgvfWriterLock -Context $Context
    try {
        $receiptPath = Get-NgvfReceiptPath -Context $Context -PlanId $PlanId
        if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
            $existingEnvelope = Read-NgvfEnvelope -Context $Context -RecordType 'execution-receipt' -Path $receiptPath
            $existingPlanRecord = Read-NgvfPlanRecord -Context $Context -PlanId $PlanId
            $existingParsedPlan = ConvertFrom-NgvfCanonicalPlan -Context $Context `
                -CanonicalPlanJson $existingPlanRecord.canonicalPlan -ValidateFreshness $false
            Assert-NgvfReceiptRecord -Context $Context -Receipt $existingEnvelope.record `
                -ExpectedPlanId $PlanId -ExpectedPlanHash $existingPlanRecord.planHash
            Assert-NgvfReceiptPlanBinding -Receipt $existingEnvelope.record -Plan $existingParsedPlan.Plan
            Write-NgvfAudit -Context $Context -Operation 'vm_factory_apply_plan' -EventName 'idempotent-receipt-read' `
                -Outcome 'succeeded' -ReasonCode 'NGVF-IDEMPOTENT-RECEIPT' -PlanId $PlanId `
                -PrincipalHash $principal.principalHash
            return (Get-NgvfPublicReceipt -Envelope $existingEnvelope)
        }

        $record = Read-NgvfPlanRecord -Context $Context -PlanId $PlanId
        if ($record.state -cne 'Registered' -or $record.approvalState -cne 'Pending') {
            Throw-NgvfError -Code 'NGVF-PLAN-STATE-NOT-APPLICABLE'
        }
        $now = Get-NgvfNow -Context $Context
        $expiry = [System.DateTimeOffset]::ParseExact(
            $record.expiresAtUtc,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal
        )
        if ($now -ge $expiry) {
            Throw-NgvfError -Code 'NGVF-PLAN-EXPIRED'
        }
        $parsed = ConvertFrom-NgvfCanonicalPlan -Context $Context -CanonicalPlanJson $record.canonicalPlan -ValidateFreshness $false
        Assert-NgvfPlanLedgerBinding -Context $Context -Plan $parsed.Plan
        Write-NgvfAudit -Context $Context -Operation 'vm_factory_apply_plan' -EventName 'apply-preflight' `
            -Outcome 'permitted' -ReasonCode 'NGVF-APPLY-PREFLIGHT-PASSED' -PlanId $PlanId `
            -PrincipalHash $principal.principalHash

        $approval = Assert-NgvfApproval -Context $Context -Record $record
        if ((Get-NgvfNow -Context $Context) -ge $expiry) {
            Throw-NgvfError -Code 'NGVF-PLAN-EXPIRED'
        }
        $approvalIdHash = Get-NgvfSha256Hex -Value ([string]$approval.approvalId)
        Assert-NgvfApprovalNotConsumed -Context $Context -ApprovalIdHash $approvalIdHash -CurrentPlanId $PlanId
        $record.approvalState = 'Consumed'
        $record.approvalIdHash = $approvalIdHash
        $record.executionId = 'ngx-' + (New-NgvfRandomHex -ByteCount 16)
        $record.state = 'Applying'
        Save-NgvfPlanRecord -Context $Context -Record $record
        Write-NgvfAudit -Context $Context -Operation 'vm_factory_apply_plan' -EventName 'approval-consumed' `
            -Outcome 'succeeded' -ReasonCode 'NGVF-EXACT-APPROVAL-CONSUMED' -PlanId $PlanId `
            -PrincipalHash $principal.principalHash

        $reasonCode = 'NGVF-SIMULATION-SUCCEEDED'
        try {
            $provisionerResult = Invoke-NgvfFixedSimulationAdapter -Context $Context -Request ([pscustomobject][ordered]@{
                executionId = $record.executionId
                plan = $parsed.Plan
                simulated = $true
            })
            Assert-NgvfProvisionerResult -Result $provisionerResult -Plan $parsed.Plan
            if ($provisionerResult.status -ne 'Succeeded') {
                $reasonCode = 'NGVF-PROVISIONER-FAILED'
            }
        }
        catch {
            $unknownStateHash = Get-NgvfHmacHex -Key $Context.MacKey `
                -Value ("northgate-outcome-unknown-v1`n$PlanId`n$($record.executionId)")
            $provisionerResult = [pscustomobject][ordered]@{
                status = 'OutcomeUnknown'
                afterStateHash = $unknownStateHash
                outcomes = @()
            }
            $reasonCode = 'NGVF-OUTCOME-UNKNOWN'
        }

        try {
            Update-NgvfLedgerFromOutcome -Context $Context -Plan $parsed.Plan -ProvisionerResult $provisionerResult
        }
        catch {
            $provisionerResult = [pscustomobject][ordered]@{
                status = 'Failed'
                afterStateHash = $provisionerResult.afterStateHash
                outcomes = @($provisionerResult.outcomes)
            }
            $reasonCode = 'NGVF-LEDGER-UPDATE-FAILED'
        }
        $receipt = New-NgvfReceiptRecord -Context $Context -PlanRecord $record -Plan $parsed.Plan `
            -ProvisionerResult $provisionerResult -ReasonCode $reasonCode `
            -ExecutorPrincipalHash $principal.principalHash
        Assert-NgvfReceiptRecord -Context $Context -Receipt $receipt -ExpectedPlanId $PlanId `
            -ExpectedPlanHash $record.planHash
        Assert-NgvfReceiptPlanBinding -Receipt $receipt -Plan $parsed.Plan
        $null = Save-NgvfEnvelope -Context $Context -RecordType 'execution-receipt' `
            -Record $receipt -Path $receiptPath
        $receiptEnvelope = Read-NgvfEnvelope -Context $Context -RecordType 'execution-receipt' -Path $receiptPath
        Assert-NgvfReceiptRecord -Context $Context -Receipt $receiptEnvelope.record `
            -ExpectedPlanId $PlanId -ExpectedPlanHash $record.planHash
        Assert-NgvfReceiptPlanBinding -Receipt $receiptEnvelope.record -Plan $parsed.Plan

        if ($provisionerResult.status -eq 'Succeeded') {
            $record.state = 'Applied'
            $record.quarantineState = 'not-required'
            $record.rollbackState = 'not-applicable'
            $auditOutcome = 'succeeded'
        }
        elseif ($provisionerResult.status -eq 'OutcomeUnknown') {
            $record.state = 'OutcomeUnknownReconciliationRequired'
            $record.quarantineState = 'required'
            $record.rollbackState = 'not-applicable'
            $auditOutcome = 'failed'
        }
        else {
            $record.state = 'FailedQuarantineRequired'
            $record.quarantineState = 'required'
            $record.rollbackState = 'not-applicable'
            $auditOutcome = 'failed'
        }
        Save-NgvfPlanRecord -Context $Context -Record $record
        Write-NgvfAudit -Context $Context -Operation 'vm_factory_apply_plan' -EventName 'simulation-completed' `
            -Outcome $auditOutcome -ReasonCode $reasonCode -PlanId $PlanId `
            -PrincipalHash $principal.principalHash
        return (Get-NgvfPublicReceipt -Envelope $receiptEnvelope)
    }
    finally {
        Exit-NgvfWriterLock -Lock $lock
    }
}

Export-ModuleMember -Function @(
    'Get-NorthGateVmFactoryEngineState',
    'Register-NorthGateVmFactoryEnginePlan',
    'Get-NorthGateVmFactoryEnginePlan',
    'Invoke-NorthGateVmFactoryEngineApply'
)
