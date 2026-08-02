Set-StrictMode -Version Latest

$script:PromotionCandidateVersion = '0.1.0'
$script:EnvelopeSchema = 'northgate/promotion-envelope/v1'
$script:LedgerSchema = 'northgate/promotion-replay-ledger/v1'
$script:InstallOperation = 'install-control-plane-candidate'
$script:SignatureAlgorithm = 'RSASSA-PKCS1-v1_5-SHA256'
$script:Utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
$script:Utf8Plain = New-Object System.Text.UTF8Encoding($false)

function Throw-NgPromotionError {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )

    throw [System.InvalidOperationException]::new("$Code`: $Message")
}

function Test-NgByteEquality {
    param(
        [Parameter(Mandatory)][byte[]]$Left,
        [Parameter(Mandatory)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    [int]$difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
    }
    return ($difference -eq 0)
}

function ConvertTo-NgLowerHex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return ([System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant())
}

function Get-NgSha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return $sha.ComputeHash($Bytes)
    }
    finally {
        $sha.Dispose()
    }
}

function Get-NgSha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return ConvertTo-NgLowerHex -Bytes (Get-NgSha256Bytes -Bytes $Bytes)
}

function Get-NgHmacHex {
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$Key)
    try {
        return ConvertTo-NgLowerHex -Bytes $hmac.ComputeHash($Bytes)
    }
    finally {
        $hmac.Dispose()
    }
}

function Read-NgBoundedFileBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$MaximumBytes,
        [Parameter(Mandatory)][string]$Context
    )

    if (-not [System.IO.File]::Exists($Path)) {
        Throw-NgPromotionError 'NGPC-FILE-MISSING' "$Context file is missing."
    }

    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-NgPromotionError 'NGPC-REPARSE-POINT' "$Context must not be a reparse point."
    }

    $length = (New-Object System.IO.FileInfo($Path)).Length
    if ($length -lt 1 -or $length -gt $MaximumBytes) {
        Throw-NgPromotionError 'NGPC-FILE-SIZE' "$Context size is outside its fixed bound."
    }

    try {
        return [System.IO.File]::ReadAllBytes($Path)
    }
    catch {
        Throw-NgPromotionError 'NGPC-FILE-READ' "$Context could not be read atomically enough for verification."
    }
}

function Skip-NgJsonWhitespace {
    param([Parameter(Mandatory)][hashtable]$State)

    while ($State.Index -lt $State.Text.Length) {
        [char]$character = $State.Text[$State.Index]
        if ($character -ne ' ' -and $character -ne "`t" -and $character -ne "`r" -and $character -ne "`n") {
            break
        }
        $State.Index++
    }
}

function Read-NgJsonString {
    param([Parameter(Mandatory)][hashtable]$State)

    if ($State.Text[$State.Index] -ne '"') {
        Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'Expected a JSON string.'
    }
    $State.Index++
    $builder = New-Object System.Text.StringBuilder

    while ($State.Index -lt $State.Text.Length) {
        [char]$character = $State.Text[$State.Index]
        $State.Index++

        if ($character -eq '"') {
            if ($builder.Length -gt 4096) {
                Throw-NgPromotionError 'NGPC-JSON-LIMIT' 'A JSON string exceeds the v1 limit.'
            }
            return $builder.ToString()
        }

        if ([int]$character -lt 0x20) {
            Throw-NgPromotionError 'NGPC-JSON-CONTROL' 'An unescaped control character is forbidden.'
        }

        if ($character -ne '\') {
            $null = $builder.Append($character)
            continue
        }

        if ($State.Index -ge $State.Text.Length) {
            Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON escape is incomplete.'
        }

        [char]$escape = $State.Text[$State.Index]
        $State.Index++
        switch ($escape) {
            '"' { $null = $builder.Append('"') }
            '\' { $null = $builder.Append('\') }
            '/' { $null = $builder.Append('/') }
            'b' { $null = $builder.Append([char]0x08) }
            'f' { $null = $builder.Append([char]0x0C) }
            'n' { $null = $builder.Append([char]0x0A) }
            'r' { $null = $builder.Append([char]0x0D) }
            't' { $null = $builder.Append([char]0x09) }
            'u' {
                if (($State.Index + 4) -gt $State.Text.Length) {
                    Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A Unicode escape is incomplete.'
                }
                $hex = $State.Text.Substring($State.Index, 4)
                if ($hex -cnotmatch '^[0-9a-fA-F]{4}$') {
                    Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A Unicode escape is malformed.'
                }
                $State.Index += 4
                $codeUnit = [Convert]::ToInt32($hex, 16)
                if ($codeUnit -ge 0xD800 -and $codeUnit -le 0xDFFF) {
                    Throw-NgPromotionError 'NGPC-JSON-UNICODE' 'Surrogate escapes are not admitted by the v1 parser.'
                }
                $null = $builder.Append([char]$codeUnit)
            }
            default { Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON escape is not recognized.' }
        }
    }

    Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON string is unterminated.'
}

function Read-NgJsonInteger {
    param([Parameter(Mandatory)][hashtable]$State)

    $start = $State.Index
    if ($State.Text[$State.Index] -eq '-') {
        $State.Index++
    }
    if ($State.Index -ge $State.Text.Length) {
        Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON number is incomplete.'
    }

    if ($State.Text[$State.Index] -eq '0') {
        $State.Index++
        if ($State.Index -lt $State.Text.Length -and $State.Text[$State.Index] -ge '0' -and $State.Text[$State.Index] -le '9') {
            Throw-NgPromotionError 'NGPC-JSON-NUMBER' 'Leading zeroes are forbidden.'
        }
    }
    elseif ($State.Text[$State.Index] -ge '1' -and $State.Text[$State.Index] -le '9') {
        while ($State.Index -lt $State.Text.Length -and $State.Text[$State.Index] -ge '0' -and $State.Text[$State.Index] -le '9') {
            $State.Index++
        }
    }
    else {
        Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON number is malformed.'
    }

    if ($State.Index -lt $State.Text.Length -and ($State.Text[$State.Index] -eq '.' -or $State.Text[$State.Index] -eq 'e' -or $State.Text[$State.Index] -eq 'E')) {
        Throw-NgPromotionError 'NGPC-JSON-INTEGER-ONLY' 'Only canonical 64-bit integers are admitted.'
    }

    $token = $State.Text.Substring($start, $State.Index - $start)
    [long]$value = 0
    if (-not [long]::TryParse($token, [System.Globalization.NumberStyles]::AllowLeadingSign, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value)) {
        Throw-NgPromotionError 'NGPC-JSON-NUMBER' 'A JSON integer is outside the 64-bit range.'
    }
    return $value
}

function Read-NgJsonValue {
    param([Parameter(Mandatory)][hashtable]$State)

    Skip-NgJsonWhitespace -State $State
    if ($State.Index -ge $State.Text.Length) {
        Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON value is missing.'
    }

    $State.Nodes++
    if ($State.Nodes -gt 4096) {
        Throw-NgPromotionError 'NGPC-JSON-LIMIT' 'The JSON node limit was exceeded.'
    }

    [char]$character = $State.Text[$State.Index]
    if ($character -eq '"') {
        return Read-NgJsonString -State $State
    }
    if ($character -eq '-' -or ($character -ge '0' -and $character -le '9')) {
        return Read-NgJsonInteger -State $State
    }
    if ($State.Text.Substring($State.Index).StartsWith('true', [System.StringComparison]::Ordinal)) {
        $State.Index += 4
        return $true
    }
    if ($State.Text.Substring($State.Index).StartsWith('false', [System.StringComparison]::Ordinal)) {
        $State.Index += 5
        return $false
    }
    if ($State.Text.Substring($State.Index).StartsWith('null', [System.StringComparison]::Ordinal)) {
        Throw-NgPromotionError 'NGPC-JSON-NULL' 'Null is forbidden in a promotion envelope or replay ledger.'
    }

    if ($character -eq '[') {
        $State.Depth++
        if ($State.Depth -gt 16) {
            Throw-NgPromotionError 'NGPC-JSON-LIMIT' 'The JSON depth limit was exceeded.'
        }
        $State.Index++
        $items = New-Object System.Collections.ArrayList
        Skip-NgJsonWhitespace -State $State
        if ($State.Index -lt $State.Text.Length -and $State.Text[$State.Index] -eq ']') {
            $State.Index++
            $State.Depth--
            return ,([object[]]@())
        }
        while ($true) {
            if ($items.Count -ge 256) {
                Throw-NgPromotionError 'NGPC-JSON-LIMIT' 'A JSON array exceeds the v1 item limit.'
            }
            $null = $items.Add((Read-NgJsonValue -State $State))
            Skip-NgJsonWhitespace -State $State
            if ($State.Index -ge $State.Text.Length) {
                Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON array is unterminated.'
            }
            if ($State.Text[$State.Index] -eq ']') {
                $State.Index++
                $State.Depth--
                return ,([object[]]$items.ToArray())
            }
            if ($State.Text[$State.Index] -ne ',') {
                Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'Expected a comma in a JSON array.'
            }
            $State.Index++
        }
    }

    if ($character -eq '{') {
        $State.Depth++
        if ($State.Depth -gt 16) {
            Throw-NgPromotionError 'NGPC-JSON-LIMIT' 'The JSON depth limit was exceeded.'
        }
        $State.Index++
        $object = New-Object System.Collections.Specialized.OrderedDictionary
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $seenCaseFolded = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Skip-NgJsonWhitespace -State $State
        if ($State.Index -lt $State.Text.Length -and $State.Text[$State.Index] -eq '}') {
            $State.Index++
            $State.Depth--
            return ,$object
        }
        while ($true) {
            if ($object.Count -ge 128) {
                Throw-NgPromotionError 'NGPC-JSON-LIMIT' 'A JSON object exceeds the v1 property limit.'
            }
            Skip-NgJsonWhitespace -State $State
            if ($State.Index -ge $State.Text.Length -or $State.Text[$State.Index] -ne '"') {
                Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON object property name is missing.'
            }
            $name = Read-NgJsonString -State $State
            if (-not $seen.Add($name)) {
                Throw-NgPromotionError 'NGPC-JSON-DUPLICATE-KEY' 'A duplicate JSON property was rejected at the byte parser.'
            }
            if (-not $seenCaseFolded.Add($name)) {
                Throw-NgPromotionError 'NGPC-JSON-CASE-COLLISION' 'Case-colliding JSON properties are forbidden.'
            }
            Skip-NgJsonWhitespace -State $State
            if ($State.Index -ge $State.Text.Length -or $State.Text[$State.Index] -ne ':') {
                Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON object property separator is missing.'
            }
            $State.Index++
            $object.Add($name, (Read-NgJsonValue -State $State))
            Skip-NgJsonWhitespace -State $State
            if ($State.Index -ge $State.Text.Length) {
                Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'A JSON object is unterminated.'
            }
            if ($State.Text[$State.Index] -eq '}') {
                $State.Index++
                $State.Depth--
                return ,$object
            }
            if ($State.Text[$State.Index] -ne ',') {
                Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'Expected a comma in a JSON object.'
            }
            $State.Index++
        }
    }

    Throw-NgPromotionError 'NGPC-JSON-SYNTAX' 'The next token is not a valid JSON value.'
}

function ConvertTo-NgCanonicalJson {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object]$Value)

    if ($null -eq $Value) {
        Throw-NgPromotionError 'NGPC-JSON-NULL' 'Null cannot be canonicalized.'
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [string]) {
        $builder = New-Object System.Text.StringBuilder
        $null = $builder.Append('"')
        foreach ($character in $Value.ToCharArray()) {
            switch ([int]$character) {
                0x22 { $null = $builder.Append('\"') }
                0x5C { $null = $builder.Append('\\') }
                0x08 { $null = $builder.Append('\b') }
                0x0C { $null = $builder.Append('\f') }
                0x0A { $null = $builder.Append('\n') }
                0x0D { $null = $builder.Append('\r') }
                0x09 { $null = $builder.Append('\t') }
                default {
                    if ([int]$character -lt 0x20) {
                        $null = $builder.AppendFormat('\u{0:x4}', [int]$character)
                    }
                    else {
                        $null = $builder.Append($character)
                    }
                }
            }
        }
        $null = $builder.Append('"')
        return $builder.ToString()
    }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]) {
        return ([Convert]::ToInt64($Value)).ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        [string[]]$keys = @($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($key in $keys) {
            $parts.Add((ConvertTo-NgCanonicalJson -Value $key) + ':' + (ConvertTo-NgCanonicalJson -Value $Value[$key]))
        }
        return '{' + ([string]::Join(',', $parts.ToArray())) + '}'
    }
    if (($Value -is [System.Array]) -or ($Value -is [System.Collections.IList])) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $parts.Add((ConvertTo-NgCanonicalJson -Value $item))
        }
        return '[' + ([string]::Join(',', $parts.ToArray())) + ']'
    }

    Throw-NgPromotionError 'NGPC-CANONICAL-TYPE' 'A value has no representation in canonical promotion JSON.'
}

function ConvertFrom-NgStrictCanonicalJsonBytes {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Context
    )

    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        Throw-NgPromotionError 'NGPC-UTF8-BOM' "$Context must be UTF-8 without a BOM."
    }

    try {
        $text = $script:Utf8Strict.GetString($Bytes)
    }
    catch {
        Throw-NgPromotionError 'NGPC-UTF8-MALFORMED' "$Context contains malformed UTF-8."
    }

    $state = @{
        Text = $text
        Index = 0
        Depth = 0
        Nodes = 0
    }
    $value = Read-NgJsonValue -State $state
    Skip-NgJsonWhitespace -State $state
    if ($state.Index -ne $text.Length) {
        Throw-NgPromotionError 'NGPC-JSON-TRAILING' "$Context has trailing content."
    }

    $canonicalBytes = $script:Utf8Plain.GetBytes((ConvertTo-NgCanonicalJson -Value $value))
    if (-not (Test-NgByteEquality -Left $Bytes -Right $canonicalBytes)) {
        Throw-NgPromotionError 'NGPC-JSON-NONCANONICAL' "$Context is valid JSON but not the exact canonical byte form."
    }
    return ,$value
}

function Assert-NgDictionary {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Context
    )

    if (-not ($Value -is [System.Collections.IDictionary])) {
        Throw-NgPromotionError 'NGPC-SCHEMA-TYPE' "$Context must be an object."
    }
}

function Assert-NgExactKeys {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Value,
        [Parameter(Mandatory)][string[]]$Keys,
        [Parameter(Mandatory)][string]$Context
    )

    [string[]]$actual = @($Value.Keys | ForEach-Object { [string]$_ })
    [Array]::Sort($actual, [System.StringComparer]::Ordinal)
    [string[]]$expected = @($Keys)
    [Array]::Sort($expected, [System.StringComparer]::Ordinal)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        Throw-NgPromotionError 'NGPC-SCHEMA-KEYS' "$Context contains missing or unknown properties."
    }
}

function Assert-NgAsciiString {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Context,
        [int]$MinimumLength = 1,
        [int]$MaximumLength = 4096
    )

    if (-not ($Value -is [string]) -or $Value.Length -lt $MinimumLength -or $Value.Length -gt $MaximumLength -or $Value -cmatch '[^\x20-\x7e]') {
        Throw-NgPromotionError 'NGPC-SCHEMA-STRING' "$Context must be bounded printable ASCII."
    }
}

function Assert-NgPattern {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Context
    )

    Assert-NgAsciiString -Value $Value -Context $Context
    if ($Value -cnotmatch $Pattern) {
        Throw-NgPromotionError 'NGPC-SCHEMA-PATTERN' "$Context does not match the v1 contract."
    }
}

function ConvertFrom-NgTimestamp {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Context
    )

    Assert-NgPattern -Value $Value -Pattern '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$' -Context $Context
    $timestamp = [DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParseExact($Value, 'yyyy-MM-ddTHH:mm:ss\Z', [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$timestamp)) {
        Throw-NgPromotionError 'NGPC-SCHEMA-TIME' "$Context is not a real canonical UTC timestamp."
    }
    return $timestamp
}

function Get-NgNormalizedTrustedRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Context
    )

    if ($Path -cnotmatch '^[A-Z]:\\' -or $Path -match '[*?%]' -or $Path.StartsWith('\\')) {
        Throw-NgPromotionError 'NGPC-TRUST-PATH' "$Context must be a fixed local drive path."
    }
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($Path -cne $full) {
        Throw-NgPromotionError 'NGPC-TRUST-PATH' "$Context must already be in its normalized fixed form."
    }
    return $full
}

function Test-NgPathWithinRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    $prefix = $Root.TrimEnd('\') + '\'
    return $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-NgRelativePath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][object]$RelativePath,
        [Parameter(Mandatory)][string]$Context
    )

    Assert-NgAsciiString -Value $RelativePath -Context $Context -MaximumLength 512
    if ($RelativePath -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,63}){0,7}$') {
        Throw-NgPromotionError 'NGPC-RELATIVE-PATH' "$Context is not an admitted relative path."
    }
    foreach ($segment in $RelativePath.Split('/')) {
        if ($segment -ceq '.' -or $segment -ceq '..') {
            Throw-NgPromotionError 'NGPC-RELATIVE-PATH' "$Context contains traversal."
        }
    }
    $full = [System.IO.Path]::GetFullPath((Join-Path $Root ($RelativePath -replace '/', '\')))
    if (-not (Test-NgPathWithinRoot -Path $full -Root $Root)) {
        Throw-NgPromotionError 'NGPC-PATH-ESCAPE' "$Context escapes its fixed root."
    }
    return $full
}

function Assert-NgNoReparsePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Context
    )

    $current = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
        if ([System.IO.File]::Exists($current) -or [System.IO.Directory]::Exists($current)) {
            $attributes = [System.IO.File]::GetAttributes($current)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-NgPromotionError 'NGPC-REPARSE-POINT' "$Context crosses a reparse point."
            }
        }
        if ($current -ieq $Root) { break }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent -or -not $parent.FullName.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
            Throw-NgPromotionError 'NGPC-PATH-ESCAPE' "$Context cannot be proven inside its fixed root."
        }
        $current = $parent.FullName
    }
}

function Get-NgAllowedSidSet {
    param([Parameter(Mandatory)][string[]]$AllowedWriterSids)

    if ($AllowedWriterSids.Count -lt 2 -or $AllowedWriterSids.Count -gt 8) {
        Throw-NgPromotionError 'NGPC-ACL-POLICY' 'The trusted writer SID allowlist is outside its fixed bound.'
    }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($sidText in $AllowedWriterSids) {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        }
        catch {
            Throw-NgPromotionError 'NGPC-ACL-POLICY' 'The trusted writer allowlist contains an invalid SID.'
        }
        $null = $set.Add($sid.Value)
    }
    if (-not $set.Contains('S-1-5-18') -or -not $set.Contains('S-1-5-32-544')) {
        Throw-NgPromotionError 'NGPC-ACL-POLICY' 'SYSTEM and BUILTIN Administrators must remain trusted writers.'
    }
    return ,$set
}

function Assert-NgRestrictiveAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AllowedWriterSet,
        [Parameter(Mandatory)][string]$Context,
        [switch]$RequireProtectedDacl
    )

    if (-not [System.IO.File]::Exists($Path) -and -not [System.IO.Directory]::Exists($Path)) {
        Throw-NgPromotionError 'NGPC-ACL-MISSING' "$Context does not exist for ACL verification."
    }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Throw-NgPromotionError 'NGPC-ACL-READ' "$Context ACL could not be read."
    }
    if (-not $AllowedWriterSet.Contains($owner)) {
        Throw-NgPromotionError 'NGPC-ACL-OWNER' "$Context owner is not an allowlisted administrative principal."
    }
    if ($RequireProtectedDacl -and -not $acl.AreAccessRulesProtected) {
        Throw-NgPromotionError 'NGPC-ACL-INHERITANCE' "$Context must have a protected DACL."
    }

    [long]$writeMask = 0
    foreach ($right in @(
        [System.Security.AccessControl.FileSystemRights]::Write,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership,
        [System.Security.AccessControl.FileSystemRights]::CreateFiles,
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
        [System.Security.AccessControl.FileSystemRights]::AppendData,
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes,
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
    )) {
        $writeMask = $writeMask -bor [long]$right
    }

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            (([long]$rule.FileSystemRights -band $writeMask) -ne 0) -and
            -not $AllowedWriterSet.Contains($rule.IdentityReference.Value)) {
            Throw-NgPromotionError 'NGPC-ACL-WRITER' "$Context grants write-class access to a non-allowlisted principal."
        }
    }
}

function Assert-NgCertificateAndSignature {
    param(
        [Parameter(Mandatory)][byte[]]$CertificateBytes,
        [Parameter(Mandatory)][string]$ExpectedCertificateSha256,
        [Parameter(Mandatory)][byte[]]$EnvelopeBytes,
        [Parameter(Mandatory)][byte[]]$SignatureBytes,
        [Parameter(Mandatory)][DateTimeOffset]$NowUtc,
        [Parameter(Mandatory)][DateTimeOffset]$EnvelopeExpiryUtc
    )

    Assert-NgPattern -Value $ExpectedCertificateSha256 -Pattern '^[0-9a-f]{64}$' -Context 'trusted signer certificate SHA-256'
    $actualPin = Get-NgSha256Hex -Bytes $CertificateBytes
    if ($actualPin -cne $ExpectedCertificateSha256) {
        Throw-NgPromotionError 'NGPC-CERT-PIN' 'The public certificate does not match the installed pin.'
    }

    try {
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$CertificateBytes)
    }
    catch {
        Throw-NgPromotionError 'NGPC-CERT-PARSE' 'The pinned certificate is not a valid DER X.509 certificate.'
    }
    try {
        if ($certificate.PublicKey.Oid.Value -cne '1.2.840.113549.1.1.1') {
            Throw-NgPromotionError 'NGPC-CERT-ALGORITHM' 'The signer certificate must contain an RSA public key.'
        }
        $keyUsage = $null
        $enhancedKeyUsage = $null
        $basicConstraints = $null
        foreach ($extension in $certificate.Extensions) {
            if ($extension.Oid.Value -ceq '2.5.29.15') { $keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]$extension }
            if ($extension.Oid.Value -ceq '2.5.29.37') { $enhancedKeyUsage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension }
            if ($extension.Oid.Value -ceq '2.5.29.19') { $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$extension }
        }
        if ($null -eq $keyUsage -or ($keyUsage.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
            Throw-NgPromotionError 'NGPC-CERT-KEY-USAGE' 'The signer certificate lacks DigitalSignature key usage.'
        }
        $hasCodeSigning = $false
        if ($null -ne $enhancedKeyUsage) {
            foreach ($oid in $enhancedKeyUsage.EnhancedKeyUsages) {
                if ($oid.Value -ceq '1.3.6.1.5.5.7.3.3') { $hasCodeSigning = $true }
            }
        }
        if (-not $hasCodeSigning) {
            Throw-NgPromotionError 'NGPC-CERT-EKU' 'The signer certificate lacks the Code Signing EKU.'
        }
        if ($null -ne $basicConstraints -and $basicConstraints.CertificateAuthority) {
            Throw-NgPromotionError 'NGPC-CERT-CA' 'A CA certificate cannot be used as the promotion signer.'
        }
        $notBefore = [DateTimeOffset]$certificate.NotBefore.ToUniversalTime()
        $notAfter = [DateTimeOffset]$certificate.NotAfter.ToUniversalTime()
        if ($NowUtc -lt $notBefore -or $NowUtc -gt $notAfter -or $EnvelopeExpiryUtc -gt $notAfter) {
            Throw-NgPromotionError 'NGPC-CERT-TIME' 'The signer certificate is not valid for the full envelope lifetime.'
        }

        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
        if ($null -eq $rsa -or $rsa.KeySize -lt 3072) {
            Throw-NgPromotionError 'NGPC-CERT-KEY-SIZE' 'The signer RSA key must be at least 3072 bits.'
        }
        try {
            if ($SignatureBytes.Length -ne [int]($rsa.KeySize / 8)) {
                Throw-NgPromotionError 'NGPC-SIGNATURE-SIZE' 'The detached signature length does not match the pinned RSA key.'
            }
            $valid = $rsa.VerifyData(
                $EnvelopeBytes,
                $SignatureBytes,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            if (-not $valid) {
                Throw-NgPromotionError 'NGPC-SIGNATURE-INVALID' 'The detached envelope signature is invalid.'
            }
        }
        finally {
            if ($null -ne $rsa) { $rsa.Dispose() }
        }
    }
    finally {
        $certificate.Dispose()
    }
}

function Get-NgTrustedArtifactValue {
    param(
        [Parameter(Mandatory)][object]$Artifact,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Artifact -is [System.Collections.IDictionary]) {
        if (-not $Artifact.Contains($Name)) {
            Throw-NgPromotionError 'NGPC-TRUST-ARTIFACT' 'Trusted artifact policy is incomplete.'
        }
        return $Artifact[$Name]
    }
    $property = $Artifact.PSObject.Properties[$Name]
    if ($null -eq $property) {
        Throw-NgPromotionError 'NGPC-TRUST-ARTIFACT' 'Trusted artifact policy is incomplete.'
    }
    return $property.Value
}

function Assert-NgArtifactRecord {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Artifact,
        [Parameter(Mandatory)][string]$Context
    )

    Assert-NgExactKeys -Value $Artifact -Keys @('destinationRelativePath', 'id', 'sha256', 'sizeBytes', 'sourceRelativePath') -Context $Context
    Assert-NgPattern -Value $Artifact.id -Pattern '^[a-z][a-z0-9-]{2,63}$' -Context "$Context id"
    Assert-NgPattern -Value $Artifact.sha256 -Pattern '^[0-9a-f]{64}$' -Context "$Context SHA-256"
    if (-not ($Artifact.sizeBytes -is [long]) -or $Artifact.sizeBytes -lt 1 -or $Artifact.sizeBytes -gt 33554432) {
        Throw-NgPromotionError 'NGPC-ARTIFACT-SIZE' "$Context size is outside the v1 bound."
    }
    $null = Resolve-NgRelativePath -Root 'C:\NGPC-SYNTAX-CHECK' -RelativePath $Artifact.sourceRelativePath -Context "$Context source path"
    $null = Resolve-NgRelativePath -Root 'C:\NGPC-SYNTAX-CHECK' -RelativePath $Artifact.destinationRelativePath -Context "$Context destination path"
}

function Assert-NgEnvelopeSchemaAndBindings {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Envelope,
        [Parameter(Mandatory)][string]$ExpectedRepositoryId,
        [Parameter(Mandatory)][string]$ExpectedRepositoryUri,
        [Parameter(Mandatory)][string]$ExpectedCommitSha,
        [Parameter(Mandatory)][string]$ExpectedTreeSha,
        [Parameter(Mandatory)][string]$ExpectedInstallRoot,
        [Parameter(Mandatory)][string]$ExpectedStagingRoot,
        [Parameter(Mandatory)][object[]]$ExpectedArtifacts,
        [Parameter(Mandatory)][DateTimeOffset]$NowUtc,
        [Parameter(Mandatory)][int]$MaximumEnvelopeLifetimeMinutes
    )

    Assert-NgExactKeys -Value $Envelope -Keys @(
        'actions', 'applyEnabled', 'artifactSetSha256', 'artifacts', 'envelopeId', 'expiresAtUtc',
        'installRoot', 'issuedAtUtc', 'nonce', 'operation', 'repository', 'schemaVersion',
        'signatureAlgorithm', 'stagingRoot'
    ) -Context 'promotion envelope'

    if ($Envelope.schemaVersion -cne $script:EnvelopeSchema -or $Envelope.operation -cne $script:InstallOperation -or
        $Envelope.signatureAlgorithm -cne $script:SignatureAlgorithm) {
        Throw-NgPromotionError 'NGPC-INSTALL-ONLY' 'The envelope is not the exact v1 install-only contract.'
    }
    if (-not ($Envelope.applyEnabled -is [bool]) -or $Envelope.applyEnabled) {
        Throw-NgPromotionError 'NGPC-APPLY-DISABLED' 'applyEnabled must be exactly false.'
    }
    if (-not ($Envelope.actions -is [System.Array]) -or $Envelope.actions.Count -ne 0) {
        Throw-NgPromotionError 'NGPC-ACTIONS-EMPTY' 'The install-only envelope must contain an empty actions array.'
    }
    Assert-NgPattern -Value $Envelope.envelopeId -Pattern '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -Context 'envelope ID'
    Assert-NgPattern -Value $Envelope.nonce -Pattern '^[A-Za-z0-9_-]{43}$' -Context 'one-use nonce'

    $issuedAt = ConvertFrom-NgTimestamp -Value $Envelope.issuedAtUtc -Context 'issuedAtUtc'
    $expiresAt = ConvertFrom-NgTimestamp -Value $Envelope.expiresAtUtc -Context 'expiresAtUtc'
    if ($issuedAt -gt $NowUtc.AddSeconds(60)) {
        Throw-NgPromotionError 'NGPC-ISSUED-FUTURE' 'The envelope issue time is beyond the fixed clock-skew allowance.'
    }
    if ($expiresAt -le $NowUtc) {
        Throw-NgPromotionError 'NGPC-EXPIRED' 'The promotion envelope has expired.'
    }
    if ($expiresAt -le $issuedAt -or ($expiresAt - $issuedAt).TotalMinutes -gt $MaximumEnvelopeLifetimeMinutes) {
        Throw-NgPromotionError 'NGPC-LIFETIME' 'The promotion envelope lifetime is invalid or too long.'
    }

    Assert-NgDictionary -Value $Envelope.repository -Context 'repository binding'
    Assert-NgExactKeys -Value $Envelope.repository -Keys @('commitSha', 'id', 'treeSha', 'uri') -Context 'repository binding'
    Assert-NgPattern -Value $Envelope.repository.id -Pattern '^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$' -Context 'repository ID'
    Assert-NgPattern -Value $Envelope.repository.uri -Pattern '^https://github\.com/[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}\.git$' -Context 'repository URI'
    Assert-NgPattern -Value $Envelope.repository.commitSha -Pattern '^[0-9a-f]{40}$' -Context 'commit SHA'
    Assert-NgPattern -Value $Envelope.repository.treeSha -Pattern '^[0-9a-f]{40}$' -Context 'tree SHA'
    Assert-NgPattern -Value $ExpectedCommitSha -Pattern '^[0-9a-f]{40}$' -Context 'trusted commit SHA'
    Assert-NgPattern -Value $ExpectedTreeSha -Pattern '^[0-9a-f]{40}$' -Context 'trusted tree SHA'
    if ($Envelope.repository.id -cne $ExpectedRepositoryId -or $Envelope.repository.uri -cne $ExpectedRepositoryUri -or
        $Envelope.repository.commitSha -cne $ExpectedCommitSha -or $Envelope.repository.treeSha -cne $ExpectedTreeSha) {
        Throw-NgPromotionError 'NGPC-REPOSITORY-BINDING' 'Repository identity, commit, or tree does not match installed trust policy.'
    }

    if ($Envelope.installRoot -cne $ExpectedInstallRoot -or $Envelope.stagingRoot -cne $ExpectedStagingRoot) {
        Throw-NgPromotionError 'NGPC-FIXED-ROOT' 'Envelope roots do not match the installed fixed roots.'
    }

    if (-not ($Envelope.artifacts -is [System.Array]) -or $Envelope.artifacts.Count -lt 1 -or $Envelope.artifacts.Count -gt 32) {
        Throw-NgPromotionError 'NGPC-ARTIFACT-COUNT' 'The artifact set is outside the v1 bound.'
    }
    if ($ExpectedArtifacts.Count -ne $Envelope.artifacts.Count) {
        Throw-NgPromotionError 'NGPC-ARTIFACT-BINDING' 'The signed artifact count differs from installed trust policy.'
    }

    $seenIds = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $seenSources = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $seenDestinations = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $previousId = $null
    for ($index = 0; $index -lt $Envelope.artifacts.Count; $index++) {
        $artifact = $Envelope.artifacts[$index]
        Assert-NgDictionary -Value $artifact -Context "artifact[$index]"
        Assert-NgArtifactRecord -Artifact $artifact -Context "artifact[$index]"
        if ($null -ne $previousId -and [StringComparer]::Ordinal.Compare($previousId, $artifact.id) -ge 0) {
            Throw-NgPromotionError 'NGPC-ARTIFACT-ORDER' 'Artifacts must be strictly ordered by id.'
        }
        $previousId = $artifact.id
        if (-not $seenIds.Add($artifact.id) -or -not $seenSources.Add($artifact.sourceRelativePath) -or -not $seenDestinations.Add($artifact.destinationRelativePath)) {
            Throw-NgPromotionError 'NGPC-ARTIFACT-DUPLICATE' 'Artifact identifiers and paths must be unique.'
        }

    }

    for ($index = 0; $index -lt $Envelope.artifacts.Count; $index++) {
        $artifact = $Envelope.artifacts[$index]
        $trusted = $ExpectedArtifacts[$index]
        foreach ($name in @('id', 'sourceRelativePath', 'destinationRelativePath', 'sha256', 'sizeBytes')) {
            $trustedValue = Get-NgTrustedArtifactValue -Artifact $trusted -Name $name
            if ($name -ceq 'sizeBytes') {
                if ([long]$artifact[$name] -ne [long]$trustedValue) {
                    Throw-NgPromotionError 'NGPC-ARTIFACT-BINDING' 'An artifact size differs from installed trust policy.'
                }
            }
            elseif ([string]$artifact[$name] -cne [string]$trustedValue) {
                Throw-NgPromotionError 'NGPC-ARTIFACT-BINDING' 'An artifact identity, path, or hash differs from installed trust policy.'
            }
        }
    }

    Assert-NgPattern -Value $Envelope.artifactSetSha256 -Pattern '^[0-9a-f]{64}$' -Context 'artifact set SHA-256'
    $artifactSetBytes = $script:Utf8Plain.GetBytes((ConvertTo-NgCanonicalJson -Value $Envelope.artifacts))
    if ((Get-NgSha256Hex -Bytes $artifactSetBytes) -cne $Envelope.artifactSetSha256) {
        Throw-NgPromotionError 'NGPC-ARTIFACT-SET-HASH' 'The artifact-set aggregate hash is invalid.'
    }

    return [pscustomobject][ordered]@{
        issuedAtUtc = $issuedAt
        expiresAtUtc = $expiresAt
    }
}

function Assert-NgArtifactFiles {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Envelope,
        [Parameter(Mandatory)][string]$StagingRoot,
        [Parameter(Mandatory)][string]$InstallRoot,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AllowedWriterSet
    )

    foreach ($artifact in $Envelope.artifacts) {
        $sourcePath = Resolve-NgRelativePath -Root $StagingRoot -RelativePath $artifact.sourceRelativePath -Context 'artifact source path'
        $destinationPath = Resolve-NgRelativePath -Root $InstallRoot -RelativePath $artifact.destinationRelativePath -Context 'artifact destination path'
        $null = $destinationPath
        if (-not [System.IO.File]::Exists($sourcePath)) {
            Throw-NgPromotionError 'NGPC-ARTIFACT-MISSING' 'A signed artifact is missing from the fixed staging root.'
        }
        Assert-NgNoReparsePath -Path $sourcePath -Root $StagingRoot -Context 'artifact source'
        Assert-NgRestrictiveAcl -Path $sourcePath -AllowedWriterSet $AllowedWriterSet -Context 'artifact source'

        $stream = $null
        $sha = $null
        try {
            $stream = New-Object System.IO.FileStream($sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            if ($stream.Length -ne [long]$artifact.sizeBytes) {
                Throw-NgPromotionError 'NGPC-ARTIFACT-ACTUAL-SIZE' 'A staged artifact size does not match the signed binding.'
            }
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $actualHash = ConvertTo-NgLowerHex -Bytes $sha.ComputeHash($stream)
            if ($actualHash -cne $artifact.sha256) {
                Throw-NgPromotionError 'NGPC-ARTIFACT-ACTUAL-HASH' 'A staged artifact hash does not match the signed binding.'
            }
        }
        finally {
            if ($null -ne $sha) { $sha.Dispose() }
            if ($null -ne $stream) { $stream.Dispose() }
        }
    }
}

function Read-NgReplayLedger {
    param(
        [Parameter(Mandatory)][string]$LedgerPath,
        [Parameter(Mandatory)][string]$LedgerId,
        [Parameter(Mandatory)][byte[]]$LedgerKey
    )

    if (-not [System.IO.File]::Exists($LedgerPath)) {
        return [pscustomobject][ordered]@{
            entries = [object[]]@()
            ledgerId = $LedgerId
            schemaVersion = $script:LedgerSchema
        }
    }

    $bytes = Read-NgBoundedFileBytes -Path $LedgerPath -MaximumBytes 1048576 -Context 'replay ledger'
    $ledger = ConvertFrom-NgStrictCanonicalJsonBytes -Bytes $bytes -Context 'replay ledger'
    Assert-NgDictionary -Value $ledger -Context 'replay ledger'
    Assert-NgExactKeys -Value $ledger -Keys @('entries', 'ledgerId', 'mac', 'schemaVersion') -Context 'replay ledger'
    if ($ledger.schemaVersion -cne $script:LedgerSchema -or $ledger.ledgerId -cne $LedgerId) {
        Throw-NgPromotionError 'NGPC-LEDGER-IDENTITY' 'Replay ledger identity does not match installed policy.'
    }
    Assert-NgPattern -Value $ledger.mac -Pattern '^[0-9a-f]{64}$' -Context 'replay ledger MAC'
    if (-not ($ledger.entries -is [System.Array]) -or $ledger.entries.Count -gt 10000) {
        Throw-NgPromotionError 'NGPC-LEDGER-SCHEMA' 'Replay ledger entries are outside their bound.'
    }

    $body = [ordered]@{
        entries = $ledger.entries
        ledgerId = $ledger.ledgerId
        schemaVersion = $ledger.schemaVersion
    }
    $expectedMac = Get-NgHmacHex -Key $LedgerKey -Bytes $script:Utf8Plain.GetBytes((ConvertTo-NgCanonicalJson -Value $body))
    $expectedMacBytes = $script:Utf8Plain.GetBytes($expectedMac)
    $actualMacBytes = $script:Utf8Plain.GetBytes([string]$ledger.mac)
    if (-not (Test-NgByteEquality -Left $expectedMacBytes -Right $actualMacBytes)) {
        Throw-NgPromotionError 'NGPC-LEDGER-MAC' 'Replay ledger authentication failed.'
    }

    $seenNonces = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    for ($index = 0; $index -lt $ledger.entries.Count; $index++) {
        $entry = $ledger.entries[$index]
        Assert-NgDictionary -Value $entry -Context "ledger entry[$index]"
        Assert-NgExactKeys -Value $entry -Keys @('consumedAtUtc', 'envelopeSha256', 'nonceSha256', 'sequence') -Context "ledger entry[$index]"
        if (-not ($entry.sequence -is [long]) -or $entry.sequence -ne ($index + 1)) {
            Throw-NgPromotionError 'NGPC-LEDGER-SEQUENCE' 'Replay ledger sequence is not contiguous.'
        }
        Assert-NgPattern -Value $entry.envelopeSha256 -Pattern '^[0-9a-f]{64}$' -Context 'ledger envelope SHA-256'
        Assert-NgPattern -Value $entry.nonceSha256 -Pattern '^[0-9a-f]{64}$' -Context 'ledger nonce SHA-256'
        $null = ConvertFrom-NgTimestamp -Value $entry.consumedAtUtc -Context 'ledger consumedAtUtc'
        if (-not $seenNonces.Add($entry.nonceSha256)) {
            Throw-NgPromotionError 'NGPC-LEDGER-DUPLICATE' 'Replay ledger contains a duplicate nonce digest.'
        }
    }
    return [pscustomobject][ordered]@{
        entries = [object[]]$ledger.entries
        ledgerId = [string]$ledger.ledgerId
        schemaVersion = [string]$ledger.schemaVersion
    }
}

function Write-NgReplayLedgerAtomic {
    param(
        [Parameter(Mandatory)][string]$LedgerPath,
        [Parameter(Mandatory)][object[]]$Entries,
        [Parameter(Mandatory)][string]$LedgerId,
        [Parameter(Mandatory)][byte[]]$LedgerKey
    )

    $body = [ordered]@{
        entries = $Entries
        ledgerId = $LedgerId
        schemaVersion = $script:LedgerSchema
    }
    $mac = Get-NgHmacHex -Key $LedgerKey -Bytes $script:Utf8Plain.GetBytes((ConvertTo-NgCanonicalJson -Value $body))
    $ledger = [ordered]@{
        entries = $Entries
        ledgerId = $LedgerId
        mac = $mac
        schemaVersion = $script:LedgerSchema
    }
    $bytes = $script:Utf8Plain.GetBytes((ConvertTo-NgCanonicalJson -Value $ledger))
    $directory = [System.IO.Path]::GetDirectoryName($LedgerPath)
    $temporaryPath = Join-Path $directory ('.promotion-ledger-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backupPath = Join-Path $directory ('.promotion-ledger-' + [Guid]::NewGuid().ToString('N') + '.bak')
    try {
        $stream = New-Object System.IO.FileStream($temporaryPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }

        if ([System.IO.File]::Exists($LedgerPath)) {
            [System.IO.File]::Replace($temporaryPath, $LedgerPath, $backupPath, $true)
            [System.IO.File]::Delete($backupPath)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $LedgerPath)
        }
    }
    catch {
        Throw-NgPromotionError 'NGPC-LEDGER-WRITE' 'The authenticated replay ledger could not be replaced atomically.'
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) }
        if ([System.IO.File]::Exists($backupPath)) { [System.IO.File]::Delete($backupPath) }
    }
}

function Add-NgReplayEntry {
    param(
        [Parameter(Mandatory)][string]$LedgerPath,
        [Parameter(Mandatory)][string]$LedgerKeyPath,
        [Parameter(Mandatory)][string]$LedgerId,
        [Parameter(Mandatory)][string]$Nonce,
        [Parameter(Mandatory)][string]$EnvelopeSha256,
        [Parameter(Mandatory)][DateTimeOffset]$NowUtc,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$AllowedWriterSet
    )

    $stateRoot = [System.IO.Path]::GetDirectoryName($LedgerPath)
    $lockPath = Join-Path $stateRoot 'promotion-replay-ledger.lock'
    $lockStream = $null
    try {
        try {
            $lockStream = New-Object System.IO.FileStream($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch {
            Throw-NgPromotionError 'NGPC-LEDGER-LOCK' 'The replay ledger writer lock is unavailable.'
        }

        Assert-NgRestrictiveAcl -Path $lockPath -AllowedWriterSet $AllowedWriterSet -Context 'replay ledger lock'
        Assert-NgRestrictiveAcl -Path $LedgerKeyPath -AllowedWriterSet $AllowedWriterSet -Context 'replay ledger key' -RequireProtectedDacl
        $ledgerKey = Read-NgBoundedFileBytes -Path $LedgerKeyPath -MaximumBytes 32 -Context 'replay ledger key'
        if ($ledgerKey.Length -ne 32) {
            Throw-NgPromotionError 'NGPC-LEDGER-KEY' 'The replay ledger key must be exactly 256 bits.'
        }
        [int]$nonZero = 0
        foreach ($byte in $ledgerKey) { $nonZero = $nonZero -bor $byte }
        if ($nonZero -eq 0) {
            Throw-NgPromotionError 'NGPC-LEDGER-KEY' 'The replay ledger key cannot be all zeroes.'
        }

        if ([System.IO.File]::Exists($LedgerPath)) {
            Assert-NgRestrictiveAcl -Path $LedgerPath -AllowedWriterSet $AllowedWriterSet -Context 'replay ledger'
        }
        $ledger = Read-NgReplayLedger -LedgerPath $LedgerPath -LedgerId $LedgerId -LedgerKey $ledgerKey
        $nonceHash = Get-NgSha256Hex -Bytes $script:Utf8Plain.GetBytes($Nonce)
        foreach ($entry in $ledger.entries) {
            if ($entry.nonceSha256 -ceq $nonceHash) {
                Throw-NgPromotionError 'NGPC-REPLAY' 'The one-use promotion nonce was already consumed.'
            }
        }

        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($entry in $ledger.entries) { $entries.Add($entry) }
        $entries.Add([ordered]@{
            consumedAtUtc = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            envelopeSha256 = $EnvelopeSha256
            nonceSha256 = $nonceHash
            sequence = [long]($entries.Count + 1)
        })
        Write-NgReplayLedgerAtomic -LedgerPath $LedgerPath -Entries ([object[]]$entries.ToArray()) -LedgerId $LedgerId -LedgerKey $ledgerKey
        Assert-NgRestrictiveAcl -Path $LedgerPath -AllowedWriterSet $AllowedWriterSet -Context 'updated replay ledger'
        return [long]$entries.Count
    }
    finally {
        if ($null -ne $lockStream) { $lockStream.Dispose() }
    }
}

function Test-NorthGatePromotionEnvelope {
    <#
    .SYNOPSIS
    Verifies and consumes a signed, install-only NorthGate control-plane promotion envelope.

    .DESCRIPTION
    This candidate verifies data and writes only the authenticated one-use replay ledger. It never
    installs artifacts, invokes repository code, enables apply, or performs a Hyper-V operation.
    Every Expected* value and allowed SID must come from installed, administrator-protected policy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$EnvelopePath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SignaturePath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SignerCertificatePath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedSignerCertificateSha256,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedRepositoryId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedRepositoryUri,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedCommitSha,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedTreeSha,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedInstallRoot,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedStagingRoot,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedStateRoot,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][object[]]$ExpectedArtifacts,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LedgerPath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LedgerKeyPath,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LedgerId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$AllowedWriterSids,
        [ValidateRange(1, 15)][int]$MaximumEnvelopeLifetimeMinutes = 10
    )

    $nowUtc = [DateTimeOffset]::UtcNow
    $installRoot = Get-NgNormalizedTrustedRoot -Path $ExpectedInstallRoot -Context 'trusted install root'
    $stagingRoot = Get-NgNormalizedTrustedRoot -Path $ExpectedStagingRoot -Context 'trusted staging root'
    $stateRoot = Get-NgNormalizedTrustedRoot -Path $ExpectedStateRoot -Context 'trusted state root'
    if ($installRoot -ieq $stagingRoot -or $installRoot -ieq $stateRoot -or $stagingRoot -ieq $stateRoot) {
        Throw-NgPromotionError 'NGPC-TRUST-PATH' 'Install, staging, and state roots must be distinct.'
    }
    foreach ($root in @($installRoot, $stagingRoot, $stateRoot)) {
        if (-not [System.IO.Directory]::Exists($root)) {
            Throw-NgPromotionError 'NGPC-ROOT-MISSING' 'A fixed trusted root is missing.'
        }
        Assert-NgNoReparsePath -Path $root -Root $root -Context 'fixed trusted root'
    }

    $allowedWriterSet = Get-NgAllowedSidSet -AllowedWriterSids $AllowedWriterSids
    Assert-NgRestrictiveAcl -Path $installRoot -AllowedWriterSet $allowedWriterSet -Context 'install root' -RequireProtectedDacl
    Assert-NgRestrictiveAcl -Path $stagingRoot -AllowedWriterSet $allowedWriterSet -Context 'staging root' -RequireProtectedDacl
    Assert-NgRestrictiveAcl -Path $stateRoot -AllowedWriterSet $allowedWriterSet -Context 'state root' -RequireProtectedDacl

    $envelopeFullPath = [System.IO.Path]::GetFullPath($EnvelopePath)
    $signatureFullPath = [System.IO.Path]::GetFullPath($SignaturePath)
    $certificateFullPath = [System.IO.Path]::GetFullPath($SignerCertificatePath)
    $ledgerFullPath = [System.IO.Path]::GetFullPath($LedgerPath)
    $ledgerKeyFullPath = [System.IO.Path]::GetFullPath($LedgerKeyPath)
    if (-not (Test-NgPathWithinRoot -Path $envelopeFullPath -Root $stagingRoot) -or
        -not (Test-NgPathWithinRoot -Path $signatureFullPath -Root $stagingRoot)) {
        Throw-NgPromotionError 'NGPC-STAGING-BOUNDARY' 'Envelope and detached signature must reside under the fixed staging root.'
    }
    if (-not (Test-NgPathWithinRoot -Path $certificateFullPath -Root $installRoot)) {
        Throw-NgPromotionError 'NGPC-CERT-BOUNDARY' 'The pinned public certificate must reside under the fixed install root.'
    }
    if (-not (Test-NgPathWithinRoot -Path $ledgerFullPath -Root $stateRoot) -or
        -not (Test-NgPathWithinRoot -Path $ledgerKeyFullPath -Root $stateRoot) -or
        [System.IO.Path]::GetDirectoryName($ledgerFullPath) -ine $stateRoot -or
        [System.IO.Path]::GetDirectoryName($ledgerKeyFullPath) -ine $stateRoot) {
        Throw-NgPromotionError 'NGPC-LEDGER-BOUNDARY' 'Replay ledger and key must be direct children of the fixed state root.'
    }
    if ($ledgerFullPath -ieq $ledgerKeyFullPath) {
        Throw-NgPromotionError 'NGPC-LEDGER-BOUNDARY' 'Replay ledger and key paths must be distinct.'
    }

    Assert-NgNoReparsePath -Path $envelopeFullPath -Root $stagingRoot -Context 'envelope'
    Assert-NgNoReparsePath -Path $signatureFullPath -Root $stagingRoot -Context 'detached signature'
    Assert-NgNoReparsePath -Path $certificateFullPath -Root $installRoot -Context 'pinned public certificate'
    Assert-NgRestrictiveAcl -Path $envelopeFullPath -AllowedWriterSet $allowedWriterSet -Context 'envelope'
    Assert-NgRestrictiveAcl -Path $signatureFullPath -AllowedWriterSet $allowedWriterSet -Context 'detached signature'
    Assert-NgRestrictiveAcl -Path $certificateFullPath -AllowedWriterSet $allowedWriterSet -Context 'pinned public certificate' -RequireProtectedDacl

    $envelopeBytes = Read-NgBoundedFileBytes -Path $envelopeFullPath -MaximumBytes 65536 -Context 'promotion envelope'
    $signatureBytes = Read-NgBoundedFileBytes -Path $signatureFullPath -MaximumBytes 1024 -Context 'detached signature'
    $certificateBytes = Read-NgBoundedFileBytes -Path $certificateFullPath -MaximumBytes 16384 -Context 'pinned public certificate'
    $envelope = ConvertFrom-NgStrictCanonicalJsonBytes -Bytes $envelopeBytes -Context 'promotion envelope'
    Assert-NgDictionary -Value $envelope -Context 'promotion envelope'

    # Parse the two signed timestamps before certificate validation, but perform no path or artifact action.
    if (-not $envelope.Contains('expiresAtUtc')) {
        Throw-NgPromotionError 'NGPC-SCHEMA-KEYS' 'The promotion envelope lacks expiresAtUtc.'
    }
    $preliminaryExpiry = ConvertFrom-NgTimestamp -Value $envelope.expiresAtUtc -Context 'expiresAtUtc'
    Assert-NgCertificateAndSignature -CertificateBytes $certificateBytes `
        -ExpectedCertificateSha256 $ExpectedSignerCertificateSha256 `
        -EnvelopeBytes $envelopeBytes -SignatureBytes $signatureBytes `
        -NowUtc $nowUtc -EnvelopeExpiryUtc $preliminaryExpiry

    $timeBinding = Assert-NgEnvelopeSchemaAndBindings -Envelope $envelope `
        -ExpectedRepositoryId $ExpectedRepositoryId -ExpectedRepositoryUri $ExpectedRepositoryUri `
        -ExpectedCommitSha $ExpectedCommitSha -ExpectedTreeSha $ExpectedTreeSha `
        -ExpectedInstallRoot $installRoot -ExpectedStagingRoot $stagingRoot `
        -ExpectedArtifacts $ExpectedArtifacts -NowUtc $nowUtc `
        -MaximumEnvelopeLifetimeMinutes $MaximumEnvelopeLifetimeMinutes

    Assert-NgArtifactFiles -Envelope $envelope -StagingRoot $stagingRoot -InstallRoot $installRoot -AllowedWriterSet $allowedWriterSet
    $envelopeSha256 = Get-NgSha256Hex -Bytes $envelopeBytes
    $sequence = Add-NgReplayEntry -LedgerPath $ledgerFullPath -LedgerKeyPath $ledgerKeyFullPath `
        -LedgerId $LedgerId -Nonce $envelope.nonce -EnvelopeSha256 $envelopeSha256 `
        -NowUtc $nowUtc -AllowedWriterSet $allowedWriterSet

    return [pscustomobject][ordered]@{
        accepted = $true
        status = 'verified-and-nonce-consumed'
        operation = $script:InstallOperation
        candidateVersion = $script:PromotionCandidateVersion
        envelopeId = $envelope.envelopeId
        envelopeSha256 = $envelopeSha256
        repositoryId = $envelope.repository.id
        commitSha = $envelope.repository.commitSha
        treeSha = $envelope.repository.treeSha
        artifactSetSha256 = $envelope.artifactSetSha256
        expiresAtUtc = $timeBinding.expiresAtUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        ledgerSequence = $sequence
        applyEnabled = $false
        executableActions = @()
        installed = $false
    }
}

Export-ModuleMember -Function @('Test-NorthGatePromotionEnvelope')
