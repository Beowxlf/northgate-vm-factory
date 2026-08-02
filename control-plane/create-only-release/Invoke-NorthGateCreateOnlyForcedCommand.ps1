[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pipeName = 'NorthGate.VMFactory.CreateOnly.v1'
$maximumPlanBytes = 32768
$maximumResponseBytes = 65536

function Stop-NgcorForcedCommand {
    param([string]$Code, [int]$ExitCode = 1)
    if ($Code -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') { $Code = 'NGCOR-REQUEST-REJECTED' }
    $safe = '{"error":"' + $Code + '","status":"rejected"}'
    [Console]::Out.Write($safe)
    exit $ExitCode
}

function Assert-NgcorInstalledLocation {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $requiredPrefix = Join-Path $programFiles 'NorthGate\VMFactory\CreateOnly\releases'
    $resolvedRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
    if (-not $resolvedRoot.StartsWith($requiredPrefix + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath (Join-Path $resolvedRoot 'installed-release.json') -PathType Leaf)) {
        throw 'NGCOR-CHECKOUT-EXECUTION-FORBIDDEN'
    }
}

function Read-NgcorStandardInput {
    param([int]$MaximumBytes, [int]$TimeoutMilliseconds)
    $stream = [Console]::OpenStandardInput()
    $memory = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 4096
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    try {
        while ($true) {
            $remaining = [int][Math]::Max(1, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
            $task = $stream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $task.Wait($remaining)) { throw 'NGCOR-STDIN-TIMEOUT' }
            $count = $task.Result
            if ($count -eq 0) { break }
            if ($memory.Length + $count -gt $MaximumBytes) { throw 'NGCOR-STDIN-SIZE-EXCEEDED' }
            $memory.Write($buffer, 0, $count)
        }
        $memory.ToArray()
    }
    finally { $memory.Dispose() }
}

function Read-NgcorPipeExact {
    param([System.IO.Stream]$Stream, [int]$Count, [int]$TimeoutMilliseconds)
    $buffer = New-Object byte[] $Count
    $offset = 0
    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ($offset -lt $Count) {
        $remaining = [int][Math]::Max(1, ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
        $task = $Stream.ReadAsync($buffer, $offset, $Count - $offset)
        if (-not $task.Wait($remaining)) { throw 'NGCOR-PIPE-READ-TIMEOUT' }
        if ($task.Result -le 0) { throw 'NGCOR-PIPE-CLOSED' }
        $offset += $task.Result
    }
    $buffer
}

try {
    Assert-NgcorInstalledLocation
    $protocolPath = Join-Path $PSScriptRoot 'NorthGate.VMFactory.CreateOnlyProtocol.psd1'
    Import-Module $protocolPath -Force -ErrorAction Stop

    $originalCommand = [Environment]::GetEnvironmentVariable('SSH_ORIGINAL_COMMAND', 'Process')
    if ($null -eq $originalCommand) { throw 'NGCOR-COMMAND-MISSING' }
    $parsedCommand = ConvertFrom-NorthGateCreateOnlyCommand $originalCommand

    if ($parsedCommand.operation -ceq 'plan') {
        $requestBytes = Read-NgcorStandardInput ($maximumPlanBytes + 1) 5000
        $parsedRequest = ConvertFrom-NorthGateCreateOnlyPlanRequestBytes $requestBytes
        $body = $parsedRequest.CanonicalJson
    }
    else {
        $requestBytes = Read-NgcorStandardInput 1 2000
        if ($requestBytes.Length -ne 0) { throw 'NGCOR-STDIN-NOT-EMPTY' }
        $body = ''
    }

    $envelope = [pscustomobject][ordered]@{ version = 1; command = $originalCommand; body = $body }
    $payload = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-NorthGateCreateOnlyCanonicalJson $envelope)
    )
    if ($payload.Length -gt 65536) { throw 'NGCOR-ENVELOPE-SIZE-INVALID' }

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous,
        [System.Security.Principal.TokenImpersonationLevel]::Identification
    )
    try {
        $pipe.Connect(3000)
        $lengthBytes = [BitConverter]::GetBytes([int]$payload.Length)
        $pipe.Write($lengthBytes, 0, 4)
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()
        $responseLengthBytes = Read-NgcorPipeExact $pipe 4 10000
        $responseLength = [BitConverter]::ToInt32($responseLengthBytes, 0)
        if ($responseLength -le 0 -or $responseLength -gt $maximumResponseBytes) {
            throw 'NGCOR-PIPE-RESPONSE-SIZE-INVALID'
        }
        $responseBytes = Read-NgcorPipeExact $pipe $responseLength 10000
        try {
            $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
            $response = $strictUtf8.GetString($responseBytes)
        }
        catch { throw 'NGCOR-PIPE-RESPONSE-UTF8-INVALID' }
        [Console]::Out.Write($response)
        exit 0
    }
    finally { $pipe.Dispose() }
}
catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^NGCOR-[A-Z0-9-]{1,96}$') { $code = 'NGCOR-REQUEST-REJECTED' }
    Stop-NgcorForcedCommand $code 1
}
