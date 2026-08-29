[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ServiceHostAssertions = 0

function Assert-NgchTest {
    param([bool]$Condition, [string]$Message)
    $script:ServiceHostAssertions++
    if (-not $Condition) { throw "SERVICE HOST ASSERTION FAILED: $Message" }
}

function Assert-NgchThrows {
    param([scriptblock]$Action, [string]$Pattern, [string]$Message)
    $script:ServiceHostAssertions++
    try { & $Action; throw "SERVICE HOST ASSERTION FAILED: $Message (no exception)" }
    catch {
        if ($_.Exception.Message -like 'SERVICE HOST ASSERTION FAILED:*') { throw }
        if ($_.Exception.Message -cnotmatch $Pattern) {
            throw "SERVICE HOST ASSERTION FAILED: $Message (got $($_.Exception.Message))"
        }
    }
}

function Get-NgchSha256 {
    param([string]$Path)
    $stream = New-Object System.IO.FileStream(
        $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read, 65536, [System.IO.FileOptions]::SequentialScan
    )
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($stream) }
    finally { $algorithm.Dispose(); $stream.Dispose() }
    (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

$root = $PSScriptRoot
$sourcePath = Join-Path $root 'NorthGate.CreateOnly.ServiceHost.cs'
$builderPath = Join-Path $root 'Build-NorthGateCreateOnlyServiceHost.ps1'
$serviceScriptPath = Join-Path $root 'Start-NorthGateCreateOnlyPipeService.ps1'
$forcedScriptPath = Join-Path $root 'Invoke-NorthGateCreateOnlyForcedCommand.ps1'
$promotionScriptPath = Join-Path $root 'New-NorthGateCreateOnlyRolloutPromotion.ps1'
$activationScriptPath = Join-Path $root 'Enable-NorthGateCreateOnlyInitialActivation.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ('ngcor-service-host-test-' + [guid]::NewGuid().ToString('N'))

try {
    $source = [System.IO.File]::ReadAllText($sourcePath)
    $builder = [System.IO.File]::ReadAllText($builderPath)
    $serviceScript = [System.IO.File]::ReadAllText($serviceScriptPath)
    $forcedScript = [System.IO.File]::ReadAllText($forcedScriptPath)
    $promotionScript = [System.IO.File]::ReadAllText($promotionScriptPath)
    $activationScript = [System.IO.File]::ReadAllText($activationScriptPath)
    Assert-NgchTest ($source -match 'ServiceBase\.Run' -and $source -match 'RunspaceFactory\.CreateRunspace') `
        'Native host runs as a Windows service and hosts Windows PowerShell in-process.'
    Assert-NgchTest ($source -match 'Start-NorthGateCreateOnlyPipeService\.ps1' -and
        $source -match 'StringComparison\.OrdinalIgnoreCase') `
        'Native host accepts only its adjacent fixed service script.'
    Assert-NgchTest ($source -match 'NorthGateServiceStopEvent' -and
        $source -match 'ManualResetEvent' -and $source -match 'Join\(15000\)') `
        'Native host has bounded cooperative stop handling.'
    Assert-NgchTest ($source -cnotmatch 'Process\.Start|powershell\.exe|cmd\.exe|CreateProcess|ShellExecute') `
        'Native host does not launch a shell or child process.'
    Assert-NgchTest ($source -match 'PipeClientIdentityCapture' -and
        $source -match 'pipe\.RunAsClient' -and $source -match 'WindowsPrincipal' -and
        $serviceScript -match 'PipeClientIdentityCapture\]::Capture\(\$pipe\)' -and
        $serviceScript -notmatch '\$identityBox' -and
        $serviceScript.IndexOf('Read-NgcorExact $pipe $length 5000') -lt
        $serviceScript.IndexOf('PipeClientIdentityCapture]::Capture($pipe)')) `
        'Client identity and administrator membership are captured inside the fixed native host.'
    Assert-NgchTest ($forcedScript -match 'TokenImpersonationLevel\]::Impersonation' -and
        $forcedScript -notmatch 'TokenImpersonationLevel\]::Identification') `
        'Authenticated pipe clients permit the fixed signed service host to capture their effective Windows identity.'
    Assert-NgchTest ($source -match 'public static class PipeServerIdentityVerifier' -and
        $source -match 'GetNamedPipeServerProcessId' -and $source -match 'QueryServiceStatusEx' -and
        $forcedScript -notmatch 'Add-Type\s+-TypeDefinition' -and
        $promotionScript -notmatch 'Add-Type\s+-TypeDefinition' -and
        $activationScript -notmatch 'Add-Type\s+-TypeDefinition' -and
        $forcedScript.IndexOf('Test-NgcorDetachedCms') -lt
        $forcedScript.IndexOf('[Reflection.Assembly]::Load')) `
        'Forced-command and promotion pipe verification use the precompiled signed service host without runtime compilation.'
    Assert-NgchTest ($source -match 'GetSafeFailureCode' -and
        $source -match 'NGCOR-\[A-Z0-9-\]' -and $source -match 'exception\.GetType\(\)\.FullName') `
        'Native host reports only bounded NorthGate codes or exception types when the engine fails.'
    Assert-NgchTest ($builder -cnotmatch 'Invoke-Expression|DownloadString|WebClient|Start-Process') `
        'Build helper has no dynamic evaluation or network primitive.'
    Assert-NgchTest ($builder -match '/deterministic\+' -and $builder -match '/warnaserror\+' -and
        $builder -match 'ExpectedCompilerSha256') `
        'Build helper requests deterministic warnings-as-errors output from an exact-hash-pinned compiler.'
    Assert-NgchTest ($serviceScript -match 'NorthGateServiceStopEvent') `
        'Service loop is bound to the native host stop event.'
    Assert-NgchTest ($serviceScript -match 'NGCOR-INSTALLED-POLICY-DISABLED' -and
        $serviceScript -match "status = 'installed-disabled'" -and
        $serviceScript -match 'applyEnabled = \$false') `
        'A running diagnostic service exposes disabled status but rejects every non-status operation.'
    Assert-NgchTest ($serviceScript -notmatch 'Get-CimInstance -ClassName Win32_Service' -and
        $serviceScript -match '\$expectedStartType = if \(\[bool\]\$policy\.applyEnabled\) \{ ''Automatic'' \} else \{ ''Disabled'' \}' -and
        $serviceScript -match '\[System\.Diagnostics\.Process\]::GetCurrentProcess\(\)\.MainModule\.FileName' -and
        $serviceScript -match '\$service\.StartType -cne \$expectedStartType' -and
        $serviceScript -match '\$service\.Status -notin @\(''StartPending'',''Running''\)') `
        'Least-privilege startup accepts the SCM StartPending race while verifying its host path and disabled-or-automatic posture without WMI.'
    Assert-NgchTest ($serviceScript -match 'Test-NgcdInitialActivationState' -and
        $serviceScript -match 'initialActivationSha256' -and
        $serviceScript -match 'NGCOR-INITIAL-ACTIVATION-STATE-INVALID') `
        'An active service requires the HMAC and approval-signer bound initial activation record.'
    Assert-NgchTest ($activationScript -match [regex]::Escape(
            "Join-Path `$installedRoot 'backend-data\bundle.json'"
        ) -and $activationScript -notmatch [regex]::Escape(
            "Join-Path `$installedRoot 'data-bundle.json'"
        )) `
        'Initial activation verifies the data bundle at the installer-owned runtime path.'
    Assert-NgchTest ($serviceScript -match '\$backendContext = \$null\s+if \(\[bool\]\$policy\.applyEnabled\)' -and
        $serviceScript.IndexOf('if ([bool]$policy.applyEnabled)') -lt
        $serviceScript.IndexOf('$backendContext = New-NorthGateCreateOnlyBackendContext')) `
        'Disabled status startup does not initialize the mutation-capable backend.'
    $contextIndex = $serviceScript.IndexOf('$backendContext = New-NorthGateCreateOnlyBackendContext')
    $recoveryIndex = $serviceScript.IndexOf('Invoke-NorthGateCreateOnlyCrashRecovery -Context $backendContext')
    $listenIndex = $serviceScript.IndexOf('while (-not $serviceStopEvent.WaitOne(0))')
    Assert-NgchTest ($contextIndex -ge 0 -and $recoveryIndex -gt $contextIndex -and
        $listenIndex -gt $recoveryIndex) `
        'Active startup completes authenticated crash recovery before accepting pipe requests.'

    $null = [System.IO.Directory]::CreateDirectory($testRoot)
    $firstRoot = Join-Path $testRoot 'first'
    $secondRoot = Join-Path $testRoot 'second'
    $null = [System.IO.Directory]::CreateDirectory($firstRoot)
    $null = [System.IO.Directory]::CreateDirectory($secondRoot)
    $firstOutput = Join-Path $firstRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $secondOutput = Join-Path $secondRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $firstProvenance = Join-Path $firstRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    $secondProvenance = Join-Path $secondRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'

    try { Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop }
    catch { throw 'SERVICE HOST ASSERTION FAILED: System.ServiceProcess is unavailable.' }
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $compilerPath = @(
        (Join-Path $programFilesX86 'Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFilesX86 'Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe'),
        (Join-Path $programFiles 'Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($compilerPath)) {
        throw 'SERVICE HOST ASSERTION FAILED: approved Roslyn compiler is unavailable.'
    }
    $automationAssemblyPath = [System.Management.Automation.PowerShell].Assembly.Location
    $mscorlibAssemblyPath = [object].Assembly.Location
    $systemAssemblyPath = [System.ComponentModel.Component].Assembly.Location
    $systemCoreAssemblyPath = [System.Linq.Enumerable].Assembly.Location
    $serviceProcessAssemblyPath = [System.ServiceProcess.ServiceBase].Assembly.Location
    $sourceHash = Get-NgchSha256 $sourcePath
    $compilerHash = Get-NgchSha256 $compilerPath
    $mscorlibHash = Get-NgchSha256 $mscorlibAssemblyPath
    $systemHash = Get-NgchSha256 $systemAssemblyPath
    $systemCoreHash = Get-NgchSha256 $systemCoreAssemblyPath
    $automationHash = Get-NgchSha256 $automationAssemblyPath
    $serviceProcessHash = Get-NgchSha256 $serviceProcessAssemblyPath

    $first = & $builderPath -OutputPath $firstOutput -ProvenancePath $firstProvenance `
        -CompilerPath $compilerPath `
        -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
        -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
        -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
        -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    $second = & $builderPath -OutputPath $secondOutput -ProvenancePath $secondProvenance `
        -CompilerPath $compilerPath `
        -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
        -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
        -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
        -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    Assert-NgchTest ($first.status -ceq 'built-unsigned-service-host' -and $first.signingRequired -eq $true -and
        $second.status -ceq 'built-unsigned-service-host') 'Build outputs are explicitly unsigned promotion inputs.'
    Assert-NgchTest ((Test-Path -LiteralPath $firstOutput -PathType Leaf) -and
        (Test-Path -LiteralPath $secondOutput -PathType Leaf) -and
        (Test-Path -LiteralPath $firstProvenance -PathType Leaf) -and
        (Test-Path -LiteralPath $secondProvenance -PathType Leaf)) `
        'Build helper emits the fixed service host and canonical provenance record.'
    Assert-NgchTest ($first.outputSha256 -ceq $second.outputSha256 -and
        (Get-NgchSha256 $firstOutput) -ceq (Get-NgchSha256 $secondOutput)) `
        'Two clean builds produce identical service-host bytes.'
    $assembly = [System.Reflection.AssemblyName]::GetAssemblyName($firstOutput)
    Assert-NgchTest ($assembly.Name -ceq 'NorthGate.CreateOnly.ServiceHost' -and
        $assembly.Version.ToString() -ceq '1.0.0.0') 'Built service host has the fixed assembly identity.'
    Assert-NgchTest ($first.signingRequired -eq $true) `
        'Build stage declares detached CMS promotion still required.'
    $loadedHost = [System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes($firstOutput))
    $captureType = $loadedHost.GetType(
        'NorthGate.VMFactory.CreateOnly.PipeClientIdentityCapture', $true, $false)
    $pipeName = 'ngcor-identity-test-' + [guid]::NewGuid().ToString('N')
    $server = New-Object System.IO.Pipes.NamedPipeServerStream(
        $pipeName, [System.IO.Pipes.PipeDirection]::InOut, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        [System.IO.Pipes.PipeOptions]::None
    )
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation
    )
    try {
        $client.Connect(2000)
        $server.WaitForConnection()
        $probeBytes = [byte[]]@(1)
        $probeWrite = $client.WriteAsync($probeBytes, 0, 1)
        Assert-NgchTest ($server.ReadByte() -eq 1) `
            'Identity capture test establishes the Windows data-read impersonation precondition.'
        $null = $probeWrite.GetAwaiter().GetResult()
        $captureArguments = New-Object object[] 1
        $captureArguments[0] = $server.PSObject.BaseObject
        $capturedIdentity = $captureType.GetMethod('Capture').Invoke($null, $captureArguments)
        $expectedIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $expectedPrincipal = New-Object System.Security.Principal.WindowsPrincipal($expectedIdentity)
        Assert-NgchTest ($capturedIdentity.Sid -ceq [string]$expectedIdentity.User.Value -and
            $capturedIdentity.IsAdministrator -eq
            $expectedPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) `
            'Native capture returns the connected client SID and effective administrator membership.'
        $verifierType = $loadedHost.GetType(
            'NorthGate.VMFactory.CreateOnly.PipeServerIdentityVerifier', $true, $false)
        $serverPidArguments = New-Object object[] 1
        $serverPidArguments[0] = $client.SafePipeHandle.PSObject.BaseObject
        $serverProcessId = [uint32]$verifierType.GetMethod('GetPipeServerProcessId').Invoke(
            $null, $serverPidArguments)
        Assert-NgchTest ($serverProcessId -eq [uint32][Diagnostics.Process]::GetCurrentProcess().Id) `
            'Precompiled verifier resolves the connected named-pipe server process without runtime compilation.'
    }
    finally {
        $client.Dispose()
        $server.Dispose()
    }
    $firstProvenanceText = [IO.File]::ReadAllText($firstProvenance)
    $firstProvenanceObject = ConvertFrom-Json $firstProvenanceText
    Assert-NgchTest ($firstProvenanceObject.schema -ceq
        'northgate/create-only-service-host-build-provenance/v1' -and
        $firstProvenanceObject.deterministic -eq $true -and
        $firstProvenanceObject.unsignedSha256 -ceq $first.outputSha256 -and
        @($firstProvenanceObject.references).Count -eq 5) `
        'Provenance binds the deterministic unsigned output and all five references.'

    $badOutputRoot = Join-Path $testRoot 'bad-hash'
    $null = [System.IO.Directory]::CreateDirectory($badOutputRoot)
    $badOutput = Join-Path $badOutputRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $badProvenance = Join-Path $badOutputRoot 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    Assert-NgchThrows {
        & $builderPath -OutputPath $badOutput -ProvenancePath $badProvenance -CompilerPath $compilerPath `
            -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
            -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
            -ExpectedCompilerSha256 ('0' * 64) -ExpectedAutomationAssemblySha256 $automationHash `
            -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    } '^NGCOR-SERVICE-HOST-BUILD-COMPILER-HASH-MISMATCH$' `
        'Build refuses an unapproved compiler hash.'
    Assert-NgchTest (-not (Test-Path -LiteralPath $badOutput) -and
        -not (Test-Path -LiteralPath $badProvenance)) `
        'Rejected toolchain provenance creates no executable.'

    $unapprovedCompiler = Join-Path $testRoot 'unapproved-csc.exe'
    [System.IO.File]::Copy($compilerPath,$unapprovedCompiler,$false)
    $unapprovedRoot = Join-Path $testRoot 'unapproved-compiler'
    $null = [System.IO.Directory]::CreateDirectory($unapprovedRoot)
    $unapprovedOutput = Join-Path $unapprovedRoot 'NorthGate.CreateOnly.ServiceHost.exe'
    $unapprovedProvenance = Join-Path $unapprovedRoot `
        'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    Assert-NgchThrows {
        & $builderPath -OutputPath $unapprovedOutput -ProvenancePath $unapprovedProvenance `
            -CompilerPath $unapprovedCompiler `
            -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
            -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
            -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
            -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    } '^NGCOR-SERVICE-HOST-BUILD-COMPILER-INVALID$' `
        'Build refuses an exact-copy compiler outside the fixed vendor path allowlist.'
    Assert-NgchTest (-not (Test-Path -LiteralPath $unapprovedOutput) -and
        -not (Test-Path -LiteralPath $unapprovedProvenance)) `
        'Unapproved compiler path rejection writes nothing.'

    $repositoryOutput = Join-Path $root 'NorthGate.CreateOnly.ServiceHost.exe'
    $repositoryProvenance = Join-Path $root 'NorthGate.CreateOnly.ServiceHost.build-provenance.json'
    Assert-NgchThrows {
        & $builderPath -OutputPath $repositoryOutput -ProvenancePath $repositoryProvenance `
            -CompilerPath $compilerPath `
            -ExpectedSourceSha256 $sourceHash -ExpectedMscorlibAssemblySha256 $mscorlibHash `
            -ExpectedSystemAssemblySha256 $systemHash -ExpectedSystemCoreAssemblySha256 $systemCoreHash `
            -ExpectedCompilerSha256 $compilerHash -ExpectedAutomationAssemblySha256 $automationHash `
            -ExpectedServiceProcessAssemblySha256 $serviceProcessHash
    } '^NGCOR-SERVICE-HOST-BUILD-OUTPUT-IN-REPOSITORY$' `
        'Build refuses to place generated binaries in the Git worktree.'
    Assert-NgchTest (-not (Test-Path -LiteralPath $repositoryOutput) -and
        -not (Test-Path -LiteralPath $repositoryProvenance)) `
        'Repository-output rejection writes nothing.'

    Write-Output "PASS: $script:ServiceHostAssertions service-host assertions"
}
finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}

# SIG # Begin signature block
# MIIHiQYJKoZIhvcNAQcCoIIHejCCB3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBKqCE0W/Xu633v
# Mv8ezeF3qmhY6KcJAT0uwYYp8b10NqCCBF0wggRZMIICwaADAgECAhAvazDvs9z4
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
# hvcNAQkEMSIEIFvE1X26SSXPwXpL3YNDKw3C1cQqLV/pbx82T53dBYVVMA0GCSqG
# SIb3DQEBAQUABIIBgDec5QzuAfq74aZcf60G+jCrOFMJ0ZUQFnXFpTdLmrsjAt69
# G9EQZeXg5lNFOUld/qPispQ6N2OEX96uouSqqzg9gcpLypft9CzIUeQs9NywEZEA
# qgIQNFOB8weRCQVWI3z/pyCr5soSacDjhH6o2/lVOC5jfs1Y0LFh9HfuNy7KjkOA
# PuTFrL2vrqD454aGISNDXRUr/ERMtQc4/0QItBrK+xhfbOtf71kCFH2kiPRiFZic
# 3QzrN3yBL8awRehu5pjQsCDSbn9j05eNKCU1xGwaTixa08SpFDi+DqtoVJCQCu0i
# +MvPb+X1bWOlih874NII5IH/vB0zp+iStzIxT/+K6bkXAL4LhuUpNysJqVhqa9qd
# uubXBoERdWJdHOL7p6SScDFKsFLHyqJyqIsKyiOTqlaZxbRWCPZKNURq02vn4L1A
# G+ds2ri+jK6h0vtmnqLGYUurqQq9Vrg2P78KG3rIoXuwfzfHgs1ySzpgJHLZZNOR
# huyDPy60tTJFoFZ9EA==
# SIG # End signature block
