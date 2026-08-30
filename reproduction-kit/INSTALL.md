# NorthGate VM Factory clean-room installation

This sealed bundle installs one exact signed create-only factory release on the
host named by its deployment authorization. It must finish with the service
stopped, startup type `Disabled`, `applyEnabled=false`, no executable actions,
and canary stage `disabled`.

## External prerequisites

The bundle intentionally does not contain secrets or private keys. Before the
installation window, independently provision and verify:

- Windows Server 2022 with Hyper-V and OpenSSH Server already installed;
- the exact computer, SMBIOS UUID, OS build, switch, volume, media, and retained
  VM identities in `authorization/host-deployment-authorization.json`;
- the unprivileged routine SSH identity and virtual service identity with the
  exact SIDs in that authorization;
- the pinned release signer as a trusted code-signing publisher;
- the non-exportable approval and receipt signing private keys in their approved
  certificate stores, with the receipt-key ACL required by the installer;
- confined `sshd_config` and authorized-key inputs, recovery backup, maintenance
  window, and Administrator rollback access.

Do not import private keys from this bundle. If any prerequisite differs, stop and
issue a new signed host authorization rather than modifying this kit.

## Verify before elevation

Obtain the expected `clean-room-kit.json` SHA-256 from the approved change record,
not from this directory alone.

```powershell
$kitRoot = 'C:\NorthGate-Staging\ngcor-clean-room-kit'
$expectedKitManifestSha256 = '<approved 64-character SHA-256>'
$verified = & "$kitRoot\tools\Test-NorthGateCleanRoomKit.ps1" `
  -KitRoot $kitRoot `
  -ExpectedKitManifestSha256 $expectedKitManifestSha256 `
  -RequireCurrentlyInstallable
$verified
```

Continue only when the status is `verified-disabled-installation-kit` and the
target-host identity is the intended clean-room host.

## Install disabled

Open a native elevated Windows PowerShell session. Re-read the manifest and invoke
only the generated, hash-reviewed bootstrap installer. The following block derives
every parameter from the already verified data-only manifest; it does not activate
the factory.

```powershell
$manifest = Get-Content -Raw -LiteralPath "$kitRoot\clean-room-kit.json" | ConvertFrom-Json
$input = $manifest.installInputs

& (Join-Path $kitRoot $input.bootstrapInstallerPath) `
  -PackageRoot (Join-Path $kitRoot $input.packageRoot) `
  -ExpectedReleaseManifestSha256 $input.releaseManifestSha256 `
  -ExpectedCommit $manifest.repository.commit `
  -ExpectedTree $manifest.repository.tree `
  -ExpectedHostAllowlistId $manifest.repository.hostAllowlistId `
  -ReleaseManifestSignaturePath (Join-Path $kitRoot $input.releaseManifestSignaturePath) `
  -SignedHostDeploymentAuthorizationPath (Join-Path $kitRoot $input.signedHostDeploymentAuthorizationPath) `
  -DeploymentAuthorizationSignaturePath (Join-Path $kitRoot $input.deploymentAuthorizationSignaturePath) `
  -ExpectedDeploymentAuthorizationSha256 $input.deploymentAuthorizationSha256 `
  -BackendPolicyPath (Join-Path $kitRoot $input.backendPolicyPath) `
  -BackendPolicySignaturePath (Join-Path $kitRoot $input.backendPolicySignaturePath) `
  -ExpectedBackendPolicySha256 $input.backendPolicySha256 `
  -DataBundleRoot (Join-Path $kitRoot $input.dataBundleRoot) `
  -ExpectedDataBundleSha256 $input.dataBundleSha256 `
  -ConfirmInstall
```

The installer independently verifies all detached CMS and Authenticode signatures,
host bindings, ACL and identity requirements, exact file inventory, and signed data
before mutation.

## Required postconditions

```powershell
$service = Get-CimInstance Win32_Service -Filter "Name='NorthGateCreateOnly'"
$authorization = Get-Content -Raw -LiteralPath `
  (Join-Path $kitRoot $input.signedHostDeploymentAuthorizationPath) | ConvertFrom-Json
$policyPath = Join-Path (Split-Path -Parent $authorization.install.stateRoot) `
  'policy\installed-policy.json'
$policy = Get-Content -Raw -LiteralPath $policyPath | ConvertFrom-Json

if ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled') {
  throw 'NGCRK-POSTCONDITION-SERVICE-NOT-DISABLED'
}
if ($policy.applyEnabled -ne $false -or @($policy.executableActions).Count -ne 0 -or
    $policy.canaryStage -ne 'disabled') {
  throw 'NGCRK-POSTCONDITION-POLICY-NOT-DISABLED'
}
```

Also verify the release pointer, installed hashes, forced-command isolation,
unauthorized mutation rejection, deployment receipt, and collateral VM inventory.
Record those results in Operation-SeeSaw.

Do not run `Enable-NorthGateCreateOnlyInitialActivation.ps1`. Activation remains a
separate signed decision after disabled-mode security and rollback tests pass.
