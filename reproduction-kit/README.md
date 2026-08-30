# Clean-room installation kit

This directory defines the workstation-side process for producing a sealed,
offline bundle that can install a new NorthGate create-only VM Factory and leave
it stopped, startup-disabled, and unable to apply a plan.

The repository is not itself an installation kit. A usable kit must be assembled
from one exact signed release tuple and a fresh, host-specific deployment
authorization. The deployment authorization expires within 24 hours, so an old
bundle remains useful as evidence but is not silently reusable on another host.

## Contents

- `New-NorthGateCleanRoomKit.ps1` assembles and seals the bundle on an authorized
  workstation.
- `Test-NorthGateCleanRoomKit.ps1` verifies the bundle inventory, exact hashes,
  source bindings, and disabled initial policy without installing anything.
- `INSTALL.md` is copied into each generated bundle as its operator runbook.
- `Test-CleanRoomKit.ps1` contains portable negative and integration tests.

## Required inputs

The assembler requires:

1. A clean checkout at the exact commit/tree recorded in the release manifest.
2. The immutable release package and detached release-manifest signature.
3. A fresh, detached-CMS-signed host deployment authorization whose
   `initialPolicy` is disabled.
4. The signed create-only backend policy and signed canonical data bundle.
5. Public `.cer` exports for the four distinct release, deployment-authorization,
   approval, and receipt signer roles.

Private keys, passwords, tokens, generated guest credentials, live plans,
receipts, DPAPI state, and host ledgers are forbidden from the kit.

## Build

Build only after the normal release ceremony has produced the complete signed
tuple. The output parent must exist, be outside every Git worktree, and the final
output directory must not already exist.

```powershell
./reproduction-kit/New-NorthGateCleanRoomKit.ps1 `
  -SourceRoot . `
  -OutputDirectory 'C:\NorthGate-Staging\ngcor-clean-room-kit' `
  -ReleasePackageRoot 'C:\NorthGate-Staging\release\package' `
  -ReleaseManifestSignaturePath 'C:\NorthGate-Staging\release\release-manifest.p7s' `
  -SignedHostDeploymentAuthorizationPath 'C:\NorthGate-Staging\authorization\host-authorization.json' `
  -DeploymentAuthorizationSignaturePath 'C:\NorthGate-Staging\authorization\host-authorization.p7s' `
  -BackendPolicyPath 'C:\NorthGate-Staging\policy\backend-policy.json' `
  -BackendPolicySignaturePath 'C:\NorthGate-Staging\policy\backend-policy.p7s' `
  -DataBundleRoot 'C:\NorthGate-Staging\data-bundle' `
  -ReleaseSignerPublicCertificatePath 'C:\NorthGate-Staging\trust\release-signer.cer' `
  -DeploymentAuthorizationSignerPublicCertificatePath 'C:\NorthGate-Staging\trust\deployment-authorization-signer.cer' `
  -ApprovalSignerPublicCertificatePath 'C:\NorthGate-Staging\trust\approval-signer.cer' `
  -ReceiptSignerPublicCertificatePath 'C:\NorthGate-Staging\trust\receipt-signer.cer' `
  -ConfirmKitBuild
```

The assembler verifies detached signatures, signer pins, repository bindings,
host-authorization semantics, policy/data bindings, the disabled initial state,
and every copied byte. It writes:

- `clean-room-kit.json`: the complete immutable inventory and install inputs;
- `clean-room-kit.sha256`: the out-of-band review value;
- `bootstrap/`: one-time pinned installer and rollback copies;
- `release/`, `authorization/`, `policy/`, and `data-bundle/`: the signed tuple;
- `trust/`: public certificates only;
- `tools/` and `README.md`: verification and operator instructions.

Record the `clean-room-kit.json` SHA-256 in the approved change record before
transfer. Git merge remains separate from installation and activation approval.

## Security and lifecycle

- Build on an authorized workstation; never execute a repository checkout on the
  Hyper-V host.
- Transfer the generated bundle over the pinned administrative path and verify the
  recorded manifest SHA-256 after transfer.
- Installation uses the generated bootstrap installer and the exact values in the
  verified manifest. It leaves the service stopped/disabled.
- Do not run the initial-activation helper. Activation is a later, separately
  signed and approved gate.
- Archive the kit as release evidence or destroy its short-lived authorization
  copy under the approved retention process. Never refresh dates or host bindings
  by editing an existing bundle.
