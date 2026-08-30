# NG-PROJ-SW-001 clean-room kit

This directory retains the sealed NorthGate VM Factory clean-room package produced for project closeout on 2026-08-30.

- Kit ID: `ngcrk-ngcor-1.0.46-fda336c-362e8183d4ff`
- Runtime release: `ngcor-1.0.46-fda336c`
- Runtime commit: `fda336ce4b61db559da7b85fa4e2584e830ee9f9`
- Target host: `HC-HV01`
- ZIP SHA-256: `914155bedbf81148c83e98ca716d2a78ac34246f773533b15ceb90da1d649098`
- Installation state: stopped, startup-disabled, apply disabled, no activation included

The archive contains public certificates only. It contains no private keys, passwords, tokens, or generated guest credentials.

## Time-bound installation authority

The bundled authorization and signed data are intentionally short-lived. The authorization expires at `2026-08-30T18:40:49Z`, and the signed data bundle expires at `2026-08-30T16:40:57Z`. After the earliest expiry, retain this ZIP as release evidence only. Do not edit or extend signed dates.

For a later installation, use the checked-in `reproduction-kit/New-NorthGateCleanRoomKit.ps1` workflow with a fresh host-specific signed authorization, policy, and data bundle. Repository presence is not deployment or VM execution approval.
