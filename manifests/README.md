# VM manifests

This directory is intentionally empty during the plan-only bootstrap phase.

A new VM may be proposed only after owner, purpose, environment, classification, criticality, recovery, dependencies, retirement/review date, and change reference are approved, and all opaque image/network/storage/firmware/bootstrap/recovery/owner references resolve to separately promoted profiles.

An existing VM does not become managed by adding a `VirtualMachine` file. It first requires reconciled read-only inventory, a protected identity-ledger binding, a separate `AdoptionRequest`, and a first plan that is exactly `NoOp`.

Place future approved manifests under `manifests/vms/<asset-id>.json`. Removing or renaming a file reports drift only and never authorizes replacement, decommission, disk deletion, or purge.
