# Create-only artifact authoring tools

This module creates canonical, detached-CMS-signed inputs for the installed
NorthGate create-only backend. It is an authoring surface, not a Hyper-V apply
surface. It never creates, changes, starts, or deletes a VM.

The exported tools build:

- a data-only bundle from exact raw Git blobs and their provenance;
- the immutable backend policy bound to host authorization and release hashes;
- a one-use approval bound to an authenticated host plan.

Signing certificates are selected by an exact SHA-256 pin and must have a
private key, Code Signing EKU, Digital Signature key usage, and a non-CA Basic
Constraints profile. Repository secrets and VM credentials are not accepted by
these tools. Output directories are create-new and claims prevent accidentally
authoring two approvals for the same plan.

Run `Test-CreateOnlyAuthoringTools.ps1` for the inert artifact and negative-test
suite. Live rollout promotions are authored through the native-Administrator
promotion helper in the installed release so that its payload begins with the
backend's authenticated live promotion context.
