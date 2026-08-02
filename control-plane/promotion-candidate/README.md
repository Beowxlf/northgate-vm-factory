# Signed promotion compensating-control candidate

## Status

**Local-only, proposed, and non-installing.** This directory contains a Windows PowerShell 5.1 verifier candidate and its tests. It has not been installed on a workstation or host, has not been signed with an owner key, and cannot enable VM Factory apply. Its only state change is an authenticated replay-ledger update after a complete envelope verification succeeds.

This is a candidate compensating control for an environment where GitHub protected-branch enforcement is not presently available. It does not claim equivalence to protected branches, independent review, or an installed privileged release. A human owner signature over an immutable, exact release envelope is an additional promotion boundary; Git remains reviewed input rather than deployment authority.

## Exact trust model

`Test-NorthGatePromotionEnvelope` accepts three untrusted staged files:

- canonical UTF-8 JSON envelope, no BOM;
- raw detached RSA PKCS#1 v1.5 SHA-256 signature;
- DER public certificate whose SHA-256 is pinned by installed policy.

All `Expected*` values, the certificate pin, fixed roots, ledger identity, and writer SID allowlist are trusted host-policy inputs. They must never come from the envelope, a checkout, an environment variable, or a moving Git reference.

The verifier requires:

1. exact repository ID and HTTPS `.git` URI;
2. exact lower-case 40-hex commit and tree IDs;
3. exact artifact identifiers, source/destination relative paths, sizes, individual SHA-256 values, and aggregate artifact-set SHA-256;
4. a pinned, currently valid, non-CA RSA certificate with a key of at least 3072 bits, DigitalSignature usage, and Code Signing EKU;
5. a detached signature over the exact envelope bytes;
6. a canonical v1 envelope with a maximum 15-minute policy bound, a 60-second future clock allowance, and a 256-bit base64url nonce;
7. exact fixed install and staging roots plus a distinct fixed state root;
8. protected root DACLs, allowlisted owners, and no write-class allow ACE for a non-allowlisted SID;
9. no reparse point from a fixed root to any staged artifact;
10. actual staged file sizes and SHA-256 values matching the signed and independently expected artifact set;
11. `applyEnabled: false`, an empty `actions` array, and the exact `install-control-plane-candidate` operation;
12. an HMAC-SHA-256-authenticated replay ledger under an exclusive writer lock, with a unique nonce digest and atomic same-volume replacement.

Successful output says `verified-and-nonce-consumed`, `installed: false`, `applyEnabled: false`, and returns no executable actions. The module does not copy artifacts, load a staged module, run repository code, contact GitHub, invoke MCP, or call Hyper-V.

## Canonical envelope contract

The byte parser is implemented with .NET Framework types available to Windows PowerShell 5.1. It strictly decodes UTF-8 with invalid-byte exceptions before JSON parsing, rejects a BOM, detects duplicate and case-colliding object keys during parsing, rejects null, floats, control characters, surplus content, excessive depth/count/size, and then requires byte-for-byte equality with its canonical serializer. V1 strings are bounded printable ASCII to avoid Unicode normalization or confusable ambiguity.

The data shape is fixed:

```json
{"actions":[],"applyEnabled":false,"artifactSetSha256":"<64 lower hex>","artifacts":[{"destinationRelativePath":"modules/NorthGate.VMFactory.Candidate.psd1","id":"promotion-manifest","sha256":"<64 lower hex>","sizeBytes":123,"sourceRelativePath":"release/NorthGate.VMFactory.Candidate.psd1"}],"envelopeId":"<lower UUIDv4>","expiresAtUtc":"2026-08-02T15:05:00Z","installRoot":"C:\\Program Files\\NorthGate\\VMFactory","issuedAtUtc":"2026-08-02T15:00:00Z","nonce":"<43 base64url characters>","operation":"install-control-plane-candidate","repository":{"commitSha":"<40 lower hex>","id":"Beowxlf/northgate-vm-factory","treeSha":"<40 lower hex>","uri":"https://github.com/Beowxlf/northgate-vm-factory.git"},"schemaVersion":"northgate/promotion-envelope/v1","signatureAlgorithm":"RSASSA-PKCS1-v1_5-SHA256","stagingRoot":"C:\\ProgramData\\NorthGate\\VMFactory\\promotion-staging"}
```

Artifact arrays are strictly ordered by `id`; IDs, source paths, and destination paths are unique. Relative paths use `/`, contain only bounded safe segments, and resolve inside their respective fixed roots. The expected artifact list must be independently installed and ordered identically.

## Replay ledger

The ledger key is an exactly 32-byte nonzero local secret with a protected DACL. The canonical ledger authenticates its schema, fixed ledger identity, complete ordered entry list, sequence numbers, nonce digests, envelope digests, and consumption timestamps with HMAC-SHA-256. The verifier holds an exclusive file lock across read, authentication, replay detection, append, flush, and atomic replacement. A failed verification never consumes a nonce.

The ledger deliberately stores nonce digests rather than raw nonces. The HMAC detects modification but does not by itself detect replacement with an older, still-authentic ledger copy; that is a residual gate below.

## Run the local tests

From the repository root in Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\control-plane\promotion-candidate\Test-PromotionCandidate.ps1
```

The tests create a non-exportable ephemeral CurrentUser code-signing certificate and random ledger key, use them only under an ACL-restricted temporary tree, and remove the certificate and tree in `finally`. They never use an owner key, install a module, or touch NorthGate. Negative cases cover malformed UTF-8, BOM, duplicate/case-colliding keys, null, float, noncanonical and oversized JSON, bad signature/pin/boundaries, apply/actions/operation changes, expiry and lifetime, repository/commit/tree drift, root/path/artifact drift, actual file tampering/missing files, ACL widening, nonce replay, ledger MAC/key/identity tampering, and malformed or duplicate-key ledger bytes.

## Promotion and installation gates still required

This candidate must remain uninstalled until a separate privileged change supplies and verifies all of the following:

- owner-controlled signing ceremony and a real non-exportable signing key, with public-certificate pin distribution and recovery/rotation/revocation procedure;
- independent review of the exact source, test evidence, commit, tree, release hashes, and a signed real envelope;
- fixed production paths and restrictive ACLs for module, certificate, staging, state, key, ledger, lock, audit, backup, and rollback locations;
- rollback-resistant replay state, such as an independently anchored monotonic ledger head or platform-protected monotonic counter;
- an installer that never executes staged content, copies from already verified handles or re-hashes during an atomic install, and validates destination ACL/hash readback;
- Authenticode signing and allowlisting for the installed module/installer, plus version pinning and a durable protected audit event;
- backup, exact rollback, isolated canary, failure-injection, concurrent-writer, power-loss, and recovery tests;
- separate approval to promote this verifier, separate approval to install a control-plane release, and later exact host-issued plan approval for any VM operation;
- continued `applyEnabled: false` and empty executable actions until the ordinary VM Factory Phase 0 and canary gates independently pass.

The verifier reduces unsigned/moving-reference promotion risk. It does not resolve single-owner separation of duties, compromise of the signing endpoint, rollback of the authenticated ledger, post-verification artifact TOCTOU in a future installer, platform time rollback, or absence of GitHub branch protection.
