# Disposable canary execution-stage proposal

## Decision

Represent the bootstrap escape path as a separate, non-operative `CanaryExecutionStageProposal`. This record describes the only shape a future canary-only stage may take without relaxing the normal VM policy.

The proposal does not authorize a Hyper-V change:

- `policy/resource-limits.json` remains `status: proposed`, `applyEnabled: false`, with an empty `executableActions` list.
- The proposal's own `effectiveState` also fixes apply to false and effective actions to an empty list.
- Its schema accepts only `kind: CanaryExecutionStageProposal`; that kind is not an activation record or an apply capability.
- No `DisposableCanaryRequest` schema or request exists in this repository, and standard `VirtualMachine` manifests are explicitly outside the proposed stage.

## Canary-only boundary

The proposed future stage is limited to one `Create` plan for one separately typed `DisposableCanaryRequest`. It cannot consume a normal `VirtualMachine` manifest, admit more than one concurrent canary, perform update, replace, decommission, or purge actions, or share promotion with its first request.

Activation requires a separate reviewed change after the installed canary policy, control-plane negative tests, immutable image, opaque profiles, identity-ledger reservation, quarantine route, and receipt path are independently ready. Each canary still requires a fresh host-issued plan and separate human approval of that exact plan capability. Repository merge or this proposal alone is never sufficient.

## Promotion sequence

1. Review and merge this non-operative proposal as policy design only.
2. Complete and record every control-plane and recovery prerequisite outside the routine repository data path.
3. Promote a signed installed canary-policy release through the privileged control-plane process.
4. Add the dedicated disposable-canary request contract in a later, separate review; do not use a standard workload manifest.
5. Submit one exact disposable-canary request in another review after the contract and installed policy are promoted.
6. Generate and register a fresh post-merge plan, approve its exact host-issued ID and hash, execute through the canary-only application identity, then verify and quarantine or retire the canary through its separate lifecycle workflow.

Until all six steps complete, both normal apply and canary apply remain disabled.
