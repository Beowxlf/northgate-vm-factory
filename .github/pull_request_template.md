## What changed

Describe the exact desired-state, policy, architecture, or documentation change.

## Why

State the operational or security outcome and affected asset IDs.

## Safety review

- [ ] No credentials, tokens, private keys, generated secrets, or live state were added.
- [ ] No raw command, path, URL, switch name, or implicit deletion entered a VM manifest.
- [ ] Merge approval is not being treated as deployment approval.
- [ ] The final deployment plan will be generated after merge and authorized by a host-issued plan ID/hash.
- [ ] Catalog/policy and privileged-code releases are not being promoted with the first VM change that consumes them.
- [ ] Rollback or quarantine behavior is defined for deployment-affecting changes.
- [ ] Operation-SeeSaw updates are identified.

## Validation

Record the checks run and their results.
