# MCP create-only candidate

This directory records the boundary for a future NorthGate MCP create-only fleet sidecar. It is not an installed release and must not be executed from a repository checkout. Live source snapshots and environment-specific mappings are intentionally excluded; generated release artifacts, signatures, host policy, installation evidence, and rollback packages remain separate promotion units.

Until the candidate passes its focused negative tests and the privileged release workflow, the installed MCP remains unchanged and VM Factory apply remains disabled.
