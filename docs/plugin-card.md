# Feature Flag v1 Plugin card

## Outcome and deletion boundary

Product teams can publish typed, environment-specific flag rules and obtain
reproducible evaluations with durable receipts. Removing the Plugin Instance,
its bindings, and its owned schema removes all flag behavior without changing
the Kernel, Organization membership, or Access Control policy.

## Owned facts

The Plugin owns typed flag definitions, environments, immutable rulesets, CAS
revisions, command receipts, and evaluation receipts. It owns no user profile,
Organization, entitlement, experiment analysis, or application deployment
fact.

## Roles and authority

`lenso.feature-evaluation@1` owns bounded evaluation and batch evaluation.
`lenso.feature-flag-admin@1` owns flag, environment, ruleset, and receipt
administration. Both require exact caller allowlists, exact-operation Auth
assertions, active Organization membership, and Access Control. The target
remains final authority over type invariants, revisions, archival, and
idempotency.

## Evaluation and privacy semantics

Target rules are ordered, rollouts use stable basis-point buckets, and a
fallthrough variant is mandatory. The SHA-256 bucket algorithm is locked by
fixed vectors. Sensitive evaluation context is bounded, generated request
`Debug` output is redacted, and only a one-way context hash is retained. The
Plugin never writes context values to logs or receipts.

## Lifecycle and removal

Operator setup/upgrade owns migrations. Activation verifies the ledger and
opens a fresh generation-local pool; deactivation closes it. There are no
background tasks, Kernel mutations, or ambient Provider registries.
