# Lenso Feature Flag Plugin

A removable, PostgreSQL-backed Feature Flag backend for Lenso Apps. It owns
typed flags, environments, immutable published rulesets, deterministic
evaluation, and durable evaluation receipts. It does not mutate the Kernel,
discover Providers through an ambient registry, or own Organizations,
identities, membership, or Access Control policy.

## Capabilities

The linked native Rust Plugin provides:

- `lenso.feature-evaluation@1`: evaluate one flag or an atomic bounded batch.
- `lenso.feature-flag-admin@1`: create/get/list/update/archive flags, put
  environments, publish rulesets, and list evaluation receipts.

It requires exactly one Provider for each of `lenso.secrets@1`,
`lenso.organization-membership@1`, and `lenso.access-control@1`.

Every request requires an exact configured caller, an Auth Actor Assertion
audienced to the exact Capability operation, live Organization membership, and
an independent Access Control decision. Permissions are
`feature-flags.evaluate` and `feature-flags.admin`.

## Evaluation contract

Flags have one immutable type: `boolean`, `string`, `integer`, `double`, or
`json`. Every ruleset variant must contain exactly one value of that type.
Published rulesets contain ordered targeting rules, a basis-point rollout, and
a required fallthrough variant. Evaluation checks targeting rules first, then
uses a stable SHA-256 bucket in `[0, 10000)`, and finally falls through.

The bucket input is the length-independent tuple
`organization_id`, `environment_key`, `flag_key`, and `targeting_key`, separated
by zero bytes. Fixed vectors in the unit suite lock this algorithm. Publishing
a ruleset advances both the flag and environment CAS revisions; old rulesets
remain immutable audit evidence.

Evaluation context is explicitly bounded by configuration. Generated request
types redact targeting keys and attributes from `Debug`. The Plugin stores only
a SHA-256 context hash in receipts and never logs raw context values. Receipts
include the chosen variant, reason, ruleset revision, and evaluation time, but
not flag values or caller attributes.

## Consistency and lifecycle

- Mutations and evaluations use caller/actor/operation-scoped idempotency keys.
- Flags and environments use positive decimal CAS revisions.
- Batch evaluation is admitted and committed atomically.
- `FeatureFlagOperator::setup/upgrade` owns DDL. Runtime activation resolves the
  database URL and verifies the exact migration ledger.
- PostgreSQL is the sole durable state; there is no memory fallback.

## Verification

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --locked --workspace --all-targets --all-features
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --locked --workspace --all-features
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
./scripts/check-repository-boundary.sh
LENSO_PACKAGE_ALLOW_DIRTY=1 ./scripts/check-public-packages.sh
```

Set `LENSO_FEATURE_FLAG_TEST_DATABASE_URL` to a dedicated PostgreSQL database
whose name starts with `lenso_feature_flag_test` to run the real
restart/idempotency/CAS/ruleset/evaluation/receipt acceptance slice.

## Honest v1 limits

There is no remote SDK transport, streaming update channel, multi-variate
experiment statistics, scheduled ruleset activation, or provider-specific
registry. Evaluation is local to the linked Plugin and one PostgreSQL store.
