# Release process

This repository publishes three crates, in order:

1. `lenso-capability-feature-evaluation`
2. `lenso-capability-feature-flag-admin`
3. `lenso-feature-flag-postgres-plugin`

Publication is manual-only from reviewed `main`. Pushes may refresh a
Release-plz PR, but merging it does not publish. The live workflow additionally
requires `live=true`, literal `confirm=publish`, and `main`.

Trusted Publishing cannot allocate a new crates.io name. Allocate each `0.1.0`
name once with a temporary new-package-only token, revoke it immediately, then
configure a separate Trusted Publisher for every crate:

- owner: `LioRael`
- repository: `lenso-feature-flag-plugin`
- workflow: `release-plz.yml`
- environment: unset

The live job has `id-token: write` and no registry-token fallback.

Required gates:

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen check crates/lenso-capability-feature-evaluation/capability.json --rust crates/lenso-capability-feature-evaluation/src/generated.rs
lenso-contract-codegen check crates/lenso-capability-feature-flag-admin/capability.json --rust crates/lenso-capability-feature-flag-admin/src/generated.rs
./scripts/check-repository-boundary.sh
./scripts/check-public-packages.sh
```

Run the PostgreSQL acceptance test before publication. Generated projections
are locked artifacts and must never be edited by hand.
