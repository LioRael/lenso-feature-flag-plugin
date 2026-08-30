#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-capability-feature-evaluation\nlenso-capability-feature-flag-admin\nlenso-feature-flag-postgres-plugin'
actual_crates="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -print0 | xargs -0 sed -n 's/^name = "\([^"]*\)"/\1/p' | LC_ALL=C sort)"
[[ "$actual_crates" == "$expected_crates" ]] || { printf 'unexpected workspace crate boundary\n%s\n' "$actual_crates" >&2; exit 1; }

if rg -n 'path\s*=\s*"(\.\./\.\./|/)' --glob Cargo.toml .; then
  echo 'cross-repository or absolute path dependency found' >&2
  exit 1
fi
if rg -n 'HostBuilder|HostLinkedModule|ModuleManifest|provider.registry|ambient.registry|Kernel.*(insert|register|mutate)' Cargo.toml crates --glob '!**/generated.rs'; then
  echo 'Kernel mutation, ambient registry, or legacy Lenso API found' >&2
  exit 1
fi
if rg -n 'HashMap|Mutex<.*Vec|memory fallback|in.memory' crates --glob '*.rs'; then
  echo 'ambient in-memory durable state found' >&2
  exit 1
fi
if rg -n 'tracing::.*(targeting|attributes|context)|println!.*(targeting|attributes|context)|dbg!' crates --glob '*.rs'; then
  echo 'sensitive evaluation context logging found' >&2
  exit 1
fi
for capability in lenso.feature-evaluation@1 lenso.feature-flag-admin@1 lenso.secrets@1 lenso.organization-membership@1 lenso.access-control@1; do
  rg -q "$capability" README.md docs crates || { echo "missing documented Capability: $capability" >&2; exit 1; }
done
