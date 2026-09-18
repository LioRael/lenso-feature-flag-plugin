#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
manifest="$root/../../../Cargo.toml"
cargo_tool="${LENSO_CARGO:-lenso-cargo}"
"$cargo_tool" rustc --locked --release --manifest-path "$manifest" --package lenso-feature-flag-workers-smoke --target wasm32-unknown-unknown -- -C link-arg=--export=__wasm_call_ctors
target_dir="$("$cargo_tool" metadata --locked --no-deps --format-version 1 --manifest-path "$manifest" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>process.stdout.write(JSON.parse(s).target_directory))')"
test "$(wasm-bindgen --version)" = 'wasm-bindgen 0.2.127'
wasm-bindgen --target web --experimental-reset-state-function --out-dir "$root/pkg" "$target_dir/wasm32-unknown-unknown/release/lenso_feature_flag_workers_smoke.wasm"
