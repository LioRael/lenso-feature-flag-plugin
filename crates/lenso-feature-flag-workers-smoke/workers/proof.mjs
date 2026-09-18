import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const owner = createRequire(require.resolve("wrangler/package.json"));
const { build } = owner("esbuild");
const { Miniflare } = owner("miniflare");
const root = fileURLToPath(new URL(".", import.meta.url));
const output = `${root}proof.bundle.mjs`;
await build({
  entryPoints: [`${root}worker.mjs`], outfile: output, bundle: true, format: "esm", platform: "browser", target: "es2022",
  plugins: [{ name: "wasm", setup(b) { b.onResolve({ filter: /\.wasm$/ }, (args) => ({ path: args.path, external: true })); } }],
});
const mf = new Miniflare({ modules: true, scriptPath: output, modulesRoot: root, modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }], compatibilityDate: "2026-07-08", d1Databases: ["FEATURES", "EMPTY"] });
let passed = 0;
async function run(mode, id = mode) {
  const response = await mf.dispatchFetch(`http://local/?mode=${mode}&id=${id}`);
  const body = await response.text();
  assert.equal(response.status, 200, `${mode}: ${body}`);
  assert(!body.includes("synthetic-private-data"));
  passed++;
  return JSON.parse(body).outcome;
}
try {
  assert.equal(await run("setup"), "setup");
  assert.equal(await run("success", "fixture"), "passed");
  assert.equal(await run("replay", "fixture"), "passed");
  for (const mode of ["forbidden", "missing-schema", "wrong-binding", "throws", "malformed"]) {
    assert.equal(await run(mode), ["missing-schema", "wrong-binding", "throws", "malformed"].includes(mode) ? "startup-rejected" : "passed");
  }
  const wasm = await readFile(`${root}pkg/lenso_feature_flag_workers_smoke_bg.wasm`);
  console.log(JSON.stringify({ passed, runtime: "workerd", workers_runtime: "0.1.2", wasm_sha256: createHash("sha256").update(wasm).digest("hex") }, null, 2));
} finally {
  await mf.dispose();
  await rm(output, { force: true });
}
