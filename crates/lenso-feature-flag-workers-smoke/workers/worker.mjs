import * as generated from "./pkg/lenso_feature_flag_workers_smoke.js";
import wasmModule from "./pkg/lenso_feature_flag_workers_smoke_bg.wasm";
import { createWorkersHttpHost, createEventScope } from "@lenso/workers-runtime";
import { createD1Binding } from "./binding.mjs";

export default createWorkersHttpHost({
  bindings: {
    ...generated,
    async handle_http(_input, scope) {
      const outcome = scope.mode === "setup"
        ? (await generated.migrate(scope.batch), "setup")
        : await generated.exercise(scope.batch, scope.mode, scope.id);
      return JSON.stringify({ status: 200, headers: [], body: Array.from(new TextEncoder().encode(JSON.stringify({ outcome }))), shutdown: "clean" });
    },
  },
  wasmModule,
  limits: { eventLimitMs: 30000 },
  createScope(request, env) {
    const url = new URL(request.url);
    const mode = url.searchParams.get("mode") || "success";
    const id = url.searchParams.get("id") || mode;
    return createEventScope((resources) => ({
      mode,
      id,
      batch: mode === "throws"
        ? () => { throw new Error("synthetic-private-data"); }
        : mode === "malformed"
          ? async () => JSON.stringify([{ success: false, results: [] }])
          : createD1Binding(mode === "missing-schema" ? env.EMPTY : env.FEATURES, resources),
    }));
  },
});
