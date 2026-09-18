// Event-owned D1 transport. Every statement is sent to the primary binding in
// one atomic batch; no exception text crosses the Plugin boundary.
export function createD1Binding(database, resources) {
  if (!database || typeof database.batch !== "function")
    throw new Error("missing_d1_binding");
  return (input) => resources.run(() => {
    const statements = JSON.parse(input);
    if (!Array.isArray(statements) || statements.length === 0 || statements.length > 128 || statements.some((s) => typeof s.sql !== "string" || !Array.isArray(s.params) || s.params.length > 100))
      throw new Error("invalid_batch");
    return database.batch(statements.map(({ sql, params }) => database.prepare(sql).bind(...params)));
  }, (result) => {
    if (!Array.isArray(result) || result.some((r) => !r.success || !Array.isArray(r.results)))
      throw new Error("invalid_receipt");
    return JSON.stringify(result.map(({ success, results }) => ({ success, results })));
  });
}
