//! Workers wire adapter; exception contents never become diagnostics.
use futures::future::LocalBoxFuture;
use lenso_migration_d1::{Error, Statement, Transport};
use serde_json::Value;
use std::{fmt, rc::Rc};
use wasm_bindgen::JsValue;

#[derive(Clone)]
pub struct D1Binding(pub js_sys::Function);

impl fmt::Debug for D1Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("D1Binding(redacted)")
    }
}

impl Transport for D1Binding {
    fn batch(
        &self,
        statements: Vec<Statement>,
    ) -> LocalBoxFuture<'_, Result<Vec<Vec<Value>>, Error>> {
        Box::pin(async move {
            let count = statements.len();
            if count == 0 || count > 128 || statements.iter().any(|s| s.params.len() > 100) {
                return Err(Error::Capacity);
            }
            let json = serde_json::to_string(&statements).map_err(|_| Error::Transport)?;
            let result = self
                .0
                .call1(&JsValue::UNDEFINED, &JsValue::from_str(&json))
                .map_err(|_| Error::Transport)?;
            let value = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&result))
                .await
                .map_err(|_| Error::Transport)?;
            let receipts: Vec<Receipt> =
                serde_json::from_str(&value.as_string().ok_or(Error::Transport)?)
                    .map_err(|_| Error::Transport)?;
            if receipts.len() != count || receipts.iter().any(|receipt| !receipt.success) {
                return Err(Error::Transport);
            }
            Ok(receipts
                .into_iter()
                .map(|receipt| receipt.results)
                .collect())
        })
    }
}

/// Supply the callback from `workers/binding.mjs`, owned by this event.
pub fn factory(
    name: impl Into<String>,
    batch: js_sys::Function,
) -> impl lenso_native_adapter::NativePluginFactory {
    super::factory(name, Rc::new(D1Binding(batch)))
}

#[derive(serde::Deserialize)]
struct Receipt {
    success: bool,
    results: Vec<Value>,
}
