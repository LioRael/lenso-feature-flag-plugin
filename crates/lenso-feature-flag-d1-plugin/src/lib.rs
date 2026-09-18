//! D1 Feature Flag Plugin with explicit, event-owned primary storage.
pub mod schema;
pub mod storage;
#[cfg(target_arch = "wasm32")]
pub mod workers;
use futures::future::LocalBoxFuture;
use lenso::prelude::*;
use lenso_capability_access_control as access;
use lenso_capability_feature_evaluation as evaluation;
use lenso_capability_feature_flag_admin as admin;
use lenso_capability_organization_membership as membership;
use lenso_feature_flag_core::{FeatureFlags, PolicyConfig};
use lenso_kernel::RuntimeFailure;
use lenso_migration_d1::{Error, Statement, Transport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cell::Cell, rc::Rc};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct D1Config {
    pub binding: String,
    pub auth_issuer: String,
    pub auth_assertion_public_key: String,
    pub evaluation_callers: Vec<String>,
    pub admin_callers: Vec<String>,
    pub max_context_bytes: usize,
    pub max_attributes: usize,
    pub max_batch_size: usize,
}
impl D1Config {
    fn policy(&self) -> PolicyConfig {
        PolicyConfig {
            auth_issuer: self.auth_issuer.clone(),
            auth_assertion_public_key: self.auth_assertion_public_key.clone(),
            evaluation_callers: self.evaluation_callers.clone(),
            admin_callers: self.admin_callers.clone(),
            max_context_bytes: self.max_context_bytes,
            max_attributes: self.max_attributes,
            max_batch_size: self.max_batch_size,
        }
    }
}
fn validate_config(config: &D1Config) -> Result<(), RuntimeFailure> {
    if config.binding.is_empty()
        || config.binding.len() > 128
        || !config.binding.as_bytes()[0].is_ascii_alphabetic()
        || !config
            .binding
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid Feature Flag D1 binding name".into(),
        });
    }
    config
        .policy()
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}
/// Host-supplied primary D1 transport, valid only for its owning event.
pub trait Binding: Transport + std::fmt::Debug {}
impl<T: Transport + std::fmt::Debug> Binding for T {}
#[derive(Clone, Debug, Default)]
struct EventBinding(Option<Rc<dyn Binding>>);
impl Transport for EventBinding {
    fn batch(
        &self,
        statements: Vec<Statement>,
    ) -> LocalBoxFuture<'_, Result<Vec<Vec<Value>>, Error>> {
        Box::pin(async move {
            self.0
                .as_ref()
                .ok_or(Error::Transport)?
                .batch(statements)
                .await
        })
    }
}
#[lenso::plugin(lifecycle, configuration_schema = "configuration.schema.json", validate = validate_config)]
#[derive(Clone, Debug)]
struct D1FeatureFlagPlugin {
    #[config]
    config: D1Config,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    binding: EventBinding,
    prepared: Rc<Cell<bool>>,
}
#[lenso::provides(evaluation::FeatureEvaluation, admin::FeatureFlagAdmin)]
impl D1FeatureFlagPlugin {}
impl D1FeatureFlagPlugin {
    fn service(&self) -> FeatureFlags<storage::D1Store<EventBinding>> {
        FeatureFlags {
            config: self.config.policy(),
            membership: self.membership.clone(),
            access: self.access.clone(),
            storage: storage::D1Store(if self.prepared.get() {
                self.binding.clone()
            } else {
                EventBinding::default()
            }),
        }
    }
    async fn evaluate(
        &self,
        context: Ctx,
        request: evaluation::EvaluateRequest,
    ) -> PluginResult<evaluation::EvaluateResponse, evaluation::EvaluateError> {
        self.service().evaluate(context, request).await
    }
    async fn evaluate_batch(
        &self,
        context: Ctx,
        request: evaluation::EvaluateBatchRequest,
    ) -> PluginResult<evaluation::EvaluateBatchResponse, evaluation::EvaluateBatchError> {
        self.service().evaluate_batch(context, request).await
    }
    async fn create_flag(
        &self,
        context: Ctx,
        request: admin::CreateFlagRequest,
    ) -> PluginResult<admin::CreateFlagResponse, admin::CreateFlagError> {
        self.service().create_flag(context, request).await
    }
    async fn get_flag(
        &self,
        context: Ctx,
        request: admin::GetFlagRequest,
    ) -> PluginResult<admin::GetFlagResponse, admin::GetFlagError> {
        self.service().get_flag(context, request).await
    }
    async fn list_flags(
        &self,
        context: Ctx,
        request: admin::ListFlagsRequest,
    ) -> PluginResult<admin::ListFlagsResponse, admin::ListFlagsError> {
        self.service().list_flags(context, request).await
    }
    async fn update_flag(
        &self,
        context: Ctx,
        request: admin::UpdateFlagRequest,
    ) -> PluginResult<admin::UpdateFlagResponse, admin::UpdateFlagError> {
        self.service().update_flag(context, request).await
    }
    async fn archive_flag(
        &self,
        context: Ctx,
        request: admin::ArchiveFlagRequest,
    ) -> PluginResult<admin::ArchiveFlagResponse, admin::ArchiveFlagError> {
        self.service().archive_flag(context, request).await
    }
    async fn put_environment(
        &self,
        context: Ctx,
        request: admin::PutEnvironmentRequest,
    ) -> PluginResult<admin::PutEnvironmentResponse, admin::PutEnvironmentError> {
        self.service().put_environment(context, request).await
    }
    async fn publish_ruleset(
        &self,
        context: Ctx,
        request: admin::PublishRulesetRequest,
    ) -> PluginResult<admin::PublishRulesetResponse, admin::PublishRulesetError> {
        self.service().publish_ruleset(context, request).await
    }
    async fn list_evaluation_receipts(
        &self,
        context: Ctx,
        request: admin::ListEvaluationReceiptsRequest,
    ) -> PluginResult<admin::ListEvaluationReceiptsResponse, admin::ListEvaluationReceiptsError>
    {
        self.service()
            .list_evaluation_receipts(context, request)
            .await
    }
}
impl Lifecycle for D1FeatureFlagPlugin {
    async fn activate(&self, _context: ActivateContext) -> Result<(), RuntimeFailure> {
        schema::plan()
            .map_err(|error| migration_failure(&error))?
            .verify(&self.binding)
            .await
            .map_err(|error| migration_failure(&error))?;
        self.prepared.set(true);
        Ok(())
    }
    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.prepared.set(false);
        Ok(())
    }
}
fn migration_failure(error: &Error) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}
/// Create an event-local factory. Binding selection is exact and never ambient.
pub fn factory(
    name: impl Into<String>,
    binding: Rc<dyn Binding>,
) -> impl lenso_native_adapter::NativePluginFactory {
    D1FeatureFlagFactory {
        name: name.into(),
        binding: EventBinding(Some(binding)),
    }
}

#[derive(Clone, Debug)]
struct D1FeatureFlagFactory {
    name: String,
    binding: EventBinding,
}

impl lenso_native_adapter::NativePluginFactory for D1FeatureFlagFactory {
    fn package_id(&self) -> &'static str {
        PACKAGE_ID
    }

    fn package_version(&self) -> &'static str {
        PACKAGE_VERSION
    }

    fn instantiate(
        &self,
        context: lenso_native_adapter::NativePluginFactoryContext<'_>,
    ) -> Result<lenso_native_adapter::NativePluginInstance, RuntimeFailure> {
        let mut plugin = D1FeatureFlagPlugin::__lenso_construct(context)?;
        if plugin.config.binding != self.name {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Feature Flag factory requires its exact configured D1 binding".into(),
            });
        }
        plugin.binding = self.binding.clone();
        let lifecycle = __LensoLifecycleD1FeatureFlagPlugin {
            plugin: plugin.clone().into(),
        };
        let (evaluation_requests, evaluation_streams, evaluation_events) = evaluation::__lenso_native_endpoints_feature_evaluation!(
            plugin.clone(),
            lenso::__private
        );
        let (admin_requests, admin_streams, admin_events) =
            admin::__lenso_native_endpoints_feature_flag_admin!(plugin, lenso::__private);
        let mut requests = evaluation_requests;
        requests.extend(admin_requests);
        let mut streams = evaluation_streams;
        streams.extend(admin_streams);
        let mut events = evaluation_events;
        events.extend(admin_events);
        Ok(
            lenso_native_adapter::NativePluginInstance::with_all_endpoints(
                requests, streams, events, lifecycle,
            ),
        )
    }
}
