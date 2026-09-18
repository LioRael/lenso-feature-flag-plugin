//! PostgreSQL-backed typed Feature Flag evaluation and administration.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use lenso::prelude::*;
#[cfg(test)]
use lenso_auth_sdk::ActorAssertionVerifier;
use lenso_capability_access_control as access;
use lenso_capability_feature_evaluation as evaluation;
use lenso_capability_feature_flag_admin as admin;
use lenso_capability_organization_membership as membership;
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
pub use operator::{FeatureFlagOperator, FeatureFlagOperatorError};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, fmt, rc::Rc, time::Duration};
use thiserror::Error;
use zeroize::Zeroizing;

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureFlagConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    evaluation_callers: Vec<String>,
    admin_callers: Vec<String>,
    max_context_bytes: usize,
    max_attributes: usize,
    max_batch_size: usize,
}

impl FeatureFlagConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        evaluation_callers: Vec<String>,
        admin_callers: Vec<String>,
        max_context_bytes: usize,
        max_attributes: usize,
        max_batch_size: usize,
    ) -> Result<Self, FeatureFlagConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            evaluation_callers,
            admin_callers,
            max_context_bytes,
            max_attributes,
            max_batch_size,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), FeatureFlagConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| FeatureFlagConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(FeatureFlagConfigError::InvalidSecretReference);
        }
        self.policy().validate().map_err(|error| match error {
            lenso_feature_flag_core::FeatureFlagConfigError::InvalidAuthIssuer => {
                FeatureFlagConfigError::InvalidAuthIssuer
            }
            lenso_feature_flag_core::FeatureFlagConfigError::InvalidAuthPublicKey => {
                FeatureFlagConfigError::InvalidAuthPublicKey
            }
            lenso_feature_flag_core::FeatureFlagConfigError::InvalidEvaluationCallers => {
                FeatureFlagConfigError::InvalidEvaluationCallers
            }
            lenso_feature_flag_core::FeatureFlagConfigError::InvalidAdminCallers => {
                FeatureFlagConfigError::InvalidAdminCallers
            }
            lenso_feature_flag_core::FeatureFlagConfigError::InvalidBounds => {
                FeatureFlagConfigError::InvalidBounds
            }
        })
    }
    fn policy(&self) -> lenso_feature_flag_core::PolicyConfig {
        lenso_feature_flag_core::PolicyConfig {
            auth_issuer: self.auth_issuer.clone(),
            auth_assertion_public_key: self.auth_assertion_public_key.clone(),
            evaluation_callers: self.evaluation_callers.clone(),
            admin_callers: self.admin_callers.clone(),
            max_context_bytes: self.max_context_bytes,
            max_attributes: self.max_attributes,
            max_batch_size: self.max_batch_size,
        }
    }
    #[cfg(test)]
    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Feature Flag Auth verification key is invalid".to_owned(),
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FeatureFlagConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("evaluation_callers must contain unique exact Instance keys")]
    InvalidEvaluationCallers,
    #[error("admin_callers must contain unique exact Instance keys")]
    InvalidAdminCallers,
    #[error("invalid context, attribute, or batch bound")]
    InvalidBounds,
}

fn validate_config(config: &FeatureFlagConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Feature Flag configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedFeatureFlags {
    postgres: OwnedPostgres,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct FeatureFlagPlugin {
    #[config]
    config: FeatureFlagConfig,
    secrets: Port<secrets::SecretsClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    prepared: Rc<RefCell<Option<PreparedFeatureFlags>>>,
}

impl fmt::Debug for FeatureFlagPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeatureFlagPlugin")
            .field("schema", &self.config.schema)
            .field("prepared", &self.prepared.borrow().is_some())
            .field(
                "evaluation_caller_count",
                &self.config.evaluation_callers.len(),
            )
            .field("admin_caller_count", &self.config.admin_callers.len())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(evaluation::FeatureEvaluation, admin::FeatureFlagAdmin)]
impl FeatureFlagPlugin {}

impl FeatureFlagPlugin {
    fn service(&self) -> lenso_feature_flag_core::FeatureFlags<storage::PostgresStore> {
        lenso_feature_flag_core::FeatureFlags {
            config: self.config.policy(),
            membership: self.membership.clone(),
            access: self.access.clone(),
            storage: storage::PostgresStore(
                self.prepared
                    .borrow()
                    .as_ref()
                    .map(|value| value.postgres.clone()),
            ),
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
impl Lifecycle for FeatureFlagPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedFeatureFlags { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|value| Zeroizing::new(value.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: "Feature Flag database secret was rejected".to_owned(),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn valid_secret_reference(value: &str) -> bool {
    valid_id(value)
        || (!value.is_empty()
            && value.len() <= 256
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains("//")
            && value.split('/').all(|part| part != "." && part != "..")
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/')
            }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{DomainFailure, StorageError};
    use lenso_auth_sdk::{ActorAssertion, ActorProjectionError, AssertionClock, TypedActor};
    use std::collections::BTreeSet;
    use time::OffsetDateTime;
    #[derive(Clone, Debug)]
    struct FeatureActor {
        subject: String,
    }
    impl TypedActor for FeatureActor {
        fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
            Ok(Self {
                subject: assertion.subject().to_owned(),
            })
        }
    }
    #[derive(Clone, Copy, Debug)]
    struct UtcClock;
    impl AssertionClock for UtcClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::now_utc()
        }
    }

    use lenso_auth_sdk::{ActorAssertionIssuer, Validity, audience};
    use lenso_kernel::{CancellationToken, InvocationContext};
    use lenso_native_adapter::NativePluginRegistry;
    use time::Duration as TimeDuration;

    fn config() -> FeatureFlagConfig {
        let issuer =
            lenso_auth_sdk::ActorAssertionIssuer::new("auth.users", b"feature-flag-test-key");
        FeatureFlagConfig::new(
            "feature_flags",
            "feature-flags/database-url",
            "auth.users",
            issuer.public_key_base64(),
            vec!["feature-api".to_owned()],
            vec!["feature-admin".to_owned()],
            16_384,
            32,
            50,
        )
        .unwrap()
    }

    fn plugin() -> FeatureFlagPlugin {
        FeatureFlagPlugin {
            config: config(),
            secrets: Port::default(),
            membership: Port::default(),
            access: Port::default(),
            prepared: Rc::new(RefCell::new(None)),
        }
    }

    fn context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller)
    }

    #[test]
    fn descriptor_declares_only_two_roles_and_three_dependencies() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            provided,
            BTreeSet::from([evaluation::CAPABILITY_ID, admin::CAPABILITY_ID])
        );
        let required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            required,
            BTreeSet::from([
                secrets::CAPABILITY_ID,
                membership::CAPABILITY_ID,
                access::CAPABILITY_ID
            ])
        );
        assert_eq!(
            NativePluginRegistry::new()
                .with_linked_factories()
                .factories()
                .filter(|factory| factory.package_id() == PACKAGE_ID)
                .count(),
            1
        );
    }

    #[test]
    fn evaluation_context_debug_is_redacted() {
        let context = evaluation::EvaluateRequestContext {
            targeting_key: "customer@example.test".to_owned(),
            attributes: std::collections::BTreeMap::from([(
                "email".to_owned(),
                serde_json::json!("customer@example.test"),
            )]),
        };
        let request = evaluation::EvaluateRequest {
            evaluation_id: "eval-1".to_owned(),
            organization_id: "org".to_owned(),
            environment_key: "production".to_owned(),
            flag_key: "checkout".to_owned(),
            context,
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("customer@example.test"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn untrusted_caller_fails_before_context_or_storage() {
        let result = futures::executor::block_on(plugin().evaluate(
            context("unknown"),
            evaluation::EvaluateRequest {
                evaluation_id: "eval-1".to_owned(),
                organization_id: "org".to_owned(),
                environment_key: "prod".to_owned(),
                flag_key: "checkout".to_owned(),
                context: evaluation::EvaluateRequestContext {
                    targeting_key: "usr".to_owned(),
                    attributes: std::collections::BTreeMap::default(),
                },
            },
        ));
        assert_eq!(
            result,
            Err(PluginError::Domain(evaluation::EvaluateError::Forbidden))
        );
    }

    #[test]
    fn deterministic_bucketing_has_fixed_vectors() {
        assert_eq!(
            storage::deterministic_bucket("org", "prod", "checkout", "user-1"),
            9_205
        );
        assert_eq!(
            storage::deterministic_bucket("org", "prod", "checkout", "user-2"),
            4_341
        );
        assert_eq!(
            storage::deterministic_bucket("other", "staging", "search", "actor"),
            1_413
        );
    }

    #[test]
    fn actor_assertion_is_bound_to_exact_operation() {
        let issuer = ActorAssertionIssuer::new("auth.users", b"feature-flag-test-key");
        let now = OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            "usr_1",
            "user",
            "strong",
            [audience(
                evaluation::CAPABILITY_ID,
                evaluation::EVALUATE_OPERATION,
            )],
            Validity::new(
                now - TimeDuration::seconds(1),
                now + TimeDuration::minutes(1),
            )
            .unwrap(),
            std::collections::BTreeMap::default(),
        );
        let context = assertion.attach(context("feature-api")).unwrap();
        let actor = config()
            .verifier()
            .unwrap()
            .project_context::<FeatureActor>(
                &context,
                evaluation::CAPABILITY_ID,
                evaluation::EVALUATE_OPERATION,
                &UtcClock,
            )
            .unwrap();
        assert_eq!(actor.subject, "usr_1");
        assert!(
            config()
                .verifier()
                .unwrap()
                .project_context::<FeatureActor>(
                    &context,
                    evaluation::CAPABILITY_ID,
                    evaluation::EVALUATE_BATCH_OPERATION,
                    &UtcClock,
                )
                .is_err()
        );
    }

    #[test]
    fn typed_ruleset_rejects_mismatched_values() {
        let definition = storage::RulesetDefinition {
            variants: vec![storage::VariantRecord {
                variant_key: "on".to_owned(),
                value: storage::ValueRecord {
                    value_type: "string".to_owned(),
                    boolean_value: None,
                    string_value: Some("yes".to_owned()),
                    integer_value: None,
                    double_value: None,
                    json_value: None,
                },
            }],
            targeting_rules: Vec::new(),
            percentage_rollout: Vec::new(),
            fallthrough_variant: "on".to_owned(),
        };
        assert!(matches!(
            storage::validate_ruleset("boolean", &definition),
            Err(StorageError::Domain(DomainFailure::TypeMismatch))
        ));
    }
}
