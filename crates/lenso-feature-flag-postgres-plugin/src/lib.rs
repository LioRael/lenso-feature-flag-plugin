//! PostgreSQL-backed typed Feature Flag evaluation and administration.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_feature_evaluation as evaluation;
use lenso_capability_feature_flag_admin as admin;
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::storage::{DomainFailure, StorageError};

pub use operator::{FeatureFlagOperator, FeatureFlagOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_ID_BYTES: usize = 512;
const MAX_VARIANTS: usize = 32;
const MAX_TARGETING_RULES: usize = 100;
const MAX_COMPARISON_VALUES: usize = 32;

const FEATURE_EVALUATE: &str = "feature-flags.evaluate";
const FEATURE_ADMIN: &str = "feature-flags.admin";

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
        if !valid_id(&self.auth_issuer) {
            return Err(FeatureFlagConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| FeatureFlagConfigError::InvalidAuthPublicKey)?;
        if !valid_callers(&self.evaluation_callers) {
            return Err(FeatureFlagConfigError::InvalidEvaluationCallers);
        }
        if !valid_callers(&self.admin_callers) {
            return Err(FeatureFlagConfigError::InvalidAdminCallers);
        }
        if !(256..=65_536).contains(&self.max_context_bytes)
            || !(1..=64).contains(&self.max_attributes)
            || !(1..=100).contains(&self.max_batch_size)
        {
            return Err(FeatureFlagConfigError::InvalidBounds);
        }
        Ok(())
    }

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

#[derive(Clone, Debug)]
struct Authorized {
    caller: String,
    actor: String,
}

#[derive(Debug)]
enum AuthorizationFailure {
    Unauthenticated,
    Forbidden,
    Runtime(RuntimeFailure),
}

macro_rules! auth_evaluation {
    ($result:expr,$kind:ident) => {
        match $result {
            Ok(value) => value,
            Err(AuthorizationFailure::Unauthenticated) => {
                return Err(PluginError::domain(evaluation::$kind::Unauthenticated))
            }
            Err(AuthorizationFailure::Forbidden) => {
                return Err(PluginError::domain(evaluation::$kind::Forbidden))
            }
            Err(AuthorizationFailure::Runtime(error)) => return Err(PluginError::runtime(error)),
        }
    };
}

macro_rules! auth_admin {
    ($result:expr,$kind:ident) => {
        match $result {
            Ok(value) => value,
            Err(AuthorizationFailure::Unauthenticated) => {
                return Err(PluginError::domain(admin::$kind::Unauthenticated))
            }
            Err(AuthorizationFailure::Forbidden) => {
                return Err(PluginError::domain(admin::$kind::Forbidden))
            }
            Err(AuthorizationFailure::Runtime(error)) => return Err(PluginError::runtime(error)),
        }
    };
}

macro_rules! evaluation_error {
    ($failure:expr,$kind:ident) => {
        match $failure {
            DomainFailure::FlagNotFound => evaluation::$kind::FlagNotFound,
            DomainFailure::EnvironmentNotFound => evaluation::$kind::EnvironmentNotFound,
            DomainFailure::NoPublishedRuleset => evaluation::$kind::NoPublishedRuleset,
            DomainFailure::Archived => evaluation::$kind::Archived,
            DomainFailure::TypeMismatch => evaluation::$kind::TypeMismatch,
            DomainFailure::IdempotencyConflict => evaluation::$kind::IdempotencyConflict,
            DomainFailure::OperationInProgress => evaluation::$kind::OperationInProgress,
            _ => evaluation::$kind::InvalidRequest,
        }
    };
}

macro_rules! admin_error {
    ($failure:expr,$kind:ident) => {
        match $failure {
            DomainFailure::NotFound
            | DomainFailure::FlagNotFound
            | DomainFailure::EnvironmentNotFound => admin::$kind::NotFound,
            DomainFailure::Archived => admin::$kind::Archived,
            DomainFailure::RevisionConflict => admin::$kind::RevisionConflict,
            DomainFailure::IdempotencyConflict => admin::$kind::IdempotencyConflict,
            DomainFailure::OperationInProgress => admin::$kind::OperationInProgress,
            DomainFailure::AlreadyExists => admin::$kind::AlreadyExists,
            DomainFailure::TypeMismatch => admin::$kind::TypeMismatch,
            DomainFailure::InvalidRuleset => admin::$kind::InvalidRuleset,
            _ => admin::$kind::InvalidRequest,
        }
    };
}

impl FeatureFlagPlugin {
    fn prepared(&self) -> Result<PreparedFeatureFlags, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Feature Flag Plugin is not prepared".to_owned(),
            })
    }

    async fn authorize(
        &self,
        context: &Ctx,
        callers: &[String],
        capability: &str,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<Authorized, AuthorizationFailure> {
        let caller = context
            .caller_instance()
            .filter(|caller| callers.iter().any(|allowed| allowed == *caller))
            .map(ToOwned::to_owned)
            .ok_or(AuthorizationFailure::Forbidden)?;
        let actor = self
            .config
            .verifier()
            .map_err(AuthorizationFailure::Runtime)?
            .project_context::<FeatureActor>(context, capability, operation, &UtcClock)
            .map_err(|_| AuthorizationFailure::Unauthenticated)?
            .subject;
        if !valid_opaque_id(organization_id) || !valid_opaque_id(&actor) {
            return Err(AuthorizationFailure::Forbidden);
        }
        let membership = self
            .membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: actor.clone(),
                },
            )
            .await
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Runtime(error) => {
                    AuthorizationFailure::Runtime(error)
                }
                OrganizationMembershipInvocationError::Domain(_) => {
                    AuthorizationFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: membership::CAPABILITY_ID,
                    })
                }
            })?;
        if !membership.active {
            return Err(AuthorizationFailure::Forbidden);
        }
        let decision = self
            .access
            .check_permission_with_context(
                context.clone(),
                CheckPermissionRequest {
                    subject: actor.clone(),
                    scope: CheckPermissionRequestScope {
                        kind: "organization".to_owned(),
                        id: organization_id.to_owned(),
                    },
                    permission: permission.to_owned(),
                },
            )
            .await
            .map_err(|error| match error {
                AccessControlInvocationError::Runtime(error) => {
                    AuthorizationFailure::Runtime(error)
                }
                AccessControlInvocationError::Domain(_) => {
                    AuthorizationFailure::Runtime(RuntimeFailure::ProtocolViolation {
                        capability: access::CAPABILITY_ID,
                    })
                }
            })?;
        if !decision.allowed {
            return Err(AuthorizationFailure::Forbidden);
        }
        Ok(Authorized { caller, actor })
    }

    async fn evaluate(
        &self,
        context: Ctx,
        request: evaluation::EvaluateRequest,
    ) -> PluginResult<evaluation::EvaluateResponse, evaluation::EvaluateError> {
        let auth = auth_evaluation!(
            self.authorize(
                &context,
                &self.config.evaluation_callers,
                evaluation::CAPABILITY_ID,
                evaluation::EVALUATE_OPERATION,
                &request.organization_id,
                FEATURE_EVALUATE
            )
            .await,
            EvaluateError
        );
        if !valid_key(&request.evaluation_id, 200)
            || !valid_key(&request.environment_key, 128)
            || !valid_key(&request.flag_key, 128)
            || !self.valid_context(&request.context.targeting_key, &request.context.attributes)
        {
            return Err(PluginError::domain(
                evaluation::EvaluateError::InvalidRequest,
            ));
        }
        let hash = request_hash(&request)?;
        let context_hash = context_hash(&request.context)?;
        let record = map_storage(
            storage::evaluate(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.evaluation_id, &hash),
                &request.organization_id,
                &request.environment_key,
                &request.flag_key,
                &request.context.targeting_key,
                &request.context.attributes,
                &context_hash,
            )
            .await,
            |failure| evaluation_error!(failure, EvaluateError),
        )?;
        wire_cast(&record)
    }

    async fn evaluate_batch(
        &self,
        context: Ctx,
        request: evaluation::EvaluateBatchRequest,
    ) -> PluginResult<evaluation::EvaluateBatchResponse, evaluation::EvaluateBatchError> {
        let auth = auth_evaluation!(
            self.authorize(
                &context,
                &self.config.evaluation_callers,
                evaluation::CAPABILITY_ID,
                evaluation::EVALUATE_BATCH_OPERATION,
                &request.organization_id,
                FEATURE_EVALUATE
            )
            .await,
            EvaluateBatchError
        );
        let unique = request.flag_keys.iter().collect::<BTreeSet<_>>();
        if !valid_key(&request.batch_id, 200)
            || !valid_key(&request.environment_key, 128)
            || request.flag_keys.is_empty()
            || request.flag_keys.len() > self.config.max_batch_size
            || unique.len() != request.flag_keys.len()
            || request.flag_keys.iter().any(|flag| !valid_key(flag, 128))
            || !self.valid_context(&request.context.targeting_key, &request.context.attributes)
        {
            return Err(PluginError::domain(
                evaluation::EvaluateBatchError::InvalidRequest,
            ));
        }
        let hash = request_hash(&request)?;
        let context_hash = context_hash(&request.context)?;
        let records = map_storage(
            storage::evaluate_batch(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.batch_id, &hash),
                &request.organization_id,
                &request.environment_key,
                &request.flag_keys,
                &request.context.targeting_key,
                &request.context.attributes,
                &context_hash,
            )
            .await,
            |failure| evaluation_error!(failure, EvaluateBatchError),
        )?;
        let results = records
            .iter()
            .map(wire_cast)
            .collect::<PluginResult<Vec<evaluation::EvaluateBatchResponseResultsItem>, _>>()?;
        Ok(evaluation::EvaluateBatchResponse { results })
    }

    async fn create_flag(
        &self,
        context: Ctx,
        request: admin::CreateFlagRequest,
    ) -> PluginResult<admin::CreateFlagResponse, admin::CreateFlagError> {
        let auth = auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::CREATE_FLAG_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            CreateFlagError
        );
        if !valid_key(&request.idempotency_key, 200)
            || !valid_key(&request.flag_key, 128)
            || !valid_text(&request.name, 240)
            || !valid_optional_text(request.description.as_deref(), 4_000)
        {
            return Err(PluginError::domain(admin::CreateFlagError::InvalidRequest));
        }
        let hash = request_hash(&request)?;
        let value_type = enum_string(&request.value_type)?;
        let record = map_storage(
            storage::create_flag(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.idempotency_key, &hash),
                &request.organization_id,
                &request.flag_key,
                &request.name,
                request.description.as_deref(),
                &value_type,
            )
            .await,
            |failure| admin_error!(failure, CreateFlagError),
        )?;
        wire_cast(&record)
    }

    async fn get_flag(
        &self,
        context: Ctx,
        request: admin::GetFlagRequest,
    ) -> PluginResult<admin::GetFlagResponse, admin::GetFlagError> {
        auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::GET_FLAG_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            GetFlagError
        );
        if !valid_key(&request.flag_key, 128) {
            return Err(PluginError::domain(admin::GetFlagError::InvalidRequest));
        }
        let record = map_storage(
            storage::get_flag(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                &request.organization_id,
                &request.flag_key,
            )
            .await,
            |failure| admin_error!(failure, GetFlagError),
        )?;
        wire_cast(&record)
    }

    async fn list_flags(
        &self,
        context: Ctx,
        request: admin::ListFlagsRequest,
    ) -> PluginResult<admin::ListFlagsResponse, admin::ListFlagsError> {
        auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::LIST_FLAGS_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            ListFlagsError
        );
        let after = parse_cursor(request.after.as_deref())
            .map_err(|()| PluginError::domain(admin::ListFlagsError::InvalidRequest))?;
        if !(1..=200).contains(&request.limit) {
            return Err(PluginError::domain(admin::ListFlagsError::InvalidRequest));
        }
        let mut records = map_storage(
            storage::list_flags(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                &request.organization_id,
                request.include_archived,
                after,
                request.limit + 1,
            )
            .await,
            |failure| admin_error!(failure, ListFlagsError),
        )?;
        let has_more = records.len() > usize::try_from(request.limit).unwrap_or(0);
        if has_more {
            records.pop();
        }
        let next_cursor = has_more
            .then(|| records.last().map(|record| record.row_seq.to_string()))
            .flatten();
        let flags = records
            .iter()
            .map(wire_cast)
            .collect::<PluginResult<Vec<admin::ListFlagsResponseFlagsItem>, _>>()?;
        Ok(admin::ListFlagsResponse { flags, next_cursor })
    }

    async fn update_flag(
        &self,
        context: Ctx,
        request: admin::UpdateFlagRequest,
    ) -> PluginResult<admin::UpdateFlagResponse, admin::UpdateFlagError> {
        let auth = auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::UPDATE_FLAG_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            UpdateFlagError
        );
        let revision = valid_mutation(
            &request.idempotency_key,
            &request.flag_key,
            &request.expected_revision,
        )
        .ok_or_else(|| PluginError::domain(admin::UpdateFlagError::InvalidRequest))?;
        if !valid_text(&request.name, 240)
            || !valid_optional_text(request.description.as_deref(), 4_000)
        {
            return Err(PluginError::domain(admin::UpdateFlagError::InvalidRequest));
        }
        let hash = request_hash(&request)?;
        let record = map_storage(
            storage::update_flag(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.idempotency_key, &hash),
                &request.organization_id,
                &request.flag_key,
                revision,
                &request.name,
                request.description.as_deref(),
            )
            .await,
            |failure| admin_error!(failure, UpdateFlagError),
        )?;
        wire_cast(&record)
    }

    async fn archive_flag(
        &self,
        context: Ctx,
        request: admin::ArchiveFlagRequest,
    ) -> PluginResult<admin::ArchiveFlagResponse, admin::ArchiveFlagError> {
        let auth = auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::ARCHIVE_FLAG_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            ArchiveFlagError
        );
        let revision = valid_mutation(
            &request.idempotency_key,
            &request.flag_key,
            &request.expected_revision,
        )
        .ok_or_else(|| PluginError::domain(admin::ArchiveFlagError::InvalidRequest))?;
        let hash = request_hash(&request)?;
        let record = map_storage(
            storage::archive_flag(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.idempotency_key, &hash),
                &request.organization_id,
                &request.flag_key,
                revision,
            )
            .await,
            |failure| admin_error!(failure, ArchiveFlagError),
        )?;
        wire_cast(&record)
    }

    async fn put_environment(
        &self,
        context: Ctx,
        request: admin::PutEnvironmentRequest,
    ) -> PluginResult<admin::PutEnvironmentResponse, admin::PutEnvironmentError> {
        let auth = auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::PUT_ENVIRONMENT_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            PutEnvironmentError
        );
        let revision =
            match request.expected_revision.as_deref() {
                None => None,
                Some(value) => Some(parse_revision(value).ok_or_else(|| {
                    PluginError::domain(admin::PutEnvironmentError::InvalidRequest)
                })?),
            };
        if !valid_key(&request.idempotency_key, 200)
            || !valid_key(&request.environment_key, 128)
            || !valid_text(&request.name, 240)
            || request.expected_revision.is_some() != revision.is_some()
        {
            return Err(PluginError::domain(
                admin::PutEnvironmentError::InvalidRequest,
            ));
        }
        let hash = request_hash(&request)?;
        let record = map_storage(
            storage::put_environment(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.idempotency_key, &hash),
                &request.organization_id,
                &request.environment_key,
                &request.name,
                revision,
            )
            .await,
            |failure| admin_error!(failure, PutEnvironmentError),
        )?;
        wire_cast(&record)
    }

    async fn publish_ruleset(
        &self,
        context: Ctx,
        request: admin::PublishRulesetRequest,
    ) -> PluginResult<admin::PublishRulesetResponse, admin::PublishRulesetError> {
        let auth = auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::PUBLISH_RULESET_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            PublishRulesetError
        );
        let flag_revision = valid_mutation(
            &request.idempotency_key,
            &request.flag_key,
            &request.expected_flag_revision,
        )
        .ok_or_else(|| PluginError::domain(admin::PublishRulesetError::InvalidRequest))?;
        let environment_revision = parse_revision(&request.expected_environment_revision)
            .filter(|_| valid_key(&request.environment_key, 128))
            .ok_or_else(|| PluginError::domain(admin::PublishRulesetError::InvalidRequest))?;
        let definition = ruleset_definition(&request)
            .map_err(|()| PluginError::domain(admin::PublishRulesetError::InvalidRuleset))?;
        let hash = request_hash(&request)?;
        let record = map_storage(
            storage::publish_ruleset(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                command(&auth, &request.idempotency_key, &hash),
                &request.organization_id,
                &request.flag_key,
                &request.environment_key,
                flag_revision,
                environment_revision,
                &definition,
            )
            .await,
            |failure| admin_error!(failure, PublishRulesetError),
        )?;
        wire_cast(&record)
    }

    async fn list_evaluation_receipts(
        &self,
        context: Ctx,
        request: admin::ListEvaluationReceiptsRequest,
    ) -> PluginResult<admin::ListEvaluationReceiptsResponse, admin::ListEvaluationReceiptsError>
    {
        auth_admin!(
            self.authorize(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::LIST_EVALUATION_RECEIPTS_OPERATION,
                &request.organization_id,
                FEATURE_ADMIN
            )
            .await,
            ListEvaluationReceiptsError
        );
        let after = parse_cursor(request.after.as_deref()).map_err(|()| {
            PluginError::domain(admin::ListEvaluationReceiptsError::InvalidRequest)
        })?;
        if !(1..=200).contains(&request.limit)
            || request
                .flag_key
                .as_ref()
                .is_some_and(|value| !valid_key(value, 128))
            || request
                .environment_key
                .as_ref()
                .is_some_and(|value| !valid_key(value, 128))
        {
            return Err(PluginError::domain(
                admin::ListEvaluationReceiptsError::InvalidRequest,
            ));
        }
        let mut records = map_storage(
            storage::list_receipts(
                &self.prepared().map_err(PluginError::runtime)?.postgres,
                &request.organization_id,
                request.flag_key.as_deref(),
                request.environment_key.as_deref(),
                after,
                request.limit + 1,
            )
            .await,
            |failure| admin_error!(failure, ListEvaluationReceiptsError),
        )?;
        let has_more = records.len() > usize::try_from(request.limit).unwrap_or(0);
        if has_more {
            records.pop();
        }
        let next_cursor = has_more
            .then(|| records.last().map(|record| record.row_seq.to_string()))
            .flatten();
        let receipts = records
            .iter()
            .map(wire_cast)
            .collect::<PluginResult<Vec<admin::ListEvaluationReceiptsResponseReceiptsItem>, _>>()?;
        Ok(admin::ListEvaluationReceiptsResponse {
            receipts,
            next_cursor,
        })
    }

    fn valid_context(
        &self,
        targeting_key: &str,
        attributes: &std::collections::BTreeMap<String, serde_json::Value>,
    ) -> bool {
        valid_opaque_id(targeting_key)
            && attributes.len() <= self.config.max_attributes
            && attributes.keys().all(|key| valid_key(key, 128))
            && serde_json::to_vec(attributes)
                .is_ok_and(|wire| wire.len() <= self.config.max_context_bytes)
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

fn ruleset_definition(
    request: &admin::PublishRulesetRequest,
) -> Result<storage::RulesetDefinition, ()> {
    if !(1..=MAX_VARIANTS).contains(&request.variants.len())
        || request.targeting_rules.len() > MAX_TARGETING_RULES
        || request.percentage_rollout.len() > MAX_VARIANTS
        || !valid_key(&request.fallthrough_variant, 128)
    {
        return Err(());
    }
    let variants = request
        .variants
        .iter()
        .map(|variant| {
            Ok(storage::VariantRecord {
                variant_key: valid_key(&variant.variant_key, 128)
                    .then(|| variant.variant_key.clone())
                    .ok_or(())?,
                value: value_record(&variant.value)?,
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let targeting_rules = request
        .targeting_rules
        .iter()
        .map(|rule| {
            Ok(storage::TargetingRuleRecord {
                rule_id: valid_key(&rule.rule_id, 128)
                    .then(|| rule.rule_id.clone())
                    .ok_or(())?,
                attribute: valid_key(&rule.attribute, 128)
                    .then(|| rule.attribute.clone())
                    .ok_or(())?,
                operator: enum_string_plain(&rule.operator)?,
                comparison_values: (rule.comparison_values.len() <= MAX_COMPARISON_VALUES
                    && rule
                        .comparison_values
                        .iter()
                        .all(|value| valid_bounded_value(value, 512)))
                .then(|| rule.comparison_values.clone())
                .ok_or(())?,
                variant_key: valid_key(&rule.variant_key, 128)
                    .then(|| rule.variant_key.clone())
                    .ok_or(())?,
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let percentage_rollout = request
        .percentage_rollout
        .iter()
        .map(|item| {
            Ok(storage::RolloutRecord {
                variant_key: valid_key(&item.variant_key, 128)
                    .then(|| item.variant_key.clone())
                    .ok_or(())?,
                basis_points: item.basis_points,
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    Ok(storage::RulesetDefinition {
        variants,
        targeting_rules,
        percentage_rollout,
        fallthrough_variant: request.fallthrough_variant.clone(),
    })
}

fn value_record(
    value: &admin::PublishRulesetRequestVariantsItemValue,
) -> Result<storage::ValueRecord, ()> {
    Ok(storage::ValueRecord {
        value_type: enum_string_plain(&value.value_type)?,
        boolean_value: value.boolean_value,
        string_value: value.string_value.clone(),
        integer_value: value.integer_value.clone(),
        double_value: value.double_value,
        json_value: value.json_value.clone(),
    })
}

fn map_storage<T, E>(
    result: Result<T, StorageError>,
    map: impl FnOnce(DomainFailure) -> E,
) -> PluginResult<T, E> {
    match result {
        Ok(value) => Ok(value),
        Err(StorageError::Domain(error)) => Err(PluginError::domain(map(error))),
        Err(error) => Err(PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })),
    }
}

fn command<'a>(auth: &'a Authorized, key: &'a str, hash: &'a [u8]) -> storage::Command<'a> {
    storage::Command {
        caller: &auth.caller,
        actor: &auth.actor,
        key,
        hash,
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

fn request_hash<T: Serialize, E>(request: &T) -> Result<Vec<u8>, PluginError<E>> {
    serde_json::to_vec(request)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(serialization_runtime)
}

fn context_hash<T: Serialize, E>(context: &T) -> Result<String, PluginError<E>> {
    serde_json::to_vec(context)
        .map(|wire| format!("{:x}", Sha256::digest(wire)))
        .map_err(serialization_runtime)
}

fn wire_cast<T: DeserializeOwned, E>(value: &impl Serialize) -> Result<T, PluginError<E>> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(serialization_runtime)
}

fn enum_string<T: Serialize, E>(value: &T) -> Result<String, PluginError<E>> {
    enum_string_plain(value).map_err(|()| {
        serialization_runtime(serde_json::Error::io(std::io::Error::other(
            "enum is not a string",
        )))
    })
}

fn enum_string_plain(value: &impl Serialize) -> Result<String, ()> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or(())
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::Internal {
        detail: format!("Feature Flag wire serialization failed: {error}"),
    })
}

fn valid_mutation(key: &str, resource: &str, revision: &str) -> Option<i64> {
    (valid_key(key, 200) && valid_key(resource, 128))
        .then(|| parse_revision(revision))
        .flatten()
}

fn parse_revision(value: &str) -> Option<i64> {
    value.parse().ok().filter(|value| *value > 0)
}
fn parse_cursor(value: Option<&str>) -> Result<Option<i64>, ()> {
    match value {
        None => Ok(None),
        Some(value) => parse_revision(value).map(Some).ok_or(()),
    }
}
fn valid_callers(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_CALLERS
        && values.iter().all(|value| valid_id(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn valid_key(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}
fn valid_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.contains('\0')
}
fn valid_optional_text(value: Option<&str>, max: usize) -> bool {
    value.is_none_or(|value| valid_text(value, max))
}
fn valid_bounded_value(value: &str, max: usize) -> bool {
    value.len() <= max && !value.contains('\0') && !value.chars().any(char::is_control)
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

#[cfg(test)]
mod tests {
    use super::*;
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
