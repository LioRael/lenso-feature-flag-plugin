//! Private real-Workers qualification for the D1 Feature Flag Plugin.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan,
};
use lenso_auth_sdk::{ActorAssertion, AuthOutcome, audience, decode_auth_response};
use lenso_capability_access_control as access;
use lenso_capability_auth::{AuthActorAssertion, AuthResponse, AuthResponseKind};
use lenso_capability_feature_evaluation as evaluation;
use lenso_capability_feature_flag_admin as admin;
use lenso_capability_organization_membership as membership;
use lenso_feature_flag_d1_plugin::{self as plugin, workers::D1Binding};
use lenso_kernel::{
    CancellationToken, InvocationContext, Kernel, NativeRequestFuture, RuntimeFailure,
    ShutdownOutcome,
};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_workers_driver::WorkersDriver;
use serde_json::json;
use std::{rc::Rc, time::Duration};
use wasm_bindgen::prelude::*;

#[derive(Debug)]
struct Caller;
impl NativePluginFactory for Caller {
    fn package_id(&self) -> &'static str {
        "test.feature-flag-caller"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}

#[derive(Debug)]
struct MembershipFixture;
impl membership::OrganizationMembershipProvider for MembershipFixture {
    fn check_membership(
        &self,
        _: InvocationContext,
        _: membership::CheckMembershipRequest,
    ) -> NativeRequestFuture<membership::OrganizationMembership> {
        Box::pin(async {
            Ok(Ok(membership::CheckMembershipResponse {
                active: true,
                owner: true,
            }))
        })
    }
}

#[derive(Debug)]
struct MembershipFactory;
impl NativePluginFactory for MembershipFactory {
    fn package_id(&self) -> &'static str {
        "fixture.organization-membership"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::new(vec![Rc::new(
            membership::OrganizationMembershipEndpoint::new(MembershipFixture),
        )]))
    }
}

#[derive(Debug)]
struct AccessFixture;
impl access::AccessControlProvider for AccessFixture {
    fn check_permission(
        &self,
        _: InvocationContext,
        _: access::CheckPermissionRequest,
    ) -> NativeRequestFuture<access::AccessControl> {
        Box::pin(async {
            Ok(Ok(access::CheckPermissionResponse {
                allowed: true,
                policy_revision: "fixture-1".into(),
            }))
        })
    }
}

#[derive(Debug)]
struct AccessFactory;
impl NativePluginFactory for AccessFactory {
    fn package_id(&self) -> &'static str {
        "fixture.access-control"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::new(vec![Rc::new(
            access::AccessControlEndpoint::new(AccessFixture),
        )]))
    }
}

struct Event(WorkersDriver);
impl Drop for Event {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}

const AUTH_ASSERTION_PUBLIC_KEY: &str = "KXWGlTbYIKmYXJl3YacNv69bI6ZcsmUL_Glc6HDWrbY";

fn failure() -> JsValue {
    JsValue::from_str("Feature Flag qualification failed")
}

fn fixture_assertion() -> Result<ActorAssertion, JsValue> {
    let response = AuthResponse {
        kind: AuthResponseKind::Authenticated,
        assertion: Some(AuthActorAssertion {
            actor_kind: "user".into(),
            assurance: "strong".into(),
            audience: vec![
                audience(admin::CAPABILITY_ID, admin::CREATE_FLAG_OPERATION),
                audience(admin::CAPABILITY_ID, admin::PUT_ENVIRONMENT_OPERATION),
                audience(admin::CAPABILITY_ID, admin::PUBLISH_RULESET_OPERATION),
                audience(admin::CAPABILITY_ID, admin::LIST_EVALUATION_RECEIPTS_OPERATION),
                audience(evaluation::CAPABILITY_ID, evaluation::EVALUATE_OPERATION),
            ],
            claims: Some(std::collections::BTreeMap::new()),
            expires_at: "2035-01-01T00:00:00Z".into(),
            issued_at: "2020-01-01T00:00:00Z".into(),
            issuer: "auth.test".into(),
            parent_provenance: None,
            proof: "UQgaaQhFPjIikYAq8UhknfU1chlsY6sYf_xWyov6R_lKG_vGaelBEaB4BODIYp3uEQtELubNxxej3-JgrQ6VDg".into(),
            subject: "usr_1".into(),
        }),
    };
    match decode_auth_response(response).map_err(|_| failure())? {
        AuthOutcome::Authenticated(assertion) => Ok(assertion),
        AuthOutcome::Absent => Err(failure()),
    }
}

fn operations_admin() -> Vec<&'static str> {
    let mut operations = vec![
        admin::ARCHIVE_FLAG_OPERATION,
        admin::CREATE_FLAG_OPERATION,
        admin::GET_FLAG_OPERATION,
        admin::LIST_EVALUATION_RECEIPTS_OPERATION,
        admin::LIST_FLAGS_OPERATION,
        admin::PUBLISH_RULESET_OPERATION,
        admin::PUT_ENVIRONMENT_OPERATION,
        admin::UPDATE_FLAG_OPERATION,
    ];
    operations.sort_unstable();
    operations
}

fn operations_evaluation() -> Vec<&'static str> {
    let mut operations = vec![
        evaluation::EVALUATE_BATCH_OPERATION,
        evaluation::EVALUATE_OPERATION,
    ];
    operations.sort_unstable();
    operations
}

fn composition(config: String) -> Result<lenso_app_plan::ResolvedAppPlan, JsValue> {
    let mut caller = PluginInstancePlan::new("caller", "test.feature-flag-caller");
    let mut denied = PluginInstancePlan::new("denied", "test.feature-flag-caller");
    let mut feature =
        PluginInstancePlan::new("feature", plugin::PACKAGE_ID).with_configuration(config);
    for (capability, version, operations) in [
        (
            evaluation::CAPABILITY_ID,
            evaluation::DESCRIPTOR_VERSION,
            operations_evaluation(),
        ),
        (
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            operations_admin(),
        ),
    ] {
        caller = caller.with_requirement(CapabilityRequirementPlan::one(capability, version));
        denied = denied.with_requirement(CapabilityRequirementPlan::one(capability, version));
        feature =
            feature.with_capability(CapabilityEndpointPlan::new(capability, version, operations));
    }
    feature = feature
        .with_requirement(CapabilityRequirementPlan::one(
            membership::CAPABILITY_ID,
            membership::DESCRIPTOR_VERSION,
        ))
        .with_requirement(CapabilityRequirementPlan::one(
            access::CAPABILITY_ID,
            access::DESCRIPTOR_VERSION,
        ));
    let membership = PluginInstancePlan::new("membership", "fixture.organization-membership")
        .with_capability(CapabilityEndpointPlan::new(
            membership::CAPABILITY_ID,
            membership::DESCRIPTOR_VERSION,
            vec![membership::CHECK_MEMBERSHIP_OPERATION],
        ));
    let access = PluginInstancePlan::new("access", "fixture.access-control").with_capability(
        CapabilityEndpointPlan::new(
            access::CAPABILITY_ID,
            access::DESCRIPTOR_VERSION,
            vec![access::CHECK_PERMISSION_OPERATION],
        ),
    );
    let bindings = [
        CapabilityBinding::new(
            "caller",
            evaluation::CAPABILITY_ID,
            evaluation::DESCRIPTOR_VERSION,
            "feature",
        ),
        CapabilityBinding::new(
            "caller",
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            "feature",
        ),
        CapabilityBinding::new(
            "denied",
            evaluation::CAPABILITY_ID,
            evaluation::DESCRIPTOR_VERSION,
            "feature",
        ),
        CapabilityBinding::new(
            "denied",
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            "feature",
        ),
        CapabilityBinding::new(
            "feature",
            membership::CAPABILITY_ID,
            membership::DESCRIPTOR_VERSION,
            "membership",
        ),
        CapabilityBinding::new(
            "feature",
            access::CAPABILITY_ID,
            access::DESCRIPTOR_VERSION,
            "access",
        ),
    ];
    AppComposition::new(
        vec![caller, denied, feature, membership, access],
        bindings.to_vec(),
    )
    .resolve()
    .map_err(|_| failure())
}

#[wasm_bindgen]
pub async fn migrate(batch: js_sys::Function) -> Result<(), JsValue> {
    plugin::schema::plan()
        .map_err(|_| failure())?
        .setup(&D1Binding(batch))
        .await
        .map_err(|_| failure())
}

#[wasm_bindgen]
#[allow(clippy::too_many_lines)]
pub async fn exercise(
    batch: js_sys::Function,
    mode: String,
    id: String,
) -> Result<String, JsValue> {
    let config = json!({
        "binding": "FEATURES",
        "auth_issuer": "auth.test",
        "auth_assertion_public_key": AUTH_ASSERTION_PUBLIC_KEY,
        "evaluation_callers": ["caller"],
        "admin_callers": ["caller"],
        "max_context_bytes": 16384,
        "max_attributes": 32,
        "max_batch_size": 50
    });
    let plan = composition(config.to_string())?;
    let driver = WorkersDriver::new();
    let _event = Event(driver.clone());
    let started = Kernel::start_native(
        plan,
        driver.clone(),
        NativePluginRegistry::new()
            .with_factory(Caller)
            .with_factory(MembershipFactory)
            .with_factory(AccessFactory)
            .with_factory(plugin::workers::factory(
                if mode == "wrong-binding" {
                    "WRONG"
                } else {
                    "FEATURES"
                },
                batch.clone(),
            )),
    )
    .await;
    if matches!(
        mode.as_str(),
        "missing-schema" | "wrong-binding" | "throws" | "malformed"
    ) {
        return if started.is_err() {
            Ok("startup-rejected".into())
        } else {
            Err(failure())
        };
    }
    let app = started.map_err(|_| failure())?;
    let context = |capability: &'static str, operation: &'static str| {
        let assertion = fixture_assertion()?;
        if !assertion
            .audience()
            .iter()
            .any(|entry| entry == &audience(capability, operation))
        {
            return Err(failure());
        }
        assertion
            .attach(app.invocation_context_after(Duration::from_secs(10), CancellationToken::new()))
            .map_err(|_| failure())
    };
    if mode == "forbidden" {
        let result = app
            .invoke::<admin::FeatureFlagAdminCreateFlag>(
                "denied",
                admin::CREATE_FLAG_OPERATION,
                admin::CreateFlagRequest {
                    description: None,
                    flag_key: "checkout".into(),
                    idempotency_key: id,
                    name: "Checkout".into(),
                    organization_id: "org".into(),
                    value_type: admin::ValueType::Boolean,
                },
            )
            .await
            .map_err(|_| failure())?;
        if result != Err(admin::CreateFlagError::Forbidden) {
            return Err(failure());
        }
    } else {
        let create_request = admin::CreateFlagRequest {
            description: Some("fixture".into()),
            flag_key: "checkout".into(),
            idempotency_key: format!("create-{id}"),
            name: "Checkout".into(),
            organization_id: "org".into(),
            value_type: admin::ValueType::Boolean,
        };
        let created = app
            .invoke_with_context::<admin::FeatureFlagAdminCreateFlag>(
                "caller",
                admin::CREATE_FLAG_OPERATION,
                context(admin::CAPABILITY_ID, admin::CREATE_FLAG_OPERATION)?,
                create_request.clone(),
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        let replay = app
            .invoke_with_context::<admin::FeatureFlagAdminCreateFlag>(
                "caller",
                admin::CREATE_FLAG_OPERATION,
                context(admin::CAPABILITY_ID, admin::CREATE_FLAG_OPERATION)?,
                create_request,
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        if created != replay || created.revision != "1" {
            return Err(failure());
        }
        let environment = app
            .invoke_with_context::<admin::FeatureFlagAdminPutEnvironment>(
                "caller",
                admin::PUT_ENVIRONMENT_OPERATION,
                context(admin::CAPABILITY_ID, admin::PUT_ENVIRONMENT_OPERATION)?,
                admin::PutEnvironmentRequest {
                    environment_key: "prod".into(),
                    expected_revision: None,
                    idempotency_key: format!("environment-{id}"),
                    name: "Production".into(),
                    organization_id: "org".into(),
                },
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        if environment.revision != "1" {
            return Err(failure());
        }
        let published = app
            .invoke_with_context::<admin::FeatureFlagAdminPublishRuleset>(
                "caller",
                admin::PUBLISH_RULESET_OPERATION,
                context(admin::CAPABILITY_ID, admin::PUBLISH_RULESET_OPERATION)?,
                admin::PublishRulesetRequest {
                    environment_key: "prod".into(),
                    expected_environment_revision: "1".into(),
                    expected_flag_revision: "1".into(),
                    fallthrough_variant: "off".into(),
                    flag_key: "checkout".into(),
                    idempotency_key: format!("publish-{id}"),
                    organization_id: "org".into(),
                    percentage_rollout: vec![],
                    targeting_rules: vec![admin::PublishRulesetRequestTargetingRulesItem {
                        attribute: "tier".into(),
                        comparison_values: vec!["staff".into()],
                        operator: admin::Operator::Equals,
                        rule_id: "staff".into(),
                        variant_key: "on".into(),
                    }],
                    variants: vec![
                        admin::PublishRulesetRequestVariantsItem {
                            variant_key: "off".into(),
                            value: admin::PublishRulesetRequestVariantsItemValue {
                                boolean_value: Some(false),
                                double_value: None,
                                integer_value: None,
                                json_value: None,
                                string_value: None,
                                value_type: admin::ValueType::Boolean,
                            },
                        },
                        admin::PublishRulesetRequestVariantsItem {
                            variant_key: "on".into(),
                            value: admin::PublishRulesetRequestVariantsItemValue {
                                boolean_value: Some(true),
                                double_value: None,
                                integer_value: None,
                                json_value: None,
                                string_value: None,
                                value_type: admin::ValueType::Boolean,
                            },
                        },
                    ],
                },
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        if published.ruleset_revision != "1" {
            return Err(failure());
        }
        let evaluation_request = evaluation::EvaluateRequest {
            context: evaluation::EvaluateRequestContext {
                attributes: std::collections::BTreeMap::from([("tier".into(), json!("staff"))]),
                targeting_key: "usr_1".into(),
            },
            environment_key: "prod".into(),
            evaluation_id: format!("evaluation-{id}"),
            flag_key: "checkout".into(),
            organization_id: "org".into(),
        };
        let evaluated = app
            .invoke_with_context::<evaluation::FeatureEvaluationEvaluate>(
                "caller",
                evaluation::EVALUATE_OPERATION,
                context(evaluation::CAPABILITY_ID, evaluation::EVALUATE_OPERATION)?,
                evaluation_request.clone(),
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        let replayed = app
            .invoke_with_context::<evaluation::FeatureEvaluationEvaluate>(
                "caller",
                evaluation::EVALUATE_OPERATION,
                context(evaluation::CAPABILITY_ID, evaluation::EVALUATE_OPERATION)?,
                evaluation_request,
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        if evaluated != replayed || evaluated.variant_key != "on" {
            return Err(failure());
        }
        let receipts = app
            .invoke_with_context::<admin::FeatureFlagAdminListEvaluationReceipts>(
                "caller",
                admin::LIST_EVALUATION_RECEIPTS_OPERATION,
                context(
                    admin::CAPABILITY_ID,
                    admin::LIST_EVALUATION_RECEIPTS_OPERATION,
                )?,
                admin::ListEvaluationReceiptsRequest {
                    after: None,
                    environment_key: Some("prod".into()),
                    flag_key: Some("checkout".into()),
                    limit: 10,
                    organization_id: "org".into(),
                },
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        if receipts.receipts.len() != 1 {
            return Err(failure());
        }
    }
    if app.shutdown(Duration::from_secs(1)).await != ShutdownOutcome::Clean {
        return Err(failure());
    }
    Ok("passed".into())
}
