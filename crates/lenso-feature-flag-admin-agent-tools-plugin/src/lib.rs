//! Agent-facing Tools over an explicitly bound Feature Flag Admin capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_feature_flag_admin::{
    self as admin, ArchiveFlagRequest, CreateFlagRequest, GetFlagRequest,
    ListEvaluationReceiptsRequest, ListFlagsRequest, PublishRulesetRequest, PutEnvironmentRequest,
    UpdateFlagRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const CREATE_FLAG_TOOL: &str = "feature_flag_admin_create_flag";
pub const GET_FLAG_TOOL: &str = "feature_flag_admin_get_flag";
pub const LIST_FLAGS_TOOL: &str = "feature_flag_admin_list_flags";
pub const UPDATE_FLAG_TOOL: &str = "feature_flag_admin_update_flag";
pub const ARCHIVE_FLAG_TOOL: &str = "feature_flag_admin_archive_flag";
pub const PUT_ENVIRONMENT_TOOL: &str = "feature_flag_admin_put_environment";
pub const PUBLISH_RULESET_TOOL: &str = "feature_flag_admin_publish_ruleset";
pub const LIST_EVALUATION_RECEIPTS_TOOL: &str = "feature_flag_admin_list_evaluation_receipts";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct FeatureFlagAdminAgentToolsPlugin {
    admin: Port<admin::FeatureFlagAdminClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl FeatureFlagAdminAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        macro_rules! invoke {
            ($future:expr, $tool:expr, $domain:path, $runtime:path) => {
                match $future.await {
                    Ok(response) => success($tool, &response),
                    Err($domain(error)) => Err(PluginError::domain(map_domain_error(&error))),
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            };
        }

        match request.name.as_str() {
            GET_FLAG_TOOL => {
                let arguments = decode::<GetFlagRequest>(&request)?;
                invoke!(
                    self.admin.get_flag_with_context(context, arguments),
                    GET_FLAG_TOOL,
                    admin::FeatureFlagAdminGetFlagInvocationError::Domain,
                    admin::FeatureFlagAdminGetFlagInvocationError::Runtime
                )
            }
            LIST_FLAGS_TOOL => {
                let arguments = decode::<ListFlagsRequest>(&request)?;
                invoke!(
                    self.admin.list_flags_with_context(context, arguments),
                    LIST_FLAGS_TOOL,
                    admin::FeatureFlagAdminListFlagsInvocationError::Domain,
                    admin::FeatureFlagAdminListFlagsInvocationError::Runtime
                )
            }
            LIST_EVALUATION_RECEIPTS_TOOL => {
                let arguments = decode::<ListEvaluationReceiptsRequest>(&request)?;
                invoke!(
                    self.admin
                        .list_evaluation_receipts_with_context(context, arguments),
                    LIST_EVALUATION_RECEIPTS_TOOL,
                    admin::FeatureFlagAdminListEvaluationReceiptsInvocationError::Domain,
                    admin::FeatureFlagAdminListEvaluationReceiptsInvocationError::Runtime
                )
            }
            CREATE_FLAG_TOOL => {
                let arguments = decode::<CreateFlagRequest>(&request)?;
                invoke!(
                    self.admin.create_flag_with_context(context, arguments),
                    CREATE_FLAG_TOOL,
                    admin::FeatureFlagAdminCreateFlagInvocationError::Domain,
                    admin::FeatureFlagAdminCreateFlagInvocationError::Runtime
                )
            }
            UPDATE_FLAG_TOOL => {
                let arguments = decode::<UpdateFlagRequest>(&request)?;
                invoke!(
                    self.admin.update_flag_with_context(context, arguments),
                    UPDATE_FLAG_TOOL,
                    admin::FeatureFlagAdminUpdateFlagInvocationError::Domain,
                    admin::FeatureFlagAdminUpdateFlagInvocationError::Runtime
                )
            }
            ARCHIVE_FLAG_TOOL => {
                let arguments = decode::<ArchiveFlagRequest>(&request)?;
                invoke!(
                    self.admin.archive_flag_with_context(context, arguments),
                    ARCHIVE_FLAG_TOOL,
                    admin::FeatureFlagAdminArchiveFlagInvocationError::Domain,
                    admin::FeatureFlagAdminArchiveFlagInvocationError::Runtime
                )
            }
            PUT_ENVIRONMENT_TOOL => {
                let arguments = decode::<PutEnvironmentRequest>(&request)?;
                invoke!(
                    self.admin.put_environment_with_context(context, arguments),
                    PUT_ENVIRONMENT_TOOL,
                    admin::FeatureFlagAdminPutEnvironmentInvocationError::Domain,
                    admin::FeatureFlagAdminPutEnvironmentInvocationError::Runtime
                )
            }
            PUBLISH_RULESET_TOOL => {
                let arguments = decode::<PublishRulesetRequest>(&request)?;
                invoke!(
                    self.admin.publish_ruleset_with_context(context, arguments),
                    PUBLISH_RULESET_TOOL,
                    admin::FeatureFlagAdminPublishRulesetInvocationError::Domain,
                    admin::FeatureFlagAdminPublishRulesetInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET_FLAG_TOOL,
            "Get one feature flag and its current immutable value type and revision.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/get-flag-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_FLAGS_TOOL,
            "List feature flag summaries with optional archived flags and bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/list-flags-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_EVALUATION_RECEIPTS_TOOL,
            "List durable evaluation receipts by optional flag and environment filters without returning evaluated values or context attributes.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/list-evaluation-receipts-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            CREATE_FLAG_TOOL,
            "Create a typed feature flag. Reuse the same idempotency_key when retrying the same intent.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/create-flag-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            UPDATE_FLAG_TOOL,
            "Update feature flag metadata using its current expected_revision. The value type remains immutable.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/update-flag-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            ARCHIVE_FLAG_TOOL,
            "Archive a feature flag using its current expected_revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/archive-flag-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            PUT_ENVIRONMENT_TOOL,
            "Create an environment with expected_revision null, or rename it using its current revision. Reuse the same idempotency_key for retries.",
            include_str!(
                "../../lenso-capability-feature-flag-admin/schemas/put-environment-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        publish_ruleset_tool(),
    ]
}

fn publish_ruleset_tool() -> ToolDefinition {
    let request_schema = include_str!(
        "../../lenso-capability-feature-flag-admin/schemas/publish-ruleset-request.schema.json"
    );
    let mut schema: serde_json::Value = serde_json::from_str(
        &request_schema.replace("flag-value.schema.json", "#/$defs/FlagValue"),
    )
    .expect("Feature Flag publish ruleset Tool schema must be valid JSON");
    let mut value_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../lenso-capability-feature-flag-admin/schemas/flag-value.schema.json"
    ))
    .expect("Feature Flag value schema must be valid JSON");
    let value_type = value_schema["$defs"]["ValueType"].clone();
    value_schema
        .as_object_mut()
        .expect("Feature Flag value schema must be an object")
        .remove("$defs");
    let definitions = schema["$defs"]
        .as_object_mut()
        .expect("Feature Flag publish ruleset schema must define $defs");
    definitions.insert("FlagValue".to_owned(), value_schema);
    definitions.insert("ValueType".to_owned(), value_type);
    definition(
        PUBLISH_RULESET_TOOL,
        "Publish an immutable environment ruleset using current flag and environment revisions. Reuse the same idempotency_key for retries.",
        &schema,
        ToolExecutionClass::Exclusive,
    )
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Feature Flag Admin Tool schema must be valid JSON");
    definition(name, description, &schema, execution)
}

fn definition(
    name: &str,
    description: &str,
    schema: &serde_json::Value,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Feature Flag Admin Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!(
                "Feature Flag Admin Tool could not serialize its typed response: {error}"
            ),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Feature Flag Admin Tool metadata must be valid JSON"),
    })
}

trait DomainToolError {
    fn to_tool_error(&self) -> ExecuteError;
}

fn map_domain_error(error: &impl DomainToolError) -> ExecuteError {
    error.to_tool_error()
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Feature Flag Admin rejected the requested operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Feature Flag Admin Tool error metadata must be valid JSON"),
        },
    }
}

macro_rules! impl_admin_error {
    ($($error:ty),+ $(,)?) => {
        $(
            impl DomainToolError for $error {
                fn to_tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::NotFound => ExecuteError::NotFound,
                        Self::Forbidden | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::AlreadyExists => rejected("already_exists"),
                        Self::Archived => rejected("archived"),
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::InvalidRuleset => rejected("invalid_ruleset"),
                        Self::OperationInProgress => rejected("operation_in_progress"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::TypeMismatch => rejected("type_mismatch"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}

impl_admin_error!(
    admin::ArchiveFlagError,
    admin::CreateFlagError,
    admin::GetFlagError,
    admin::ListEvaluationReceiptsError,
    admin::ListFlagsError,
    admin::PublishRulesetError,
    admin::PutEnvironmentError,
    admin::UpdateFlagError,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_is_a_removable_admin_only_adapter() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.feature-flag.admin.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.feature-flag-admin@1");
    }

    #[test]
    fn catalog_has_three_reads_and_five_mutations_without_evaluation_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 8);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            3
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            5
        );
        assert!(tools.iter().all(|tool| {
            !matches!(
                tool.name.as_str(),
                "feature_flag_evaluate" | "feature_flag_evaluate_batch"
            ) && !tool
                .input_schema_json
                .as_str()
                .contains("flag-value.schema.json")
        }));
    }

    #[test]
    fn exact_request_decodes_and_domain_failures_stay_distinct() {
        let get = decode::<GetFlagRequest>(&request(
            GET_FLAG_TOOL,
            r#"{"organization_id":"org-1","flag_key":"new-editor"}"#,
        ))
        .unwrap();
        assert_eq!(get.flag_key, "new-editor");
        assert!(decode::<GetFlagRequest>(&request(GET_FLAG_TOOL, r#"{"flag_key":42}"#)).is_err());

        assert_eq!(
            map_domain_error(&admin::GetFlagError::Forbidden),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_domain_error(&admin::GetFlagError::NotFound),
            ExecuteError::NotFound
        );
        let ExecuteError::ExecutionFailed { payload } =
            map_domain_error(&admin::PublishRulesetError::RevisionConflict)
        else {
            panic!("revision conflict must remain an execution failure");
        };
        assert_eq!(payload.reason_code, "revision_conflict");
    }
}
