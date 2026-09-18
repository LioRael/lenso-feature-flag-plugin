//! Backend contract for authorized operations. Each write includes its command receipt.
use crate::domain::{
    Command, EnvironmentRecord, EvaluationRecord, FlagRecord, PublishRecord, ReceiptRecord,
    RulesetDefinition, StorageError,
};
use std::collections::BTreeMap;
#[allow(async_fn_in_trait, clippy::too_many_arguments)]
pub trait Store {
    async fn create_flag(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        name: &str,
        description: Option<&str>,
        value_type: &str,
    ) -> Result<FlagRecord, StorageError>;
    async fn get_flag(
        &self,
        organization_id: &str,
        flag_key: &str,
    ) -> Result<FlagRecord, StorageError>;
    async fn list_flags(
        &self,
        organization_id: &str,
        include_archived: bool,
        after: Option<i64>,
        limit: i64,
    ) -> Result<Vec<FlagRecord>, StorageError>;
    async fn update_flag(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        expected_revision: i64,
        name: &str,
        description: Option<&str>,
    ) -> Result<FlagRecord, StorageError>;
    async fn archive_flag(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        expected_revision: i64,
    ) -> Result<FlagRecord, StorageError>;
    async fn put_environment(
        &self,
        command: Command<'_>,
        organization_id: &str,
        environment_key: &str,
        name: &str,
        expected_revision: Option<i64>,
    ) -> Result<EnvironmentRecord, StorageError>;
    async fn publish_ruleset(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        environment_key: &str,
        expected_flag_revision: i64,
        expected_environment_revision: i64,
        definition: &RulesetDefinition,
    ) -> Result<PublishRecord, StorageError>;
    async fn evaluate(
        &self,
        command: Command<'_>,
        organization_id: &str,
        environment_key: &str,
        flag_key: &str,
        targeting_key: &str,
        attributes: &BTreeMap<String, serde_json::Value>,
        context_hash: &str,
    ) -> Result<EvaluationRecord, StorageError>;
    async fn evaluate_batch(
        &self,
        command: Command<'_>,
        organization_id: &str,
        environment_key: &str,
        flag_keys: &[String],
        targeting_key: &str,
        attributes: &BTreeMap<String, serde_json::Value>,
        context_hash: &str,
    ) -> Result<Vec<EvaluationRecord>, StorageError>;
    async fn list_receipts(
        &self,
        organization_id: &str,
        flag_key: Option<&str>,
        environment_key: Option<&str>,
        after: Option<i64>,
        limit: i64,
    ) -> Result<Vec<ReceiptRecord>, StorageError>;
}
