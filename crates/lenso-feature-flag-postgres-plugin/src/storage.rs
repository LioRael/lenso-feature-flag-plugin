use std::collections::{BTreeMap, BTreeSet};

use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ValueRecord {
    pub value_type: String,
    pub boolean_value: Option<bool>,
    pub string_value: Option<String>,
    pub integer_value: Option<String>,
    pub double_value: Option<f64>,
    pub json_value: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct VariantRecord {
    pub variant_key: String,
    pub value: ValueRecord,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TargetingRuleRecord {
    pub rule_id: String,
    pub attribute: String,
    pub operator: String,
    pub comparison_values: Vec<String>,
    pub variant_key: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct RolloutRecord {
    pub variant_key: String,
    pub basis_points: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct RulesetDefinition {
    pub variants: Vec<VariantRecord>,
    pub targeting_rules: Vec<TargetingRuleRecord>,
    pub percentage_rollout: Vec<RolloutRecord>,
    pub fallthrough_variant: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct FlagRecord {
    pub organization_id: String,
    pub flag_key: String,
    pub name: String,
    pub description: Option<String>,
    pub value_type: String,
    pub archived: bool,
    pub revision: String,
    pub created_at: String,
    pub updated_at: String,
    pub archived_at: Option<String>,
    pub row_seq: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct EnvironmentRecord {
    pub organization_id: String,
    pub environment_key: String,
    pub name: String,
    pub revision: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct PublishRecord {
    pub organization_id: String,
    pub flag_key: String,
    pub environment_key: String,
    pub ruleset_revision: String,
    pub flag_revision: String,
    pub environment_revision: String,
    pub published_by: String,
    pub published_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct EvaluationRecord {
    pub flag_key: String,
    pub environment_key: String,
    pub variant_key: String,
    pub value: ValueRecord,
    pub reason: String,
    pub ruleset_revision: String,
    pub receipt_id: String,
    pub evaluated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct ReceiptRecord {
    pub receipt_id: String,
    pub evaluation_id: String,
    pub flag_key: String,
    pub environment_key: String,
    pub variant_key: String,
    pub reason: String,
    pub ruleset_revision: String,
    pub context_hash: String,
    pub evaluated_at: String,
    #[serde(skip)]
    pub row_seq: i64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Command<'a> {
    pub caller: &'a str,
    pub actor: &'a str,
    pub key: &'a str,
    pub hash: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    NotFound,
    FlagNotFound,
    EnvironmentNotFound,
    NoPublishedRuleset,
    Archived,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
    AlreadyExists,
    TypeMismatch,
    InvalidRuleset,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("domain failure: {0:?}")]
    Domain(DomainFailure),
    #[error("database failure during {operation}: {source}")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("failed to encode or decode persisted JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to format a timestamp: {0}")]
    Time(#[from] time::error::Format),
}

impl From<DomainFailure> for StorageError {
    fn from(value: DomainFailure) -> Self {
        Self::Domain(value)
    }
}

pub(crate) async fn create_flag(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    flag_key: &str,
    name: &str,
    description: Option<&str>,
    value_type: &str,
) -> Result<FlagRecord, StorageError> {
    let mut tx = begin(postgres, "begin create flag").await?;
    if let Some(replay) = admit_command(&mut tx, command, "create_flag").await? {
        commit(tx, "commit create flag replay").await?;
        return Ok(replay);
    }
    let inserted = sqlx::query("INSERT INTO feature_flags(organization_id,flag_key,name,description,value_type) VALUES($1,$2,$3,$4,$5)")
        .bind(organization_id).bind(flag_key).bind(name).bind(description).bind(value_type)
        .execute(&mut *tx).await;
    if let Err(source) = inserted {
        if unique_violation(&source) {
            return Err(DomainFailure::AlreadyExists.into());
        }
        return Err(database("insert flag", source));
    }
    let record = read_flag_tx(&mut tx, organization_id, flag_key).await?;
    finish_command(&mut tx, command, "create_flag", &record).await?;
    commit(tx, "commit create flag").await?;
    Ok(record)
}

pub(crate) async fn get_flag(
    postgres: &OwnedPostgres,
    organization_id: &str,
    flag_key: &str,
) -> Result<FlagRecord, StorageError> {
    let row = sqlx::query("SELECT * FROM feature_flags WHERE organization_id=$1 AND flag_key=$2")
        .bind(organization_id)
        .bind(flag_key)
        .fetch_optional(postgres.pool())
        .await
        .map_err(|source| database("read flag", source))?
        .ok_or(DomainFailure::NotFound)?;
    flag_from_row(&row)
}

pub(crate) async fn list_flags(
    postgres: &OwnedPostgres,
    organization_id: &str,
    include_archived: bool,
    after: Option<i64>,
    limit: i64,
) -> Result<Vec<FlagRecord>, StorageError> {
    let rows = sqlx::query("SELECT * FROM feature_flags WHERE organization_id=$1 AND ($2 OR NOT archived) AND row_seq>$3 ORDER BY row_seq LIMIT $4")
        .bind(organization_id).bind(include_archived).bind(after.unwrap_or(0)).bind(limit)
        .fetch_all(postgres.pool()).await.map_err(|source| database("list flags", source))?;
    rows.iter().map(flag_from_row).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_flag(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    flag_key: &str,
    expected_revision: i64,
    name: &str,
    description: Option<&str>,
) -> Result<FlagRecord, StorageError> {
    let mut tx = begin(postgres, "begin update flag").await?;
    if let Some(replay) = admit_command(&mut tx, command, "update_flag").await? {
        commit(tx, "commit update flag replay").await?;
        return Ok(replay);
    }
    let current = lock_flag(&mut tx, organization_id, flag_key).await?;
    require_flag_revision(&current, expected_revision)?;
    sqlx::query("UPDATE feature_flags SET name=$3,description=$4,revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND flag_key=$2")
        .bind(organization_id).bind(flag_key).bind(name).bind(description).execute(&mut *tx).await
        .map_err(|source| database("update flag", source))?;
    let record = read_flag_tx(&mut tx, organization_id, flag_key).await?;
    finish_command(&mut tx, command, "update_flag", &record).await?;
    commit(tx, "commit update flag").await?;
    Ok(record)
}

pub(crate) async fn archive_flag(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    flag_key: &str,
    expected_revision: i64,
) -> Result<FlagRecord, StorageError> {
    let mut tx = begin(postgres, "begin archive flag").await?;
    if let Some(replay) = admit_command(&mut tx, command, "archive_flag").await? {
        commit(tx, "commit archive flag replay").await?;
        return Ok(replay);
    }
    let current = lock_flag(&mut tx, organization_id, flag_key).await?;
    require_flag_revision(&current, expected_revision)?;
    sqlx::query("UPDATE feature_flags SET archived=true,archived_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND flag_key=$2")
        .bind(organization_id).bind(flag_key).execute(&mut *tx).await
        .map_err(|source| database("archive flag", source))?;
    let record = read_flag_tx(&mut tx, organization_id, flag_key).await?;
    finish_command(&mut tx, command, "archive_flag", &record).await?;
    commit(tx, "commit archive flag").await?;
    Ok(record)
}

pub(crate) async fn put_environment(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    environment_key: &str,
    name: &str,
    expected_revision: Option<i64>,
) -> Result<EnvironmentRecord, StorageError> {
    let mut tx = begin(postgres, "begin put environment").await?;
    if let Some(replay) = admit_command(&mut tx, command, "put_environment").await? {
        commit(tx, "commit environment replay").await?;
        return Ok(replay);
    }
    let existing = sqlx::query("SELECT revision FROM feature_environments WHERE organization_id=$1 AND environment_key=$2 FOR UPDATE")
        .bind(organization_id).bind(environment_key).fetch_optional(&mut *tx).await
        .map_err(|source| database("lock environment", source))?;
    match (existing, expected_revision) {
        (None, None) => {
            sqlx::query("INSERT INTO feature_environments(organization_id,environment_key,name) VALUES($1,$2,$3)")
                .bind(organization_id).bind(environment_key).bind(name).execute(&mut *tx).await
                .map_err(|source| if unique_violation(&source) { StorageError::Domain(DomainFailure::AlreadyExists) } else { database("insert environment", source) })?;
        }
        (Some(row), Some(expected)) => {
            let revision: i64 = row
                .try_get("revision")
                .map_err(|source| database("decode environment revision", source))?;
            if revision != expected {
                return Err(DomainFailure::RevisionConflict.into());
            }
            sqlx::query("UPDATE feature_environments SET name=$3,revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND environment_key=$2")
                .bind(organization_id).bind(environment_key).bind(name).execute(&mut *tx).await
                .map_err(|source| database("update environment", source))?;
        }
        (Some(_), None) => return Err(DomainFailure::AlreadyExists.into()),
        (None, Some(_)) => return Err(DomainFailure::NotFound.into()),
    }
    let record = read_environment_tx(&mut tx, organization_id, environment_key).await?;
    finish_command(&mut tx, command, "put_environment", &record).await?;
    commit(tx, "commit put environment").await?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_ruleset(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    flag_key: &str,
    environment_key: &str,
    expected_flag_revision: i64,
    expected_environment_revision: i64,
    definition: &RulesetDefinition,
) -> Result<PublishRecord, StorageError> {
    let mut tx = begin(postgres, "begin publish ruleset").await?;
    if let Some(replay) = admit_command(&mut tx, command, "publish_ruleset").await? {
        commit(tx, "commit publish replay").await?;
        return Ok(replay);
    }
    let flag = lock_flag(&mut tx, organization_id, flag_key).await?;
    require_flag_revision(&flag, expected_flag_revision)?;
    validate_ruleset(&flag.value_type, definition)?;
    let environment = sqlx::query("SELECT revision FROM feature_environments WHERE organization_id=$1 AND environment_key=$2 FOR UPDATE")
        .bind(organization_id).bind(environment_key).fetch_optional(&mut *tx).await
        .map_err(|source| database("lock ruleset environment", source))?.ok_or(DomainFailure::NotFound)?;
    let environment_revision: i64 = environment
        .try_get("revision")
        .map_err(|source| database("decode environment revision", source))?;
    if environment_revision != expected_environment_revision {
        return Err(DomainFailure::RevisionConflict.into());
    }
    let next_revision: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(ruleset_revision),0)+1 FROM feature_rulesets WHERE organization_id=$1 AND flag_key=$2 AND environment_key=$3")
        .bind(organization_id).bind(flag_key).bind(environment_key).fetch_one(&mut *tx).await
        .map_err(|source| database("allocate ruleset revision", source))?;
    let json = serde_json::to_value(definition)?;
    let row = sqlx::query("INSERT INTO feature_rulesets(organization_id,flag_key,environment_key,ruleset_revision,ruleset_json,published_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING published_at")
        .bind(organization_id).bind(flag_key).bind(environment_key).bind(next_revision).bind(json).bind(command.actor)
        .fetch_one(&mut *tx).await.map_err(|source| database("insert ruleset", source))?;
    let published_at: OffsetDateTime = row
        .try_get("published_at")
        .map_err(|source| database("decode ruleset", source))?;
    let flag_revision = bump_flag(&mut tx, organization_id, flag_key).await?;
    let environment_revision = bump_environment(&mut tx, organization_id, environment_key).await?;
    let record = PublishRecord {
        organization_id: organization_id.to_owned(),
        flag_key: flag_key.to_owned(),
        environment_key: environment_key.to_owned(),
        ruleset_revision: next_revision.to_string(),
        flag_revision: flag_revision.to_string(),
        environment_revision: environment_revision.to_string(),
        published_by: command.actor.to_owned(),
        published_at: format_timestamp(published_at)?,
    };
    finish_command(&mut tx, command, "publish_ruleset", &record).await?;
    commit(tx, "commit publish ruleset").await?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn evaluate(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    environment_key: &str,
    flag_key: &str,
    targeting_key: &str,
    attributes: &BTreeMap<String, serde_json::Value>,
    context_hash: &str,
) -> Result<EvaluationRecord, StorageError> {
    let mut tx = begin(postgres, "begin evaluation").await?;
    if let Some(replay) = admit_command(&mut tx, command, "evaluate").await? {
        commit(tx, "commit evaluation replay").await?;
        return Ok(replay);
    }
    let record = evaluate_one(
        &mut tx,
        command,
        "evaluate",
        organization_id,
        environment_key,
        flag_key,
        command.key,
        targeting_key,
        attributes,
        context_hash,
    )
    .await?;
    finish_command(&mut tx, command, "evaluate", &record).await?;
    commit(tx, "commit evaluation").await?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn evaluate_batch(
    postgres: &OwnedPostgres,
    command: Command<'_>,
    organization_id: &str,
    environment_key: &str,
    flag_keys: &[String],
    targeting_key: &str,
    attributes: &BTreeMap<String, serde_json::Value>,
    context_hash: &str,
) -> Result<Vec<EvaluationRecord>, StorageError> {
    let mut tx = begin(postgres, "begin evaluation batch").await?;
    if let Some(replay) = admit_command(&mut tx, command, "evaluate_batch").await? {
        commit(tx, "commit evaluation batch replay").await?;
        return Ok(replay);
    }
    let mut records = Vec::with_capacity(flag_keys.len());
    for (index, flag_key) in flag_keys.iter().enumerate() {
        let evaluation_id = format!("{}:{index}", command.key);
        records.push(
            evaluate_one(
                &mut tx,
                command,
                "evaluate_batch",
                organization_id,
                environment_key,
                flag_key,
                &evaluation_id,
                targeting_key,
                attributes,
                context_hash,
            )
            .await?,
        );
    }
    finish_command(&mut tx, command, "evaluate_batch", &records).await?;
    commit(tx, "commit evaluation batch").await?;
    Ok(records)
}

pub(crate) async fn list_receipts(
    postgres: &OwnedPostgres,
    organization_id: &str,
    flag_key: Option<&str>,
    environment_key: Option<&str>,
    after: Option<i64>,
    limit: i64,
) -> Result<Vec<ReceiptRecord>, StorageError> {
    let rows = sqlx::query("SELECT * FROM feature_evaluation_receipts WHERE organization_id=$1 AND ($2::text IS NULL OR flag_key=$2) AND ($3::text IS NULL OR environment_key=$3) AND row_seq>$4 ORDER BY row_seq LIMIT $5")
        .bind(organization_id).bind(flag_key).bind(environment_key).bind(after.unwrap_or(0)).bind(limit)
        .fetch_all(postgres.pool()).await.map_err(|source| database("list evaluation receipts", source))?;
    rows.iter().map(receipt_from_row).collect()
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_one(
    tx: &mut Transaction<'_, Postgres>,
    command: Command<'_>,
    operation: &str,
    organization_id: &str,
    environment_key: &str,
    flag_key: &str,
    evaluation_id: &str,
    targeting_key: &str,
    attributes: &BTreeMap<String, serde_json::Value>,
    context_hash: &str,
) -> Result<EvaluationRecord, StorageError> {
    let flag = sqlx::query(
        "SELECT value_type,archived FROM feature_flags WHERE organization_id=$1 AND flag_key=$2 FOR SHARE",
    )
    .bind(organization_id)
    .bind(flag_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|source| database("read evaluation flag", source))?
    .ok_or(DomainFailure::FlagNotFound)?;
    if flag
        .try_get::<bool, _>("archived")
        .map_err(|source| database("decode evaluation flag", source))?
    {
        return Err(DomainFailure::Archived.into());
    }
    let value_type: String = flag
        .try_get("value_type")
        .map_err(|source| database("decode evaluation flag", source))?;
    let environment = sqlx::query(
        "SELECT 1 FROM feature_environments WHERE organization_id=$1 AND environment_key=$2",
    )
    .bind(organization_id)
    .bind(environment_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|source| database("read evaluation environment", source))?;
    if environment.is_none() {
        return Err(DomainFailure::EnvironmentNotFound.into());
    }
    let row = sqlx::query("SELECT ruleset_revision,ruleset_json FROM feature_rulesets WHERE organization_id=$1 AND flag_key=$2 AND environment_key=$3 ORDER BY ruleset_revision DESC LIMIT 1")
        .bind(organization_id).bind(flag_key).bind(environment_key).fetch_optional(&mut **tx).await
        .map_err(|source| database("read evaluation ruleset", source))?.ok_or(DomainFailure::NoPublishedRuleset)?;
    let ruleset_revision: i64 = row
        .try_get("ruleset_revision")
        .map_err(|source| database("decode evaluation ruleset", source))?;
    let ruleset_json: serde_json::Value = row
        .try_get("ruleset_json")
        .map_err(|source| database("decode evaluation ruleset", source))?;
    let definition: RulesetDefinition = serde_json::from_value(ruleset_json)?;
    validate_ruleset(&value_type, &definition)?;
    let (variant, reason) = choose_variant(
        organization_id,
        environment_key,
        flag_key,
        targeting_key,
        attributes,
        &definition,
    )?;
    let receipt_id = Uuid::new_v4();
    let evaluated_at = OffsetDateTime::now_utc();
    sqlx::query("INSERT INTO feature_evaluation_receipts(receipt_id,caller_instance,actor_subject,operation,evaluation_id,organization_id,flag_key,environment_key,variant_key,reason,ruleset_revision,context_hash,evaluated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(receipt_id).bind(command.caller).bind(command.actor).bind(operation).bind(evaluation_id).bind(organization_id).bind(flag_key)
        .bind(environment_key).bind(&variant.variant_key).bind(reason).bind(ruleset_revision).bind(context_hash).bind(evaluated_at)
        .execute(&mut **tx).await.map_err(|source| database("insert evaluation receipt", source))?;
    Ok(EvaluationRecord {
        flag_key: flag_key.to_owned(),
        environment_key: environment_key.to_owned(),
        variant_key: variant.variant_key.clone(),
        value: variant.value.clone(),
        reason: reason.to_owned(),
        ruleset_revision: ruleset_revision.to_string(),
        receipt_id: receipt_id.to_string(),
        evaluated_at: format_timestamp(evaluated_at)?,
    })
}

pub(crate) fn validate_ruleset(
    value_type: &str,
    definition: &RulesetDefinition,
) -> Result<(), StorageError> {
    let variant_keys = definition
        .variants
        .iter()
        .map(|variant| variant.variant_key.as_str())
        .collect::<BTreeSet<_>>();
    if definition.variants.is_empty()
        || variant_keys.len() != definition.variants.len()
        || !variant_keys.contains(definition.fallthrough_variant.as_str())
    {
        return Err(DomainFailure::InvalidRuleset.into());
    }
    if !definition
        .variants
        .iter()
        .all(|variant| valid_value(value_type, &variant.value))
    {
        return Err(DomainFailure::TypeMismatch.into());
    }
    let rule_ids = definition
        .targeting_rules
        .iter()
        .map(|rule| rule.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    if rule_ids.len() != definition.targeting_rules.len()
        || !definition.targeting_rules.iter().all(|rule| {
            variant_keys.contains(rule.variant_key.as_str())
                && match rule.operator.as_str() {
                    "equals" | "not_equals" | "contains" => rule.comparison_values.len() == 1,
                    "one_of" => !rule.comparison_values.is_empty(),
                    _ => false,
                }
        })
    {
        return Err(DomainFailure::InvalidRuleset.into());
    }
    let rollout_keys = definition
        .percentage_rollout
        .iter()
        .map(|item| item.variant_key.as_str())
        .collect::<BTreeSet<_>>();
    let total: i64 = definition
        .percentage_rollout
        .iter()
        .map(|item| item.basis_points)
        .sum();
    if rollout_keys.len() != definition.percentage_rollout.len()
        || total > 10_000
        || definition
            .percentage_rollout
            .iter()
            .any(|item| item.basis_points <= 0 || !variant_keys.contains(item.variant_key.as_str()))
    {
        return Err(DomainFailure::InvalidRuleset.into());
    }
    Ok(())
}

fn valid_value(expected_type: &str, value: &ValueRecord) -> bool {
    let present = usize::from(value.boolean_value.is_some())
        + usize::from(value.string_value.is_some())
        + usize::from(value.integer_value.is_some())
        + usize::from(value.double_value.is_some())
        + usize::from(value.json_value.is_some());
    present == 1
        && value.value_type == expected_type
        && match expected_type {
            "boolean" => value.boolean_value.is_some(),
            "string" => value
                .string_value
                .as_ref()
                .is_some_and(|value| value.len() <= 4_000),
            "integer" => value
                .integer_value
                .as_ref()
                .is_some_and(|value| value.parse::<i64>().is_ok()),
            "double" => value.double_value.is_some_and(f64::is_finite),
            "json" => value.json_value.as_ref().is_some_and(|value| {
                serde_json::to_vec(value).is_ok_and(|wire| wire.len() <= 16_384)
            }),
            _ => false,
        }
}

fn choose_variant<'a>(
    organization_id: &str,
    environment_key: &str,
    flag_key: &str,
    targeting_key: &str,
    attributes: &BTreeMap<String, serde_json::Value>,
    definition: &'a RulesetDefinition,
) -> Result<(&'a VariantRecord, &'static str), StorageError> {
    for rule in &definition.targeting_rules {
        if attributes
            .get(&rule.attribute)
            .is_some_and(|value| rule_matches(value, rule))
        {
            return variant(definition, &rule.variant_key).map(|variant| (variant, "target_match"));
        }
    }
    let bucket = deterministic_bucket(organization_id, environment_key, flag_key, targeting_key);
    let mut upper = 0_u64;
    for rollout in &definition.percentage_rollout {
        upper += u64::try_from(rollout.basis_points).map_err(|_| DomainFailure::InvalidRuleset)?;
        if bucket < upper {
            return variant(definition, &rollout.variant_key)
                .map(|variant| (variant, "percentage_rollout"));
        }
    }
    variant(definition, &definition.fallthrough_variant).map(|variant| (variant, "fallthrough"))
}

fn variant<'a>(
    definition: &'a RulesetDefinition,
    key: &str,
) -> Result<&'a VariantRecord, StorageError> {
    definition
        .variants
        .iter()
        .find(|variant| variant.variant_key == key)
        .ok_or(DomainFailure::InvalidRuleset.into())
}

fn rule_matches(value: &serde_json::Value, rule: &TargetingRuleRecord) -> bool {
    let rendered = match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    };
    match rule.operator.as_str() {
        "equals" => rule.comparison_values.first() == Some(&rendered),
        "not_equals" => rule.comparison_values.first() != Some(&rendered),
        "contains" => rule
            .comparison_values
            .first()
            .is_some_and(|needle| rendered.contains(needle)),
        "one_of" => rule.comparison_values.contains(&rendered),
        _ => false,
    }
}

pub(crate) fn deterministic_bucket(
    organization_id: &str,
    environment_key: &str,
    flag_key: &str,
    targeting_key: &str,
) -> u64 {
    let mut hasher = Sha256::new();
    for part in [organization_id, environment_key, flag_key, targeting_key] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    ) % 10_000
}

#[derive(Clone, Debug)]
struct LockedFlag {
    revision: i64,
    archived: bool,
    value_type: String,
}

async fn lock_flag(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    flag_key: &str,
) -> Result<LockedFlag, StorageError> {
    let row = sqlx::query("SELECT revision,archived,value_type FROM feature_flags WHERE organization_id=$1 AND flag_key=$2 FOR UPDATE")
        .bind(organization_id).bind(flag_key).fetch_optional(&mut **tx).await
        .map_err(|source| database("lock flag", source))?.ok_or(DomainFailure::NotFound)?;
    let value_type: String = row
        .try_get("value_type")
        .map_err(|source| database("decode flag lock", source))?;
    Ok(LockedFlag {
        revision: row
            .try_get("revision")
            .map_err(|source| database("decode flag lock", source))?,
        archived: row
            .try_get("archived")
            .map_err(|source| database("decode flag lock", source))?,
        value_type,
    })
}

fn require_flag_revision(flag: &LockedFlag, expected: i64) -> Result<(), StorageError> {
    if flag.archived {
        return Err(DomainFailure::Archived.into());
    }
    if flag.revision != expected {
        return Err(DomainFailure::RevisionConflict.into());
    }
    Ok(())
}

async fn bump_flag(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    flag_key: &str,
) -> Result<i64, StorageError> {
    sqlx::query_scalar("UPDATE feature_flags SET revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND flag_key=$2 RETURNING revision")
        .bind(organization_id).bind(flag_key).fetch_one(&mut **tx).await.map_err(|source| database("bump flag", source))
}

async fn bump_environment(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    environment_key: &str,
) -> Result<i64, StorageError> {
    sqlx::query_scalar("UPDATE feature_environments SET revision=revision+1,updated_at=clock_timestamp() WHERE organization_id=$1 AND environment_key=$2 RETURNING revision")
        .bind(organization_id).bind(environment_key).fetch_one(&mut **tx).await.map_err(|source| database("bump environment", source))
}

async fn read_flag_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    flag_key: &str,
) -> Result<FlagRecord, StorageError> {
    let row = sqlx::query("SELECT * FROM feature_flags WHERE organization_id=$1 AND flag_key=$2")
        .bind(organization_id)
        .bind(flag_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|source| database("read flag", source))?
        .ok_or(DomainFailure::NotFound)?;
    flag_from_row(&row)
}

async fn read_environment_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    environment_key: &str,
) -> Result<EnvironmentRecord, StorageError> {
    let row = sqlx::query(
        "SELECT * FROM feature_environments WHERE organization_id=$1 AND environment_key=$2",
    )
    .bind(organization_id)
    .bind(environment_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|source| database("read environment", source))?
    .ok_or(DomainFailure::NotFound)?;
    environment_from_row(&row)
}

async fn begin<'a>(
    postgres: &'a OwnedPostgres,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, StorageError> {
    postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database(operation, source))
}

async fn commit(
    tx: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    tx.commit()
        .await
        .map_err(|source| database(operation, source))
}

async fn admit_command<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    command: Command<'_>,
    operation: &str,
) -> Result<Option<T>, StorageError> {
    let existing = sqlx::query("SELECT request_hash,response_json FROM feature_commands WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE")
        .bind(command.caller).bind(command.actor).bind(operation).bind(command.key).fetch_optional(&mut **tx).await
        .map_err(|source| database("read command receipt", source))?;
    if let Some(row) = existing {
        let stored: Vec<u8> = row
            .try_get("request_hash")
            .map_err(|source| database("decode command receipt", source))?;
        if stored != command.hash {
            return Err(DomainFailure::IdempotencyConflict.into());
        }
        let response: Option<serde_json::Value> = row
            .try_get("response_json")
            .map_err(|source| database("decode command receipt", source))?;
        let Some(response) = response else {
            return Err(DomainFailure::OperationInProgress.into());
        };
        return Ok(Some(serde_json::from_value(response)?));
    }
    sqlx::query("INSERT INTO feature_commands(caller_instance,actor_subject,operation,idempotency_key,request_hash) VALUES($1,$2,$3,$4,$5)")
        .bind(command.caller).bind(command.actor).bind(operation).bind(command.key).bind(command.hash).execute(&mut **tx).await
        .map_err(|source| if unique_violation(&source) { StorageError::Domain(DomainFailure::OperationInProgress) } else { database("insert command receipt", source) })?;
    Ok(None)
}

async fn finish_command<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    command: Command<'_>,
    operation: &str,
    response: &T,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE feature_commands SET response_json=$5 WHERE caller_instance=$1 AND actor_subject=$2 AND operation=$3 AND idempotency_key=$4")
        .bind(command.caller).bind(command.actor).bind(operation).bind(command.key).bind(serde_json::to_value(response)?)
        .execute(&mut **tx).await.map_err(|source| database("finish command receipt", source))?;
    Ok(())
}

fn flag_from_row(row: &sqlx::postgres::PgRow) -> Result<FlagRecord, StorageError> {
    Ok(FlagRecord {
        organization_id: decode(row, "organization_id", "decode flag")?,
        flag_key: decode(row, "flag_key", "decode flag")?,
        name: decode(row, "name", "decode flag")?,
        description: decode(row, "description", "decode flag")?,
        value_type: decode(row, "value_type", "decode flag")?,
        archived: decode(row, "archived", "decode flag")?,
        revision: decode::<i64>(row, "revision", "decode flag")?.to_string(),
        created_at: format_timestamp(decode(row, "created_at", "decode flag")?)?,
        updated_at: format_timestamp(decode(row, "updated_at", "decode flag")?)?,
        archived_at: optional_timestamp(decode(row, "archived_at", "decode flag")?)?,
        row_seq: decode(row, "row_seq", "decode flag")?,
    })
}

fn environment_from_row(row: &sqlx::postgres::PgRow) -> Result<EnvironmentRecord, StorageError> {
    Ok(EnvironmentRecord {
        organization_id: decode(row, "organization_id", "decode environment")?,
        environment_key: decode(row, "environment_key", "decode environment")?,
        name: decode(row, "name", "decode environment")?,
        revision: decode::<i64>(row, "revision", "decode environment")?.to_string(),
        created_at: format_timestamp(decode(row, "created_at", "decode environment")?)?,
        updated_at: format_timestamp(decode(row, "updated_at", "decode environment")?)?,
    })
}

fn receipt_from_row(row: &sqlx::postgres::PgRow) -> Result<ReceiptRecord, StorageError> {
    Ok(ReceiptRecord {
        receipt_id: decode::<Uuid>(row, "receipt_id", "decode receipt")?.to_string(),
        evaluation_id: decode(row, "evaluation_id", "decode receipt")?,
        flag_key: decode(row, "flag_key", "decode receipt")?,
        environment_key: decode(row, "environment_key", "decode receipt")?,
        variant_key: decode(row, "variant_key", "decode receipt")?,
        reason: decode(row, "reason", "decode receipt")?,
        ruleset_revision: decode::<i64>(row, "ruleset_revision", "decode receipt")?.to_string(),
        context_hash: decode(row, "context_hash", "decode receipt")?,
        evaluated_at: format_timestamp(decode(row, "evaluated_at", "decode receipt")?)?,
        row_seq: decode(row, "row_seq", "decode receipt")?,
    })
}

fn decode<T>(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
    operation: &'static str,
) -> Result<T, StorageError>
where
    for<'r> T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|source| database(operation, source))
}

fn format_timestamp(value: OffsetDateTime) -> Result<String, StorageError> {
    Ok(value.format(&Rfc3339)?)
}
fn optional_timestamp(value: Option<OffsetDateTime>) -> Result<Option<String>, StorageError> {
    value.map(format_timestamp).transpose()
}
fn unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
        == Some("23505")
}
fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}
