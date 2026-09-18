use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ValueRecord {
    pub value_type: String,
    pub boolean_value: Option<bool>,
    pub string_value: Option<String>,
    pub integer_value: Option<String>,
    pub double_value: Option<f64>,
    pub json_value: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VariantRecord {
    pub variant_key: String,
    pub value: ValueRecord,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TargetingRuleRecord {
    pub rule_id: String,
    pub attribute: String,
    pub operator: String,
    pub comparison_values: Vec<String>,
    pub variant_key: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RolloutRecord {
    pub variant_key: String,
    pub basis_points: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RulesetDefinition {
    pub variants: Vec<VariantRecord>,
    pub targeting_rules: Vec<TargetingRuleRecord>,
    pub percentage_rollout: Vec<RolloutRecord>,
    pub fallthrough_variant: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FlagRecord {
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
pub struct EnvironmentRecord {
    pub organization_id: String,
    pub environment_key: String,
    pub name: String,
    pub revision: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PublishRecord {
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
pub struct EvaluationRecord {
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
pub struct ReceiptRecord {
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
pub struct Command<'a> {
    pub caller: &'a str,
    pub actor: &'a str,
    pub key: &'a str,
    pub hash: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainFailure {
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
pub enum StorageError {
    #[error("domain failure: {0:?}")]
    Domain(DomainFailure),
    #[error("storage failure: {0}")]
    Backend(String),
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
pub fn validate_ruleset(
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

pub fn choose_variant<'a>(
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

pub fn deterministic_bucket(
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
