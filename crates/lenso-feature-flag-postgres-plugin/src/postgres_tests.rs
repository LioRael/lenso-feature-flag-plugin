use std::collections::BTreeMap;

use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Executor as _};
use uuid::Uuid;

use crate::{FeatureFlagOperator, schema, storage};

fn command<'a>(key: &'a str, hash: &'a [u8]) -> storage::Command<'a> {
    storage::Command {
        caller: "feature-admin",
        actor: "usr_admin",
        key,
        hash,
    }
}

fn boolean_value(value: bool) -> storage::ValueRecord {
    storage::ValueRecord {
        value_type: "boolean".to_owned(),
        boolean_value: Some(value),
        string_value: None,
        integer_value: None,
        double_value: None,
        json_value: None,
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn restart_idempotency_cas_ruleset_evaluation_and_receipts_are_durable() {
    let Ok(database_url) = std::env::var("LENSO_FEATURE_FLAG_TEST_DATABASE_URL") else {
        return;
    };
    let database_name = database_url
        .split('?')
        .next()
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or_default();
    assert!(
        database_name.starts_with("lenso_feature_flag_test"),
        "acceptance requires a dedicated lenso_feature_flag_test database"
    );
    let schema_name = format!("feature_flag_test_{}", Uuid::new_v4().simple());
    FeatureFlagOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let flag = storage::create_flag(
        &postgres,
        command("create", &[1]),
        "org",
        "checkout",
        "Checkout",
        None,
        "boolean",
    )
    .await
    .unwrap();
    assert_eq!(flag.revision, "1");
    assert_eq!(
        storage::create_flag(
            &postgres,
            command("create", &[1]),
            "org",
            "checkout",
            "Checkout",
            None,
            "boolean",
        )
        .await
        .unwrap(),
        flag
    );
    let environment = storage::put_environment(
        &postgres,
        command("environment", &[2]),
        "org",
        "prod",
        "Production",
        None,
    )
    .await
    .unwrap();
    assert_eq!(environment.revision, "1");
    let ruleset = storage::RulesetDefinition {
        variants: vec![
            storage::VariantRecord {
                variant_key: "off".to_owned(),
                value: boolean_value(false),
            },
            storage::VariantRecord {
                variant_key: "on".to_owned(),
                value: boolean_value(true),
            },
        ],
        targeting_rules: vec![storage::TargetingRuleRecord {
            rule_id: "staff".to_owned(),
            attribute: "tier".to_owned(),
            operator: "equals".to_owned(),
            comparison_values: vec!["staff".to_owned()],
            variant_key: "on".to_owned(),
        }],
        percentage_rollout: vec![storage::RolloutRecord {
            variant_key: "on".to_owned(),
            basis_points: 5_000,
        }],
        fallthrough_variant: "off".to_owned(),
    };
    let published = storage::publish_ruleset(
        &postgres,
        command("publish", &[3]),
        "org",
        "checkout",
        "prod",
        1,
        1,
        &ruleset,
    )
    .await
    .unwrap();
    assert_eq!(published.ruleset_revision, "1");
    let attributes = BTreeMap::from([("tier".to_owned(), serde_json::json!("staff"))]);
    let evaluation = storage::evaluate(
        &postgres,
        storage::Command {
            caller: "feature-api",
            actor: "usr_1",
            key: "eval-1",
            hash: &[4],
        },
        "org",
        "prod",
        "checkout",
        "usr_1",
        &attributes,
        "context-hash",
    )
    .await
    .unwrap();
    assert_eq!(evaluation.variant_key, "on");
    assert_eq!(evaluation.reason, "target_match");
    assert_eq!(
        storage::evaluate(
            &postgres,
            storage::Command {
                caller: "feature-api",
                actor: "usr_1",
                key: "eval-1",
                hash: &[4],
            },
            "org",
            "prod",
            "checkout",
            "usr_1",
            &attributes,
            "context-hash",
        )
        .await
        .unwrap(),
        evaluation
    );
    postgres.pool().close().await;

    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let receipts = storage::list_receipts(&restarted, "org", Some("checkout"), None, None, 10)
        .await
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].context_hash, "context-hash");

    let first = storage::update_flag(
        &restarted,
        command("update-a", &[5]),
        "org",
        "checkout",
        2,
        "Checkout A",
        None,
    );
    let second = storage::update_flag(
        &restarted,
        command("update-b", &[6]),
        "org",
        "checkout",
        2,
        "Checkout B",
        None,
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(
                result,
                Err(storage::StorageError::Domain(
                    storage::DomainFailure::RevisionConflict
                ))
            ))
            .count(),
        1
    );

    restarted.pool().close().await;
    let cleanup = sqlx::PgPool::connect(&database_url).await.unwrap();
    cleanup
        .execute(AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema_name}\" CASCADE"
        )))
        .await
        .unwrap();
    cleanup.close().await;
}
