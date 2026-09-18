//! Primary D1 snapshots and atomic guarded batches. Never retry submitted writes.
use lenso_feature_flag_core::{
    domain::{
        Command, DomainFailure, EnvironmentRecord, EvaluationRecord, FlagRecord, PublishRecord,
        ReceiptRecord, RulesetDefinition, StorageError, choose_variant, validate_ruleset,
    },
    store::Store,
};
use lenso_migration_d1::{Statement, Transport};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct D1Store<T>(pub T);

struct Snapshot {
    epoch: i64,
    command: Vec<Value>,
    flags: BTreeMap<String, FlagRecord>,
    environment: Option<EnvironmentRecord>,
    rulesets: BTreeMap<String, (String, RulesetDefinition)>,
}
fn failure() -> StorageError {
    StorageError::Backend("D1 operation failed; a submitted write may have committed; retry only with the same idempotency key".into())
}
fn encode(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(serde_json::to_string(value)?)
}
fn decode<T: DeserializeOwned>(row: &Value, field: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(
        row[field].as_str().ok_or_else(failure)?,
    )?)
}
fn params(command: Command<'_>, operation: &str) -> Vec<Value> {
    vec![
        json!(command.caller),
        json!(command.actor),
        json!(operation),
        json!(command.key),
    ]
}
fn command_query(command: Command<'_>, operation: &str) -> Statement {
    Statement::new(
        "SELECT request_hash,response FROM feature_commands WHERE caller=?1 AND actor=?2 AND operation=?3 AND command_key=?4",
        params(command, operation),
    )
}
fn replay<T: DeserializeOwned>(
    rows: &[Value],
    command: Command<'_>,
) -> Result<Option<T>, StorageError> {
    match rows {
        [] => Ok(None),
        [row] => {
            if row["request_hash"].as_str() != Some(&encode(&command.hash)?) {
                return Err(DomainFailure::IdempotencyConflict.into());
            }
            Ok(Some(decode(row, "response")?))
        }
        _ => Err(failure()),
    }
}
fn now() -> Result<String, StorageError> {
    Ok(wall_clock_now().format(&Rfc3339)?)
}

#[cfg(target_arch = "wasm32")]
#[allow(clippy::cast_possible_truncation)]
fn wall_clock_now() -> OffsetDateTime {
    let nanos = (js_sys::Date::now() * 1_000_000.0) as i128;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

#[cfg(not(target_arch = "wasm32"))]
fn wall_clock_now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
fn revision(value: &str) -> Result<i64, StorageError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(failure)
}
fn bump(value: &str) -> Result<String, StorageError> {
    Ok(revision(value)?
        .checked_add(1)
        .ok_or_else(failure)?
        .to_string())
}
fn require_flag(flag: &FlagRecord, expected: i64) -> Result<(), StorageError> {
    if flag.archived {
        return Err(DomainFailure::Archived.into());
    }
    if revision(&flag.revision)? != expected {
        return Err(DomainFailure::RevisionConflict.into());
    }
    Ok(())
}
fn flag_write(flag: &FlagRecord, create: bool) -> Result<Statement, StorageError> {
    Ok(if create {
        Statement::new(
            "INSERT INTO feature_flags(organization_id,flag_key,row_seq,record) VALUES(?1,?2,?3,?4)",
            vec![
                json!(flag.organization_id),
                json!(flag.flag_key),
                json!(flag.row_seq),
                json!(encode(flag)?),
            ],
        )
    } else {
        Statement::new(
            "UPDATE feature_flags SET record=?3 WHERE organization_id=?1 AND flag_key=?2",
            vec![
                json!(flag.organization_id),
                json!(flag.flag_key),
                json!(encode(flag)?),
            ],
        )
    })
}
fn environment_write(environment: &EnvironmentRecord) -> Result<Statement, StorageError> {
    Ok(Statement::new(
        "INSERT INTO feature_environments(organization_id,environment_key,record) VALUES(?1,?2,?3) ON CONFLICT(organization_id,environment_key) DO UPDATE SET record=excluded.record",
        vec![
            json!(environment.organization_id),
            json!(environment.environment_key),
            json!(encode(environment)?),
        ],
    ))
}
impl<T: Transport> D1Store<T> {
    async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<Vec<Value>>, StorageError> {
        let count = statements.len();
        if count == 0 || count > 128 || statements.iter().any(|s| s.params.len() > 100) {
            return Err(failure());
        }
        let result = self.0.batch(statements).await.map_err(|_| failure())?;
        if result.len() != count {
            return Err(failure());
        }
        Ok(result)
    }
    async fn query(&self, statement: Statement) -> Result<Vec<Value>, StorageError> {
        Ok(self.batch(vec![statement]).await?.remove(0))
    }
    async fn snapshot(
        &self,
        command: Command<'_>,
        operation: &str,
        org: &str,
        flags: &[String],
        environment: &str,
    ) -> Result<Snapshot, StorageError> {
        // All snapshot reads share a primary D1 batch. The epoch fences every
        // Feature Flag-owned change between this snapshot and the write batch.
        let mut rows=self.batch(vec![
            Statement::new("SELECT CAST(revision AS TEXT) AS revision FROM feature_epoch WHERE singleton=1",vec![]),
            command_query(command,operation),
            Statement::new("SELECT record FROM feature_flags WHERE organization_id=?1 AND flag_key IN (SELECT value FROM json_each(?2))",vec![json!(org),json!(encode(&flags)?)]),
            Statement::new("SELECT record FROM feature_environments WHERE organization_id=?1 AND environment_key=?2",vec![json!(org),json!(environment)]),
            Statement::new("SELECT flag_key,CAST(revision AS TEXT) AS revision,definition FROM feature_rulesets AS r WHERE organization_id=?1 AND environment_key=?2 AND flag_key IN (SELECT value FROM json_each(?3)) AND revision=(SELECT MAX(revision) FROM feature_rulesets WHERE organization_id=r.organization_id AND flag_key=r.flag_key AND environment_key=r.environment_key)",vec![json!(org),json!(environment),json!(encode(&flags)?)]),
        ]).await?.into_iter();
        let epoch = rows.next().ok_or_else(failure)?;
        let epoch = revision(
            epoch
                .first()
                .and_then(|r| r["revision"].as_str())
                .ok_or_else(failure)?,
        )?;
        let command = rows.next().ok_or_else(failure)?;
        let flags = rows
            .next()
            .ok_or_else(failure)?
            .iter()
            .map(|row| {
                let flag: FlagRecord = decode(row, "record")?;
                Ok((flag.flag_key.clone(), flag))
            })
            .collect::<Result<_, StorageError>>()?;
        let environment = rows
            .next()
            .ok_or_else(failure)?
            .first()
            .map(|row| decode(row, "record"))
            .transpose()?;
        let rulesets = rows
            .next()
            .ok_or_else(failure)?
            .iter()
            .map(|row| {
                Ok((
                    row["flag_key"].as_str().ok_or_else(failure)?.to_owned(),
                    (
                        row["revision"].as_str().ok_or_else(failure)?.to_owned(),
                        decode(row, "definition")?,
                    ),
                ))
            })
            .collect::<Result<_, StorageError>>()?;
        Ok(Snapshot {
            epoch,
            command,
            flags,
            environment,
            rulesets,
        })
    }
    async fn commit<R: Serialize + DeserializeOwned>(
        &self,
        snapshot: &Snapshot,
        command: Command<'_>,
        operation: &str,
        mut writes: Vec<Statement>,
        response: R,
    ) -> Result<R, StorageError> {
        let mut batch = vec![Statement::new(
            "INSERT INTO feature_guard(value) SELECT CASE WHEN (SELECT CAST(revision AS TEXT) FROM feature_epoch WHERE singleton=1)=?1 THEN 1 ELSE 0 END",
            vec![json!(snapshot.epoch.to_string())],
        )];
        // Unique command admission, all facts and the exact response are in the
        // same transaction. A constraint failure rolls back every statement.
        let mut arguments = params(command, operation);
        arguments.push(json!(encode(&command.hash)?));
        arguments.push(json!(encode(&response)?));
        batch.push(Statement::new("INSERT INTO feature_commands(caller,actor,operation,command_key,request_hash,response) VALUES(?1,?2,?3,?4,?5,?6)",arguments));
        batch.append(&mut writes);
        batch.push(Statement::new(
            "UPDATE feature_epoch SET revision=revision+1 WHERE singleton=1",
            vec![],
        ));
        batch.push(Statement::new("DELETE FROM feature_guard", vec![]));
        if self.batch(batch).await.is_err() {
            // Read-only reconciliation: never automatically resubmit the batch.
            if let Some(stored) = replay(
                &self.query(command_query(command, operation)).await?,
                command,
            )? {
                return Ok(stored);
            }
            return Err(failure());
        }
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    async fn evaluations(
        &self,
        command: Command<'_>,
        operation: &str,
        org: &str,
        environment: &str,
        flags: &[String],
        targeting_key: &str,
        attributes: &BTreeMap<String, Value>,
        context_hash: &str,
    ) -> Result<Vec<EvaluationRecord>, StorageError> {
        let snapshot = self
            .snapshot(command, operation, org, flags, environment)
            .await?;
        if operation == "evaluate" {
            if let Some(record) = replay::<EvaluationRecord>(&snapshot.command, command)? {
                return Ok(vec![record]);
            }
        } else if let Some(records) = replay(&snapshot.command, command)? {
            return Ok(records);
        }
        let mut records = Vec::with_capacity(flags.len());
        let mut receipts = Vec::with_capacity(flags.len());
        for (index, key) in flags.iter().enumerate() {
            let flag = snapshot.flags.get(key).ok_or(DomainFailure::FlagNotFound)?;
            if flag.archived {
                return Err(DomainFailure::Archived.into());
            }
            snapshot
                .environment
                .as_ref()
                .ok_or(DomainFailure::EnvironmentNotFound)?;
            let (ruleset_revision, definition) = snapshot
                .rulesets
                .get(key)
                .ok_or(DomainFailure::NoPublishedRuleset)?;
            validate_ruleset(&flag.value_type, definition)?;
            let (variant, reason) =
                choose_variant(org, environment, key, targeting_key, attributes, definition)?;
            let record = EvaluationRecord {
                flag_key: key.clone(),
                environment_key: environment.to_owned(),
                variant_key: variant.variant_key.clone(),
                value: variant.value.clone(),
                reason: reason.into(),
                ruleset_revision: ruleset_revision.clone(),
                receipt_id: Uuid::new_v4().to_string(),
                evaluated_at: now()?,
            };
            let evaluation_id = if operation == "evaluate" {
                command.key.to_owned()
            } else {
                format!("{}:{index}", command.key)
            };
            // Values and raw context never enter the public audit receipt.
            receipts.push(json!({"receipt_id":record.receipt_id,"evaluation_id":evaluation_id,"flag_key":key,"environment_key":environment,"variant_key":record.variant_key,"reason":reason,"ruleset_revision":ruleset_revision,"context_hash":context_hash,"evaluated_at":record.evaluated_at}));
            records.push(record);
        }
        // One statement for a bounded batch of up to 100 receipts, without
        // multiplying D1 statement or bind-parameter counts by the flag count.
        let writes = vec![Statement::new(
            "INSERT INTO feature_evaluation_receipts(receipt_id,organization_id,flag_key,environment_key,caller,actor,operation,evaluation_id,record) SELECT json_extract(value,'$.receipt_id'),?1,json_extract(value,'$.flag_key'),json_extract(value,'$.environment_key'),?2,?3,?4,json_extract(value,'$.evaluation_id'),value FROM json_each(?5)",
            vec![
                json!(org),
                json!(command.caller),
                json!(command.actor),
                json!(operation),
                json!(encode(&receipts)?),
            ],
        )];
        if operation == "evaluate" {
            let record = records.pop().ok_or_else(failure)?;
            Ok(vec![
                self.commit(&snapshot, command, operation, writes, record)
                    .await?,
            ])
        } else {
            self.commit(&snapshot, command, operation, writes, records)
                .await
        }
    }
}
impl<T: Transport> Store for D1Store<T> {
    async fn create_flag(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        name: &str,
        description: Option<&str>,
        value_type: &str,
    ) -> Result<FlagRecord, StorageError> {
        let snapshot = self
            .snapshot(
                command,
                "create_flag",
                organization_id,
                &[flag_key.into()],
                "",
            )
            .await?;
        if let Some(record) = replay(&snapshot.command, command)? {
            return Ok(record);
        }
        if snapshot.flags.contains_key(flag_key) {
            return Err(DomainFailure::AlreadyExists.into());
        }
        let now = now()?;
        let record = FlagRecord {
            organization_id: organization_id.into(),
            flag_key: flag_key.into(),
            name: name.into(),
            description: description.map(Into::into),
            value_type: value_type.into(),
            archived: false,
            revision: "1".into(),
            created_at: now.clone(),
            updated_at: now,
            archived_at: None,
            row_seq: snapshot.epoch,
        };
        self.commit(
            &snapshot,
            command,
            "create_flag",
            vec![flag_write(&record, true)?],
            record,
        )
        .await
    }
    async fn get_flag(
        &self,
        organization_id: &str,
        flag_key: &str,
    ) -> Result<FlagRecord, StorageError> {
        let rows = self
            .query(Statement::new(
                "SELECT record FROM feature_flags WHERE organization_id=?1 AND flag_key=?2",
                vec![json!(organization_id), json!(flag_key)],
            ))
            .await?;
        decode(rows.first().ok_or(DomainFailure::NotFound)?, "record")
    }
    async fn list_flags(
        &self,
        organization_id: &str,
        include_archived: bool,
        after: Option<i64>,
        limit: i64,
    ) -> Result<Vec<FlagRecord>, StorageError> {
        self.query(Statement::new("SELECT record FROM feature_flags WHERE organization_id=?1 AND (?2 OR NOT json_extract(record,'$.archived')) AND row_seq>?3 ORDER BY row_seq LIMIT ?4",vec![json!(organization_id),json!(i32::from(include_archived)),json!(after.unwrap_or(0)),json!(limit)])).await?.iter().map(|row|decode(row,"record")).collect()
    }
    async fn update_flag(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        expected_revision: i64,
        name: &str,
        description: Option<&str>,
    ) -> Result<FlagRecord, StorageError> {
        let snapshot = self
            .snapshot(
                command,
                "update_flag",
                organization_id,
                &[flag_key.into()],
                "",
            )
            .await?;
        if let Some(record) = replay(&snapshot.command, command)? {
            return Ok(record);
        }
        let mut record = snapshot
            .flags
            .get(flag_key)
            .ok_or(DomainFailure::NotFound)?
            .clone();
        require_flag(&record, expected_revision)?;
        record.name = name.into();
        record.description = description.map(Into::into);
        record.revision = bump(&record.revision)?;
        record.updated_at = now()?;
        self.commit(
            &snapshot,
            command,
            "update_flag",
            vec![flag_write(&record, false)?],
            record,
        )
        .await
    }
    async fn archive_flag(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        expected_revision: i64,
    ) -> Result<FlagRecord, StorageError> {
        let snapshot = self
            .snapshot(
                command,
                "archive_flag",
                organization_id,
                &[flag_key.into()],
                "",
            )
            .await?;
        if let Some(record) = replay(&snapshot.command, command)? {
            return Ok(record);
        }
        let mut record = snapshot
            .flags
            .get(flag_key)
            .ok_or(DomainFailure::NotFound)?
            .clone();
        require_flag(&record, expected_revision)?;
        record.revision = bump(&record.revision)?;
        record.updated_at = now()?;
        record.archived = true;
        record.archived_at = Some(record.updated_at.clone());
        self.commit(
            &snapshot,
            command,
            "archive_flag",
            vec![flag_write(&record, false)?],
            record,
        )
        .await
    }
    async fn put_environment(
        &self,
        command: Command<'_>,
        organization_id: &str,
        environment_key: &str,
        name: &str,
        expected_revision: Option<i64>,
    ) -> Result<EnvironmentRecord, StorageError> {
        let snapshot = self
            .snapshot(
                command,
                "put_environment",
                organization_id,
                &[],
                environment_key,
            )
            .await?;
        if let Some(record) = replay(&snapshot.command, command)? {
            return Ok(record);
        }
        let now = now()?;
        let record = match (&snapshot.environment, expected_revision) {
            (None, None) => EnvironmentRecord {
                organization_id: organization_id.into(),
                environment_key: environment_key.into(),
                name: name.into(),
                revision: "1".into(),
                created_at: now.clone(),
                updated_at: now,
            },
            (Some(current), Some(expected)) => {
                if revision(&current.revision)? != expected {
                    return Err(DomainFailure::RevisionConflict.into());
                }
                let mut value = current.clone();
                value.name = name.into();
                value.revision = bump(&value.revision)?;
                value.updated_at = now;
                value
            }
            (None, Some(_)) => return Err(DomainFailure::NotFound.into()),
            (Some(_), None) => return Err(DomainFailure::AlreadyExists.into()),
        };
        self.commit(
            &snapshot,
            command,
            "put_environment",
            vec![environment_write(&record)?],
            record,
        )
        .await
    }
    async fn publish_ruleset(
        &self,
        command: Command<'_>,
        organization_id: &str,
        flag_key: &str,
        environment_key: &str,
        expected_flag_revision: i64,
        expected_environment_revision: i64,
        definition: &RulesetDefinition,
    ) -> Result<PublishRecord, StorageError> {
        let snapshot = self
            .snapshot(
                command,
                "publish_ruleset",
                organization_id,
                &[flag_key.into()],
                environment_key,
            )
            .await?;
        if let Some(record) = replay(&snapshot.command, command)? {
            return Ok(record);
        }
        let mut flag = snapshot
            .flags
            .get(flag_key)
            .ok_or(DomainFailure::NotFound)?
            .clone();
        require_flag(&flag, expected_flag_revision)?;
        validate_ruleset(&flag.value_type, definition)?;
        let mut environment = snapshot
            .environment
            .clone()
            .ok_or(DomainFailure::NotFound)?;
        if revision(&environment.revision)? != expected_environment_revision {
            return Err(DomainFailure::RevisionConflict.into());
        }
        flag.revision = bump(&flag.revision)?;
        environment.revision = bump(&environment.revision)?;
        flag.updated_at = now()?;
        environment.updated_at = flag.updated_at.clone();
        let next = snapshot
            .rulesets
            .get(flag_key)
            .map_or(Ok("1".into()), |(rev, _)| bump(rev))?;
        let record = PublishRecord {
            organization_id: organization_id.into(),
            flag_key: flag_key.into(),
            environment_key: environment_key.into(),
            ruleset_revision: next,
            flag_revision: flag.revision.clone(),
            environment_revision: environment.revision.clone(),
            published_by: command.actor.into(),
            published_at: flag.updated_at.clone(),
        };
        let writes = vec![
            flag_write(&flag, false)?,
            environment_write(&environment)?,
            Statement::new(
                "INSERT INTO feature_rulesets(organization_id,flag_key,environment_key,revision,definition,publication) VALUES(?1,?2,?3,?4,?5,?6)",
                vec![
                    json!(organization_id),
                    json!(flag_key),
                    json!(environment_key),
                    json!(record.ruleset_revision),
                    json!(encode(definition)?),
                    json!(encode(&record)?),
                ],
            ),
        ];
        self.commit(&snapshot, command, "publish_ruleset", writes, record)
            .await
    }
    async fn evaluate(
        &self,
        command: Command<'_>,
        organization_id: &str,
        environment_key: &str,
        flag_key: &str,
        targeting_key: &str,
        attributes: &BTreeMap<String, Value>,
        context_hash: &str,
    ) -> Result<EvaluationRecord, StorageError> {
        self.evaluations(
            command,
            "evaluate",
            organization_id,
            environment_key,
            &[flag_key.into()],
            targeting_key,
            attributes,
            context_hash,
        )
        .await?
        .pop()
        .ok_or_else(failure)
    }
    async fn evaluate_batch(
        &self,
        command: Command<'_>,
        organization_id: &str,
        environment_key: &str,
        flag_keys: &[String],
        targeting_key: &str,
        attributes: &BTreeMap<String, Value>,
        context_hash: &str,
    ) -> Result<Vec<EvaluationRecord>, StorageError> {
        self.evaluations(
            command,
            "evaluate_batch",
            organization_id,
            environment_key,
            flag_keys,
            targeting_key,
            attributes,
            context_hash,
        )
        .await
    }
    async fn list_receipts(
        &self,
        organization_id: &str,
        flag_key: Option<&str>,
        environment_key: Option<&str>,
        after: Option<i64>,
        limit: i64,
    ) -> Result<Vec<ReceiptRecord>, StorageError> {
        let rows=self.query(Statement::new("SELECT CAST(row_seq AS TEXT) AS row_seq,record FROM feature_evaluation_receipts WHERE organization_id=?1 AND (?2 IS NULL OR flag_key=?2) AND (?3 IS NULL OR environment_key=?3) AND row_seq>?4 ORDER BY row_seq LIMIT ?5",vec![json!(organization_id),json!(flag_key),json!(environment_key),json!(after.unwrap_or(0)),json!(limit)])).await?;
        rows.iter()
            .map(|row| {
                let record: Value = decode(row, "record")?;
                Ok(ReceiptRecord {
                    receipt_id: field(&record, "receipt_id")?,
                    evaluation_id: field(&record, "evaluation_id")?,
                    flag_key: field(&record, "flag_key")?,
                    environment_key: field(&record, "environment_key")?,
                    variant_key: field(&record, "variant_key")?,
                    reason: field(&record, "reason")?,
                    ruleset_revision: field(&record, "ruleset_revision")?,
                    context_hash: field(&record, "context_hash")?,
                    evaluated_at: field(&record, "evaluated_at")?,
                    row_seq: revision(&field(row, "row_seq")?)?,
                })
            })
            .collect()
    }
}
fn field(value: &Value, key: &str) -> Result<String, StorageError> {
    Ok(value[key].as_str().ok_or_else(failure)?.to_owned())
}
