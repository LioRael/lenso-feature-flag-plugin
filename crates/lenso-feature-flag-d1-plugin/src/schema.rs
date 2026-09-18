//! Operator setup/upgrade and read-only runtime verification use lenso-migration.
use lenso_migration::{Migration, sql_migrations};
use lenso_migration_d1::{Plan, SqlMigration};
const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-feature-flags",
    "migrations/001_feature_flags.sql"
)];
const SQL: &[SqlMigration] = &[SqlMigration {
    migration: MIGRATIONS[0],
    statement_ends: include!("migration_statement_ends.rs"),
}];
pub fn plan() -> Result<Plan, lenso_migration_d1::Error> {
    Plan::new("lenso.feature-flag.d1", SQL, MIGRATIONS, None)
}
