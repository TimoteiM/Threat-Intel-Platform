-- Three database roles, with the privileges each one actually needs.
--
-- Until 2026-10-19 this platform had exactly one role: `threatintel`,
-- superuser, createrole, createdb, and the owner of every table. The API, the
-- worker, beat and Alembic all connected as it. Three consequences, from
-- least to most expensive:
--
--   1. Least privilege was not expressible. A request to revoke a privilege
--      from "the application's role" had no second role to grant it to
--      instead, which is what blocked decision C on the token boundary.
--   2. A SQL injection reaching the connection was a host takeover rather
--      than a data read: `COPY ... PROGRAM` and `pg_read_file` are superuser
--      capabilities.
--   3. Migrations and ordinary traffic arrived at the database as the same
--      principal, so nothing in Postgres' own view separated a schema change
--      from a page load.
--
-- Run through scripts/provision_db_roles.sh, which supplies the two passwords
-- as psql variables. Idempotent: safe to re-run, and re-running is how a new
-- table created by a migration gets its grants if the default privileges
-- below were ever missed.
--
-- ─── who connects as what ───────────────────────────────────────────────
--
--   threatintel     superuser, owner of the schema. MIGRATIONS ONLY.
--                   DATABASE_MIGRATION_URL. Alembic and nothing else.
--   tip_app         the API, the worker and beat. DML on the application
--                   tables. No DDL, no superuser, and NO access to
--                   investigation_token_maps.
--   tip_sanitizer   the token boundary alone. DML on
--                   investigation_token_maps and nothing else in the
--                   database.
--
-- The split exists because `investigation_token_maps` is the one table whose
-- rows are, by construction, the identifiers every other protection is there
-- to remove: it maps `[HOST_a3f9c1_1]` back to a real machine name. The rows
-- are encrypted (migration 071), so this is the second lock rather than the
-- only one.

\set ON_ERROR_STOP on

-- ─── 1. the roles ───────────────────────────────────────────────────────
--
-- NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION are spelled
-- out rather than left to the default, because the default is what the
-- cluster was configured with and the whole point is not to inherit it.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tip_app') THEN
        CREATE ROLE tip_app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tip_sanitizer') THEN
        CREATE ROLE tip_sanitizer LOGIN;
    END IF;
END
$$;

ALTER ROLE tip_app       NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
ALTER ROLE tip_sanitizer NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;

ALTER ROLE tip_app       PASSWORD :'app_password';
ALTER ROLE tip_sanitizer PASSWORD :'sanitizer_password';

-- ─── 2. nothing by default ──────────────────────────────────────────────
--
-- PUBLIC is a role every login role is a member of, so a privilege held by
-- PUBLIC is held by both roles below no matter what is granted explicitly.
-- CONNECT is revoked from PUBLIC and granted by name, so a future role
-- cannot reach this database by existing.

REVOKE ALL ON DATABASE threatintel FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

GRANT CONNECT ON DATABASE threatintel TO tip_app, tip_sanitizer;
GRANT USAGE   ON SCHEMA public        TO tip_app, tip_sanitizer;

-- ─── 3. the application role ────────────────────────────────────────────
--
-- DML on every table, then the token map taken back. Granting table by table
-- would mean a hand-maintained list of 43 names that a migration silently
-- outgrows — this codebase has had eight of those lists and they have been
-- the bug repeatedly. "Everything, minus the one exception" has a single
-- place to be wrong, and the exception is asserted by a test.
--
-- No TRUNCATE and no REFERENCES: the application does neither, and TRUNCATE
-- bypasses row triggers and cannot be rolled back as cheaply as DELETE.

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO tip_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO tip_app;

-- The reverse index. REVOKE after the blanket GRANT, not instead of it.
REVOKE ALL ON TABLE investigation_token_maps FROM tip_app;

-- `alembic_version` is the migration tool's own bookkeeping. The application
-- never reads it — schema drift is detected by comparing the model's columns
-- to the live ones, not by reading a revision string — so it is readable but
-- not writable, and a version cannot be forged by anything but a migration.
REVOKE INSERT, UPDATE, DELETE ON TABLE alembic_version FROM tip_app;

-- ─── 4. the sanitizer role ──────────────────────────────────────────────
--
-- The only role that can reach the token map. It gets DML rather than SELECT
-- alone: the boundary mints a map, updates it as an investigation discovers
-- identifiers, and deletes it on completion.

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE investigation_token_maps TO tip_sanitizer;

-- And nothing else. Spelled as an explicit revoke rather than left implicit,
-- so re-running this file after a migration adds a table does not leave the
-- sanitizer holding a grant it was never meant to have.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM tip_sanitizer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM tip_sanitizer;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE investigation_token_maps TO tip_sanitizer;

-- ─── 4b. row-level security, which these grants make possible ───────────
--
-- `tenant_integrations` holds the per-client source map: one row per (client,
-- platform) with that client's connection details and encrypted credential.
-- Migration 072 puts a row-level policy on it —
--     USING (tenant_id = current_setting('app.tenant_id', true))
-- — so a query from the application role sees one client's rows and no
-- others, and an unbound session sees none at all.
--
-- **That policy only binds because of the grants above.** Row-level security
-- does not apply to a table's owner or to a role with BYPASSRLS. While the
-- application connected as `threatintel` the policy would have been
-- decoration. `tip_app` owns nothing and has neither attribute, which is what
-- turns a convention into a control.
--
-- Nothing to grant here; it is recorded because someone reading this file to
-- understand what `tip_app` can see would otherwise miss a second layer that
-- narrows it further. scripts/check_db_privileges.sql asserts the policy is
-- present and still reads the setting.

-- ─── 5. tables that do not exist yet ────────────────────────────────────
--
-- Without this, the next migration creates a table owned by `threatintel`
-- with no grant to `tip_app`, and the application gets
-- `permission denied for table ...` on whichever code path happens to touch
-- it first — possibly hours later, in a Celery task nobody is watching.
--
-- That is the failure mode this platform keeps producing in other registries,
-- and it is the one a role split introduces for free. Default privileges make
-- the grant automatic rather than remembered.
--
-- It applies to tables created BY threatintel, which is the only role that
-- can create them, because migrations are the only DDL path.

ALTER DEFAULT PRIVILEGES FOR ROLE threatintel IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tip_app;
ALTER DEFAULT PRIVILEGES FOR ROLE threatintel IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO tip_app;

-- Deliberately NOT extended to tip_sanitizer. A new table is not the
-- sanitizer's business, and a role whose grants grow on their own is not a
-- restricted role.
