-- Does the database agree with scripts/db_roles.sql?
--
-- Asked by introspection rather than by trying things and reading the
-- exceptions. The reason is measured: on 2026-10-19 the full unit suite was
-- run against a database it could not connect to AT ALL, and produced one
-- extra failure out of 3,281 tests — and the integration suite, which does
-- use a database, SKIPS when the server is unreachable. So "the tests pass"
-- is compatible with every grant in this file being wrong, and a missing
-- grant would first appear in production.
--
-- Prints one row per violation, and nothing when the cluster matches. The
-- last two queries are positive controls: a check that cannot see a
-- violation reports a clean cluster forever.

\set ON_ERROR_STOP on
\pset pager off

-- ─── 1. role attributes ─────────────────────────────────────────────────

SELECT 'ROLE ATTRIBUTE' AS violation, rolname,
       concat_ws(' ',
           CASE WHEN rolsuper     THEN 'SUPERUSER'   END,
           CASE WHEN rolcreatedb  THEN 'CREATEDB'    END,
           CASE WHEN rolcreaterole THEN 'CREATEROLE' END,
           CASE WHEN rolbypassrls THEN 'BYPASSRLS'   END,
           CASE WHEN rolreplication THEN 'REPLICATION' END) AS holds
FROM pg_roles
WHERE rolname IN ('tip_app', 'tip_sanitizer')
  AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication);

-- ─── 2. the application role must not reach the token map ───────────────

SELECT 'APP CAN REACH TOKEN MAP' AS violation, 'tip_app' AS rolname, priv AS holds
FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES']) AS priv
WHERE has_table_privilege('tip_app', 'investigation_token_maps', priv);

-- ─── 3. the sanitizer must reach nothing else ───────────────────────────

SELECT 'SANITIZER REACHES ANOTHER TABLE' AS violation, c.relname AS rolname, p.priv AS holds
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p(priv)
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND c.relname <> 'investigation_token_maps'
  AND has_table_privilege('tip_sanitizer', c.oid, p.priv);

-- ─── 4. the application role must reach everything else ─────────────────
--
-- The direction that breaks the product rather than the security property,
-- and the one a role split introduces for free: a migration creates a table
-- and nothing grants it. alembic_version is write-restricted on purpose.

SELECT 'APP MISSING A GRANT' AS violation, c.relname AS rolname, p.priv AS holds
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p(priv)
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND c.relname NOT IN ('investigation_token_maps', 'alembic_version')
  AND NOT has_table_privilege('tip_app', c.oid, p.priv);

SELECT 'APP CANNOT READ alembic_version' AS violation, 'tip_app' AS rolname, 'SELECT' AS holds
WHERE NOT has_table_privilege('tip_app', 'alembic_version', 'SELECT');

-- ─── 5. sequences, which are how an insert gets its id ──────────────────

SELECT 'APP MISSING SEQUENCE GRANT' AS violation, c.relname AS rolname, p.priv AS holds
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN unnest(ARRAY['USAGE','SELECT']) AS p(priv)
WHERE n.nspname = 'public' AND c.relkind = 'S'
  AND NOT has_sequence_privilege('tip_app', c.oid, p.priv);

-- ─── 6. no DDL for either role ──────────────────────────────────────────

SELECT 'CAN CREATE IN SCHEMA' AS violation, r AS rolname, 'CREATE' AS holds
FROM unnest(ARRAY['tip_app','tip_sanitizer']) AS r
WHERE has_schema_privilege(r, 'public', 'CREATE');

-- ─── 7. tables a future migration adds ──────────────────────────────────
--
-- The default privileges are what make the grant automatic instead of
-- remembered. Their absence is silent until the table exists.

SELECT 'NO DEFAULT PRIVILEGES FOR tip_app' AS violation, 'threatintel' AS rolname,
       'ALTER DEFAULT PRIVILEGES' AS holds
WHERE NOT EXISTS (
    SELECT 1 FROM pg_default_acl d
    JOIN pg_namespace n ON n.oid = d.defaclnamespace
    WHERE n.nspname = 'public' AND d.defaclobjtype = 'r'
      AND array_to_string(d.defaclacl, ',') LIKE '%tip_app=%'
);

-- ─── positive controls ──────────────────────────────────────────────────
--
-- Everything above is written so that silence means "clean". A check whose
-- predicate can never be true is also silent, so two of them are inverted
-- here: these print a row when the introspection is NOT working, which is
-- the only way an empty report above can be trusted.

-- `client_alerts`, not `alerts`. The first version of this control named a
-- table that does not exist, and psql refused the whole file — which is the
-- loud version of the failure it exists to prevent, and the reason a control
-- naming a specific object is better than one asserting a count.
SELECT 'CONTROL FAILED: has_table_privilege sees nothing for tip_app' AS violation,
       'tip_app' AS rolname, 'SELECT on client_alerts' AS holds
WHERE NOT has_table_privilege('tip_app', 'client_alerts', 'SELECT');

SELECT 'CONTROL FAILED: the sanitizer cannot reach its own table' AS violation,
       'tip_sanitizer' AS rolname, 'SELECT on investigation_token_maps' AS holds
WHERE NOT has_table_privilege('tip_sanitizer', 'investigation_token_maps', 'SELECT');
