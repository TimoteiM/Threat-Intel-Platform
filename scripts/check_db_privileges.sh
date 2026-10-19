#!/usr/bin/env bash
#
# Run scripts/check_db_privileges.sql and fail if the cluster disagrees with
# scripts/db_roles.sql.
#
# Exit 0 and "privileges match" when clean; exit 1 and the violations
# otherwise. Called by scripts/liveness.sh, so this is a control rather than
# something a person has to remember.
#
set -euo pipefail
cd "$(dirname "$0")/.."

out="$(docker compose exec -T postgres psql -U threatintel -d threatintel \
        --quiet --no-psqlrc --tuples-only --no-align \
        -v ON_ERROR_STOP=1 -f - < scripts/check_db_privileges.sql)"

# Blank lines are what a query returning no rows contributes.
violations="$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' || true)"

if [[ -z "$violations" ]]; then
    echo "db privileges match scripts/db_roles.sql"
    exit 0
fi

echo "DB PRIVILEGE VIOLATIONS:" >&2
printf '%s\n' "$violations" >&2
exit 1
