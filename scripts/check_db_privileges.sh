#!/usr/bin/env bash
#
# Run scripts/check_db_privileges.sql and fail if the cluster disagrees with
# scripts/db_roles.sql.
#
# Exit 0 and "privileges match" when clean, 1 with the violations when the
# cluster disagrees, and 2 when the check could not be performed at all —
# because "could not run" is not "it matches". Called by scripts/liveness.sh,
# so this is a control rather than something a person has to remember.
#
set -euo pipefail
cd "$(dirname "$0")/.."

# "could not run" is not "it matches", so the two exit differently: 1 for a
# privilege violation, 2 for a check that could not be performed. The file
# below was excluded from the repository by a `*.sql` ignore rule for one
# commit, and a privilege check missing from a clone must not pass by not
# running.
if [[ ! -r scripts/check_db_privileges.sql ]]; then
    echo "cannot read scripts/check_db_privileges.sql — privileges NOT checked" >&2
    exit 2
fi

if ! out="$(docker compose exec -T postgres psql -U threatintel -d threatintel \
        --quiet --no-psqlrc --tuples-only --no-align \
        -v ON_ERROR_STOP=1 -f - < scripts/check_db_privileges.sql 2>&1)"; then
    echo "psql could not run the check — privileges NOT checked:" >&2
    printf '%s\n' "$out" >&2
    exit 2
fi

# Blank lines are what a query returning no rows contributes.
violations="$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' || true)"

if [[ -z "$violations" ]]; then
    echo "db privileges match scripts/db_roles.sql"
    exit 0
fi

echo "DB PRIVILEGE VIOLATIONS:" >&2
printf '%s\n' "$violations" >&2
exit 1
