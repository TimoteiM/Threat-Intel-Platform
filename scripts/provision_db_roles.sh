#!/usr/bin/env bash
#
# Create (or re-apply) the three database roles described in db_roles.sql.
#
# Idempotent in both halves: a password already present in .env is reused
# rather than rotated, and the SQL re-applies the same grants. Re-run it after
# a migration adds a table if you want to be certain the grants are current —
# the default privileges in the SQL should make that unnecessary, and running
# it anyway is how you find out they did not.
#
# Passwords are generated here, written to .env, and never printed. The only
# thing this script puts on stdout is what it did, never a value.
#
# Usage:  scripts/provision_db_roles.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE=".env"
COMPOSE="docker compose"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "no $ENV_FILE — refusing to write credentials to a file that does not exist" >&2
    exit 1
fi

# .env holds every other secret this deployment has, and it is gitignored.
# Verified rather than assumed, because the cost of being wrong is a database
# password in the repository.
if ! git check-ignore -q "$ENV_FILE"; then
    echo "$ENV_FILE is NOT gitignored — refusing to write a password into it" >&2
    exit 1
fi

# Reuse an existing password; generate one only when absent. Rotating on every
# run would mean the roles and the running containers disagree the moment
# somebody re-applies the grants.
ensure_password() {
    local var="$1"
    if grep -qE "^${var}=.+" "$ENV_FILE"; then
        echo "  $var already set, reused"
        return
    fi
    # 40 alphanumeric characters from the system CSPRNG. Never echoed.
    #
    # Generated with python rather than `tr -dc < /dev/urandom | head -c 40`,
    # which looks obvious and fails under `set -o pipefail`: head exits at 40
    # bytes, tr takes SIGPIPE, and the non-zero status from the left-hand side
    # kills the script. It did exactly that on the first run of this file.
    # Alphanumeric only, so the value needs no escaping inside a URL.
    local value
    value="$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40)))')"
    printf '%s=%s\n' "$var" "$value" >> "$ENV_FILE"
    unset value
    echo "  $var generated and appended to $ENV_FILE"
}

echo "passwords:"
ensure_password TIP_APP_PASSWORD
ensure_password TIP_SANITIZER_PASSWORD

# Read them back from .env without exporting the whole file: `set -a` over a
# file with arbitrary values is how an unrelated variable ends up in the
# environment of everything below.
APP_PW="$(grep -E '^TIP_APP_PASSWORD=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
SAN_PW="$(grep -E '^TIP_SANITIZER_PASSWORD=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"

if [[ -z "$APP_PW" || -z "$SAN_PW" ]]; then
    echo "a password is empty in $ENV_FILE; not applying grants" >&2
    exit 1
fi

echo "applying scripts/db_roles.sql as the superuser..."

# -v for the psql variables the SQL file references. Passed on stdin so the
# values do not appear in the container's process list.
$COMPOSE exec -T postgres psql \
    -U threatintel -d threatintel \
    --quiet --no-psqlrc \
    -v ON_ERROR_STOP=1 \
    -v app_password="$APP_PW" \
    -v sanitizer_password="$SAN_PW" \
    -f - < scripts/db_roles.sql

unset APP_PW SAN_PW

echo "done. Verify with: scripts/check_db_privileges.sh"
