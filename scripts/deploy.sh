#!/bin/bash
# Safe code-only deploy to an already-running Protean host.
#
# Ships ONLY the paths listed in deploy-allowlist.txt via
# `rsync --files-from` -- never a blanket tree copy. .env*, secrets/,
# and any DB/volume data are structurally outside what this script can
# ever read or write. Defaults to a dry run; nothing touches the
# remote host until --apply is passed, and even then a config/secrets
# backup is taken first and only the one target service is rebuilt and
# restarted (--no-deps), so postgres is never recreated as a side
# effect of a code deploy.
#
# Usage:
#   scripts/deploy.sh --host root@1.2.3.4 --key ~/.ssh/id_ed25519 \
#     --path /root/protean [--service panel] [--env-file .env.standalone] \
#     [--compose-file docker-compose.standalone.yml] [--apply]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ALLOWLIST="$SCRIPT_DIR/deploy-allowlist.txt"

HOST=""
KEY=""
REMOTE_PATH=""
SERVICE="panel"
ENV_FILE=".env.standalone"
COMPOSE_FILE="docker-compose.standalone.yml"
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --path) REMOTE_PATH="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --compose-file) COMPOSE_FILE="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

[ -n "$HOST" ] && [ -n "$KEY" ] && [ -n "$REMOTE_PATH" ] || {
  echo "usage: $0 --host user@host --key path/to/key --path /remote/dir [--apply]" >&2
  exit 1
}

# Defense in depth: even though the allow-list is the sole source of
# truth for what gets synced, refuse to run at all if it was ever
# edited to include anything secret/data-shaped.
if grep -Eq '(^|/)(\.env|secrets|\.git)(/|$)|\.db$|\.sqlite' "$ALLOWLIST"; then
  echo "ABORT: deploy-allowlist.txt contains a secret/data-looking path -- refusing to run" >&2
  exit 1
fi

SSH="ssh -i $KEY"
RSYNC_FLAGS=(-a --relative --exclude 'internal/web/dist/' --exclude 'node_modules/' -e "$SSH")
[ "$APPLY" -eq 0 ] && RSYNC_FLAGS+=(--dry-run -v)

if [ "$APPLY" -eq 1 ]; then MODE="APPLY"; else MODE="DRY RUN"; fi
echo "== $MODE: syncing allow-listed paths to $HOST:$REMOTE_PATH =="
(cd "$REPO_ROOT" && rsync "${RSYNC_FLAGS[@]}" --files-from="$ALLOWLIST" ./ "$HOST:$REMOTE_PATH/")

if [ "$APPLY" -eq 0 ]; then
  echo
  echo "Dry run only -- no files were changed, nothing was rebuilt/restarted."
  echo "Re-run with --apply to actually deploy."
  exit 0
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
echo "== backing up config/secrets on $HOST before restart =="
$SSH "$HOST" "mkdir -p $REMOTE_PATH/../protean-backups/$TS && cd $REMOTE_PATH && tar czf ../protean-backups/$TS/config-secrets.tar.gz $ENV_FILE secrets/ 2>/dev/null; echo backed up to ../protean-backups/$TS/"

echo "== tagging current $SERVICE image as :rollback (previous good build) =="
$SSH "$HOST" "docker tag protean-$SERVICE:latest protean-$SERVICE:rollback 2>/dev/null || true"

echo "== building $SERVICE only =="
$SSH "$HOST" "cd $REMOTE_PATH && docker compose -f $COMPOSE_FILE --env-file $ENV_FILE build $SERVICE"

echo "== restarting $SERVICE only (--no-deps: postgres is never touched) =="
$SSH "$HOST" "cd $REMOTE_PATH && docker compose -f $COMPOSE_FILE --env-file $ENV_FILE up -d --no-deps $SERVICE"

echo "== healthcheck =="
for i in 1 2 3 4 5; do
  sleep 2
  STATUS="$($SSH "$HOST" "docker inspect -f '{{.State.Health.Status}}' protean-${SERVICE}-1 2>/dev/null || echo unknown")"
  echo "  attempt $i: $STATUS"
  [ "$STATUS" = "healthy" ] && break
done

if [ "$STATUS" != "healthy" ]; then
  echo "!! $SERVICE did not report healthy -- check: docker logs protean-${SERVICE}-1" >&2
  echo "!! rollback: scripts/rollback.sh --host $HOST --key $KEY --path $REMOTE_PATH --backup $TS" >&2
  exit 1
fi

echo "== deployed and healthy. backup for rollback: $TS =="
