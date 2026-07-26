#!/bin/bash
# One-command rollback for scripts/deploy.sh: restores the config/secrets
# backup taken right before the deploy, and retags+restarts the previous
# working image. Never touches postgres/volumes -- code + config only,
# the same two things deploy.sh ever changes.
#
# Usage:
#   scripts/rollback.sh --host root@1.2.3.4 --key ~/.ssh/id_ed25519 \
#     --path /root/protean --backup 20260726T074500Z [--service panel] \
#     [--env-file .env.standalone] [--compose-file docker-compose.standalone.yml]
set -euo pipefail

HOST=""
KEY=""
REMOTE_PATH=""
BACKUP=""
SERVICE="panel"
ENV_FILE=".env.standalone"
COMPOSE_FILE="docker-compose.standalone.yml"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --path) REMOTE_PATH="$2"; shift 2 ;;
    --backup) BACKUP="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --compose-file) COMPOSE_FILE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

[ -n "$HOST" ] && [ -n "$KEY" ] && [ -n "$REMOTE_PATH" ] && [ -n "$BACKUP" ] || {
  echo "usage: $0 --host user@host --key path/to/key --path /remote/dir --backup <timestamp>" >&2
  exit 1
}

SSH="ssh -i $KEY"
BACKUP_DIR="$REMOTE_PATH/../protean-backups/$BACKUP"

echo "== restoring config/secrets from $BACKUP_DIR =="
$SSH "$HOST" "test -f $BACKUP_DIR/config-secrets.tar.gz" || {
  echo "ABORT: no backup found at $BACKUP_DIR/config-secrets.tar.gz" >&2
  exit 1
}
$SSH "$HOST" "cd $REMOTE_PATH && tar xzf $BACKUP_DIR/config-secrets.tar.gz"

echo "== reverting $SERVICE image to previous build (:rollback tag) =="
$SSH "$HOST" "docker tag protean-$SERVICE:rollback protean-$SERVICE:latest"

echo "== restarting $SERVICE only =="
$SSH "$HOST" "cd $REMOTE_PATH && docker compose -f $COMPOSE_FILE --env-file $ENV_FILE up -d --no-deps $SERVICE"

sleep 3
$SSH "$HOST" "docker ps --format '{{.Names}}\t{{.Status}}'"
echo "== rollback applied =="
