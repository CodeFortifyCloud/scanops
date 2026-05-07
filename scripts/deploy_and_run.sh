#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
APP_SERVICE="${SCANOPS_SERVICE:-scanops-web}"
WORKER_SERVICE="${SCANOPS_WORKER_SERVICE:-scanops-worker}"
DB_SERVICE="${SCANOPS_DB_SERVICE:-db}"
HOST="${SCANOPS_HOST:-0.0.0.0}"
PORT="${SCANOPS_PORT:-8008}"
DEFAULT_BACKUP_DIR="${PROJECT_ROOT}/dbbackup/migration"

ACTION="up"
DO_BUILD=1
FOLLOW_LOGS=0
NO_VERIFY=0
RUN_RESTORE_AFTER_UP=0
BACKUP_FILE=""
COMPOSE_CMD=()

DB_NAME="${SCANOPS_DB_NAME:-db_scanops}"
DB_USER="${SCANOPS_DB_USER:-scanops}"
DB_PASSWORD="${SCANOPS_DB_PASSWORD:-scanops_dev_password}"

log() {
  printf '[ScanOps] %s\n' "$*"
}

warn() {
  printf '[ScanOps][WARN] %s\n' "$*" >&2
}

die() {
  printf '[ScanOps][ERROR] %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage: scripts/deploy_and_run.sh [action] [options]

Actions:
  up (default)            Build image, start DB + app, run migrate/collectstatic, verify readiness
  build                   Build Docker image for ScanOps app service
  down                    Stop and remove containers/network
  restart                 Recreate services (down then up)
  logs                    Follow service logs
  ps                      Show compose service status
  migrate                 Run Django migrations inside Docker
  collectstatic           Run Django collectstatic inside Docker
  check                   Run Django system checks inside Docker
  backup-local-db         Backup current local DB configured in .env to dbbackup/migration
  restore-db              Restore a SQL backup into Docker PostgreSQL, then run migrations

Options:
  --service <name>        Compose app service name (default: ${APP_SERVICE})
  --db-service <name>     Compose DB service name (default: ${DB_SERVICE})
  --worker-service <name> Compose worker service name (default: ${WORKER_SERVICE})
  --port <port>           Host port for readiness checks and compose mapping (default: ${PORT})
  --build                 Force build step for 'up' and 'restart' (default behavior)
  --no-build              Skip build step for 'up' and 'restart'
  --restore-db            With action 'up', restore DB after startup
  --backup-file <path>    SQL backup file path for restore-db / --restore-db
  --logs                  Follow logs after a successful 'up' or 'restart'
  --no-verify             Skip HTTP readiness verification after startup
  -h, --help              Show this help

Environment:
  SCANOPS_SERVICE         Override compose app service name
  SCANOPS_DB_SERVICE      Override compose DB service name
  SCANOPS_WORKER_SERVICE  Override compose worker service name
  SCANOPS_PORT            Override host port mapping (default 8008)
  SCANOPS_HOST            Display host for startup URL (default 0.0.0.0)
  SCANOPS_DB_NAME         Docker PostgreSQL database name
  SCANOPS_DB_USER         Docker PostgreSQL database user
  SCANOPS_DB_PASSWORD     Docker PostgreSQL database password
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    up|build|down|restart|logs|ps|migrate|collectstatic|check|backup-local-db|restore-db)
      ACTION="$1"
      shift
      ;;
    --service)
      [[ $# -ge 2 ]] || die "--service requires a value"
      APP_SERVICE="$2"
      shift 2
      ;;
    --db-service)
      [[ $# -ge 2 ]] || die "--db-service requires a value"
      DB_SERVICE="$2"
      shift 2
      ;;
    --worker-service)
      [[ $# -ge 2 ]] || die "--worker-service requires a value"
      WORKER_SERVICE="$2"
      shift 2
      ;;
    --port)
      [[ $# -ge 2 ]] || die "--port requires a value"
      PORT="$2"
      shift 2
      ;;
    --build)
      DO_BUILD=1
      shift
      ;;
    --no-build)
      DO_BUILD=0
      shift
      ;;
    --restore-db)
      RUN_RESTORE_AFTER_UP=1
      shift
      ;;
    --backup-file)
      [[ $# -ge 2 ]] || die "--backup-file requires a value"
      BACKUP_FILE="$2"
      shift 2
      ;;
    --logs)
      FOLLOW_LOGS=1
      shift
      ;;
    --no-verify)
      NO_VERIFY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

[[ -f "${COMPOSE_FILE}" ]] || die "docker-compose.yml not found at ${COMPOSE_FILE}"

load_env_file() {
  if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${PROJECT_ROOT}/.env"
    set +a
    return 0
  fi

  if [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
    cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
    warn "No .env file found. Created ${PROJECT_ROOT}/.env from .env.example."
  elif [[ -f "${PROJECT_ROOT}/.env.sample" ]]; then
    cp "${PROJECT_ROOT}/.env.sample" "${PROJECT_ROOT}/.env"
    warn "No .env file found. Created ${PROJECT_ROOT}/.env from .env.sample."
  else
    warn "No .env/.env.example/.env.sample found. Continuing with environment defaults."
    return 0
  fi

  set -a
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env"
  set +a
}

set_compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  else
    die "Docker Compose is required"
  fi
}

ensure_docker() {
  command -v docker >/dev/null 2>&1 || die "Docker is not installed"
  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable"
  set_compose_cmd
}

compose() {
  SCANOPS_PORT="${PORT}" "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" "$@"
}

wait_for_http() {
  local url="$1"
  local attempts="$2"
  local sleep_for="$3"
  local i

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl is not available; skipping HTTP readiness verification for ${url}"
    return 0
  fi

  for ((i = 1; i <= attempts; i += 1)); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_for}"
  done
  return 1
}

wait_for_db() {
  local attempts=90
  local i

  log "Waiting for PostgreSQL service '${DB_SERVICE}'"
  for ((i = 1; i <= attempts; i += 1)); do
    if compose exec -T "${DB_SERVICE}" pg_isready -U "${DB_USER}" -d "${DB_NAME}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  compose logs --tail=200 "${DB_SERVICE}" || true
  die "PostgreSQL service '${DB_SERVICE}' did not become ready in time"
}

run_manage_command() {
  local subcommand="$1"
  shift
  log "Running 'python manage.py ${subcommand} $*' in '${APP_SERVICE}'"
  compose exec -T "${APP_SERVICE}" python manage.py "${subcommand}" "$@"
}

ensure_runtime_up() {
  if [[ "${DO_BUILD}" -eq 1 ]]; then
    log "Building Docker image for '${APP_SERVICE}'"
    compose build "${APP_SERVICE}"
  fi

  log "Starting service '${DB_SERVICE}'"
  compose up -d --remove-orphans "${DB_SERVICE}"
  wait_for_db

  log "Starting service '${APP_SERVICE}'"
  compose up -d --remove-orphans "${APP_SERVICE}"
  log "Starting service '${WORKER_SERVICE}'"
  compose up -d --remove-orphans "${WORKER_SERVICE}"
}

wait_for_app() {
  local login_url="http://127.0.0.1:${PORT}/login/"
  if wait_for_http "${login_url}" 90 1; then
    return 0
  fi
  compose logs --tail=200 "${APP_SERVICE}" || true
  die "Application did not become ready on ${login_url}"
}

resolve_backup_file() {
  if [[ -n "${BACKUP_FILE}" ]]; then
    [[ -f "${BACKUP_FILE}" ]] || die "Backup file not found: ${BACKUP_FILE}"
    printf '%s\n' "${BACKUP_FILE}"
    return 0
  fi

  local latest_backup
  latest_backup="$(ls -1t "${DEFAULT_BACKUP_DIR}"/*.sql 2>/dev/null | head -n 1 || true)"
  [[ -n "${latest_backup}" ]] || die "No backup file found in ${DEFAULT_BACKUP_DIR}. Use --backup-file <path>."
  printf '%s\n' "${latest_backup}"
}

restore_db() {
  local backup_path
  backup_path="$(resolve_backup_file)"

  log "Restoring '${backup_path}' into Docker PostgreSQL database '${DB_NAME}'"
  compose exec -T "${DB_SERVICE}" psql -U "${DB_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1 \
    -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
  compose exec -T "${DB_SERVICE}" psql -U "${DB_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1 < "${backup_path}"
  log "Restore completed"
}

backup_local_db() {
  local timestamp backup_dir output_file
  backup_dir="${DEFAULT_BACKUP_DIR}"
  mkdir -p "${backup_dir}"
  timestamp="$(date +%Y%m%d_%H%M%S)"

  local dev_database_mode dev_database_engine local_db_name local_db_user local_db_password local_db_host local_db_port sqlite_path
  dev_database_mode="${JTRO_DEV_DATABASE:-}"
  dev_database_engine="${JTRO_DEV_DATABASE_ENGINE:-}"
  local_db_name="${JTRO_DEV_DATABASE_NAME:-}"
  local_db_user="${JTRO_DEV_DATABASE_USER:-postgres}"
  local_db_password="${JTRO_DEV_DATABASE_PASSWORD:-}"
  local_db_host="${JTRO_DEV_DATABASE_HOST:-localhost}"
  local_db_port="${JTRO_DEV_DATABASE_PORT:-5432}"
  sqlite_path="${JTRO_SQLITE_PATH:-${PROJECT_ROOT}/db.sqlite3}"

  if [[ "${dev_database_mode}" == "postgres" || "${dev_database_engine}" == *postgres* ]]; then
    command -v pg_dump >/dev/null 2>&1 || die "pg_dump is required for PostgreSQL local backup"
    [[ -n "${local_db_name}" ]] || die "JTRO_DEV_DATABASE_NAME is required for PostgreSQL local backup"
    output_file="${backup_dir}/local_postgres_${local_db_name}_${timestamp}.sql"
    log "Backing up local PostgreSQL database '${local_db_name}' from ${local_db_host}:${local_db_port}"
    PGPASSWORD="${local_db_password}" pg_dump --format=plain --no-owner --no-privileges \
      -h "${local_db_host}" -p "${local_db_port}" -U "${local_db_user}" -d "${local_db_name}" -f "${output_file}"
    log "Local PostgreSQL backup created at ${output_file}"
    return 0
  fi

  if [[ "${dev_database_mode}" == "sqlite" || "${dev_database_engine}" == *sqlite* ]]; then
    [[ -f "${sqlite_path}" ]] || die "SQLite file not found: ${sqlite_path}"
    output_file="${backup_dir}/local_sqlite_snapshot_${timestamp}.sqlite3"
    cp "${sqlite_path}" "${output_file}"
    log "SQLite snapshot created at ${output_file}"
    return 0
  fi

  die "Unsupported local development DB config: JTRO_DEV_DATABASE='${dev_database_mode}', JTRO_DEV_DATABASE_ENGINE='${dev_database_engine}'"
}

start_service() {
  if [[ "${DO_BUILD}" -eq 1 ]]; then
    log "Building Docker image for '${APP_SERVICE}'"
    compose build "${APP_SERVICE}"
  fi

  log "Starting service '${DB_SERVICE}'"
  compose up -d --remove-orphans "${DB_SERVICE}"
  wait_for_db

  if [[ "${RUN_RESTORE_AFTER_UP}" -eq 1 ]]; then
    restore_db
  fi

  log "Starting service '${APP_SERVICE}'"
  compose up -d --remove-orphans "${APP_SERVICE}"

  if [[ "${NO_VERIFY}" -eq 0 ]]; then
    wait_for_app
    log "Application is reachable at http://${HOST}:${PORT}/login/"
  fi

  compose ps "${DB_SERVICE}" "${APP_SERVICE}" "${WORKER_SERVICE}"

  if [[ "${FOLLOW_LOGS}" -eq 1 ]]; then
    compose logs -f --tail=200 "${DB_SERVICE}" "${APP_SERVICE}" "${WORKER_SERVICE}"
  fi
}

down_stack() {
  log "Stopping ScanOps Docker services"
  compose down --remove-orphans
}

restart_service() {
  down_stack
  start_service
}

main() {
  ensure_docker
  cd "${PROJECT_ROOT}"
  load_env_file

  DB_NAME="${SCANOPS_DB_NAME:-db_scanops}"
  DB_USER="${SCANOPS_DB_USER:-scanops}"
  DB_PASSWORD="${SCANOPS_DB_PASSWORD:-scanops_dev_password}"

  case "${ACTION}" in
    up)
      start_service
      ;;
    build)
      log "Building Docker image for '${APP_SERVICE}'"
      compose build "${APP_SERVICE}"
      ;;
    down)
      down_stack
      ;;
    restart)
      restart_service
      ;;
    logs)
      compose logs -f --tail=200 "${DB_SERVICE}" "${APP_SERVICE}" "${WORKER_SERVICE}"
      ;;
    ps)
      compose ps "${DB_SERVICE}" "${APP_SERVICE}" "${WORKER_SERVICE}"
      ;;
    migrate)
      ensure_runtime_up
      wait_for_app
      run_manage_command migrate --noinput
      ;;
    collectstatic)
      ensure_runtime_up
      wait_for_app
      run_manage_command collectstatic --noinput --ignore "admin/js/*"
      ;;
    check)
      ensure_runtime_up
      wait_for_app
      run_manage_command check
      ;;
    backup-local-db)
      backup_local_db
      ;;
    restore-db)
      if [[ "${DO_BUILD}" -eq 1 ]]; then
        log "Building Docker image for '${APP_SERVICE}'"
        compose build "${APP_SERVICE}"
      fi
      log "Starting service '${DB_SERVICE}'"
      compose up -d --remove-orphans "${DB_SERVICE}"
      wait_for_db
      restore_db
      log "Starting service '${APP_SERVICE}'"
      compose up -d --remove-orphans "${APP_SERVICE}"
      log "Starting service '${WORKER_SERVICE}'"
      compose up -d --remove-orphans "${WORKER_SERVICE}"
      wait_for_app
      run_manage_command migrate --noinput
      ;;
    *)
      die "Unsupported action: ${ACTION}"
      ;;
  esac
}

main
