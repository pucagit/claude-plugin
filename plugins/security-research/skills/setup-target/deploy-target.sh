#!/usr/bin/env bash
set -euo pipefail

# deploy-target.sh — Docker Compose lifecycle management for security audit targets
# Co-located with the setup-target skill that invokes it.
#
# Usage:
#   ./deploy-target.sh --dir <path> --project-name <name> [--app-port PORT]
#   ./deploy-target.sh --dir <path> --project-name <name> --down
#   ./deploy-target.sh --dir <path> --project-name <name> --status
#   ./deploy-target.sh --dir <path> --project-name <name> --logs

# ─── Defaults ───────────────────────────────────────────────────────────
TARGET_DIR=""
PROJECT_NAME="security-audit"
APP_PORT="8080"
MODE="up"  # up | down | status | logs
HEALTH_TIMEOUT=120
HEALTH_INTERVAL=2

# ─── Parse arguments ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)          TARGET_DIR="$2"; shift 2 ;;
    --project-name) PROJECT_NAME="$2"; shift 2 ;;
    --app-port)     APP_PORT="$2"; shift 2 ;;
    --down)         MODE="down"; shift ;;
    --status)       MODE="status"; shift ;;
    --logs)         MODE="logs"; shift ;;
    --timeout)      HEALTH_TIMEOUT="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$TARGET_DIR" ]]; then
  echo '{"error": "Missing required --dir argument"}' >&2
  exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "{\"error\": \"Directory does not exist: $TARGET_DIR\"}" >&2
  exit 1
fi

# ─── Check Docker is available ──────────────────────────────────────────
check_docker() {
  if ! command -v docker &>/dev/null; then
    echo '{"error": "Docker is not installed. Install from https://docs.docker.com/get-docker/"}' >&2
    exit 1
  fi

  if ! docker info &>/dev/null 2>&1; then
    echo '{"error": "Docker daemon is not running. Start with: sudo systemctl start docker"}' >&2
    exit 1
  fi

  # Check for docker compose (v2 plugin or standalone)
  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  else
    echo '{"error": "Docker Compose not found. Install from https://docs.docker.com/compose/install/"}' >&2
    exit 1
  fi
}

check_docker

# ─── Mode: down ─────────────────────────────────────────────────────────
if [[ "$MODE" == "down" ]]; then
  echo "Stopping containers..." >&2
  cd "$TARGET_DIR"
  $COMPOSE_CMD -p "$PROJECT_NAME" down -v --remove-orphans 2>&1 >&2
  echo '{"status": "stopped", "project_name": "'"$PROJECT_NAME"'", "message": "All containers and volumes removed"}'
  exit 0
fi

# ─── Mode: status ───────────────────────────────────────────────────────
if [[ "$MODE" == "status" ]]; then
  cd "$TARGET_DIR"
  $COMPOSE_CMD -p "$PROJECT_NAME" ps --format json 2>/dev/null || $COMPOSE_CMD -p "$PROJECT_NAME" ps
  exit 0
fi

# ─── Mode: logs ─────────────────────────────────────────────────────────
if [[ "$MODE" == "logs" ]]; then
  cd "$TARGET_DIR"
  $COMPOSE_CMD -p "$PROJECT_NAME" logs -f --tail=100
  exit 0
fi

# ─── Mode: up (default) ────────────────────────────────────────────────
cd "$TARGET_DIR"

# Check for docker-compose.yml
if [[ ! -f "docker-compose.yml" && ! -f "docker-compose.yaml" && ! -f "compose.yml" && ! -f "compose.yaml" ]]; then
  echo '{"error": "No docker-compose.yml found in '"$TARGET_DIR"'"}' >&2
  exit 1
fi

# Build if Dockerfile exists
if [[ -f "Dockerfile" ]]; then
  echo "Building Docker image..." >&2
  if ! $COMPOSE_CMD -p "$PROJECT_NAME" build 2>&1 >&2; then
    echo '{"error": "Docker build failed. Check Dockerfile and dependencies."}' >&2
    # Show last 20 lines of build output for debugging
    $COMPOSE_CMD -p "$PROJECT_NAME" build 2>&1 | tail -20 >&2
    exit 1
  fi
fi

# Start containers
echo "Starting containers..." >&2
if ! $COMPOSE_CMD -p "$PROJECT_NAME" up -d 2>&1 >&2; then
  echo '{"error": "Failed to start containers"}' >&2
  exit 1
fi

# Get the list of services
SERVICES=$($COMPOSE_CMD -p "$PROJECT_NAME" ps --services 2>/dev/null | tr '\n' ',' | sed 's/,$//')

# ─── Health check ───────────────────────────────────────────────────────
echo "Waiting for app to be ready..." >&2

# Determine app port — try to extract from compose config
MAPPED_PORT=""
for port_try in "$APP_PORT" 8080 8000 3000 5000 4000 80 443; do
  MAPPED_PORT=$($COMPOSE_CMD -p "$PROJECT_NAME" port app "$port_try" 2>/dev/null || true)
  if [[ -n "$MAPPED_PORT" ]]; then
    break
  fi
done

# If no mapped port found, try to get it from docker ps
if [[ -z "$MAPPED_PORT" ]]; then
  MAPPED_PORT=$(docker ps --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --format '{{.Ports}}' 2>/dev/null | grep -oP '0\.0\.0\.0:\K\d+' | head -1 || true)
  if [[ -n "$MAPPED_PORT" ]]; then
    MAPPED_PORT="0.0.0.0:$MAPPED_PORT"
  fi
fi

# Parse host:port from mapped port
if [[ -n "$MAPPED_PORT" ]]; then
  HOST_IP=$(echo "$MAPPED_PORT" | cut -d: -f1)
  HOST_PORT=$(echo "$MAPPED_PORT" | cut -d: -f2)

  # Replace 0.0.0.0 with localhost
  if [[ "$HOST_IP" == "0.0.0.0" ]]; then
    HOST_IP="127.0.0.1"
  fi

  # Health check loop
  ELAPSED=0
  HEALTHY=false
  while [[ $ELAPSED -lt $HEALTH_TIMEOUT ]]; do
    if curl -sf "http://${HOST_IP}:${HOST_PORT}/" -o /dev/null -m 5 2>/dev/null || \
       curl -sf "http://${HOST_IP}:${HOST_PORT}/health" -o /dev/null -m 5 2>/dev/null || \
       curl -sf "http://${HOST_IP}:${HOST_PORT}/api" -o /dev/null -m 5 2>/dev/null || \
       nc -z "$HOST_IP" "$HOST_PORT" 2>/dev/null; then
      HEALTHY=true
      break
    fi
    sleep "$HEALTH_INTERVAL"
    ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
    echo "  Waiting... (${ELAPSED}s/${HEALTH_TIMEOUT}s)" >&2
  done

  if ! $HEALTHY; then
    echo "WARNING: Health check timed out after ${HEALTH_TIMEOUT}s. Container may still be starting." >&2
    echo "Container logs:" >&2
    $COMPOSE_CMD -p "$PROJECT_NAME" logs --tail=30 2>&1 >&2
  fi
else
  HOST_IP="127.0.0.1"
  HOST_PORT="unknown"
  echo "WARNING: Could not determine app port. Check docker-compose.yml port mappings." >&2
fi

# ─── Run seed script if present ─────────────────────────────────────────
SEEDED=false
if [[ -f "seed.sh" ]]; then
  echo "Running seed script (seed.sh)..." >&2
  if $COMPOSE_CMD -p "$PROJECT_NAME" exec -T app bash /app/seed.sh 2>&1 >&2 || \
     docker cp seed.sh "$($COMPOSE_CMD -p "$PROJECT_NAME" ps -q app 2>/dev/null):/tmp/seed.sh" 2>/dev/null && \
     $COMPOSE_CMD -p "$PROJECT_NAME" exec -T app bash /tmp/seed.sh 2>&1 >&2; then
    SEEDED=true
  else
    echo "WARNING: Seed script failed. App is running but unseeded." >&2
  fi
elif [[ -f "seed.py" ]]; then
  echo "Running seed script (seed.py)..." >&2
  if docker cp seed.py "$($COMPOSE_CMD -p "$PROJECT_NAME" ps -q app 2>/dev/null):/tmp/seed.py" 2>/dev/null && \
     $COMPOSE_CMD -p "$PROJECT_NAME" exec -T app python3 /tmp/seed.py 2>&1 >&2; then
    SEEDED=true
  else
    echo "WARNING: Seed script failed." >&2
  fi
elif [[ -f "seed.js" ]]; then
  echo "Running seed script (seed.js)..." >&2
  if docker cp seed.js "$($COMPOSE_CMD -p "$PROJECT_NAME" ps -q app 2>/dev/null):/tmp/seed.js" 2>/dev/null && \
     $COMPOSE_CMD -p "$PROJECT_NAME" exec -T app node /tmp/seed.js 2>&1 >&2; then
    SEEDED=true
  else
    echo "WARNING: Seed script failed." >&2
  fi
elif [[ -f "seed.sql" ]]; then
  echo "Running seed SQL..." >&2
  # Try to find and seed the database container
  DB_CONTAINER=$($COMPOSE_CMD -p "$PROJECT_NAME" ps -q db 2>/dev/null || true)
  if [[ -n "$DB_CONTAINER" ]]; then
    # Detect DB type from compose file
    if grep -q "postgres" docker-compose.yml 2>/dev/null; then
      docker cp seed.sql "$DB_CONTAINER:/tmp/seed.sql" 2>/dev/null && \
      $COMPOSE_CMD -p "$PROJECT_NAME" exec -T db psql -U postgres -f /tmp/seed.sql 2>&1 >&2 && SEEDED=true
    elif grep -q "mysql\|mariadb" docker-compose.yml 2>/dev/null; then
      docker cp seed.sql "$DB_CONTAINER:/tmp/seed.sql" 2>/dev/null && \
      $COMPOSE_CMD -p "$PROJECT_NAME" exec -T db mysql -u root -p"${MYSQL_ROOT_PASSWORD:-root}" < /tmp/seed.sql 2>&1 >&2 && SEEDED=true
    fi
  fi
  if ! $SEEDED; then
    echo "WARNING: Could not seed database." >&2
  fi
fi

# ─── Collect DB port info ───────────────────────────────────────────────
DB_PORT=""
for db_port_try in 5432 3306 27017 6379; do
  DB_MAPPED=$($COMPOSE_CMD -p "$PROJECT_NAME" port db "$db_port_try" 2>/dev/null || true)
  if [[ -n "$DB_MAPPED" ]]; then
    DB_PORT=$(echo "$DB_MAPPED" | cut -d: -f2)
    break
  fi
done

# ─── Read credentials from .env if available ────────────────────────────
ADMIN_USER="admin"
ADMIN_PASS="admin123"
TEST_USER1="testuser1"
TEST_PASS1="test123"
TEST_USER2="testuser2"
TEST_PASS2="test123"

if [[ -f ".env" ]]; then
  # Try to read custom credentials from .env
  source <(grep -E '^(ADMIN_USER|ADMIN_PASS|TEST_USER|TEST_PASS)=' .env 2>/dev/null || true)
fi

# ─── Read custom configs from .env ──────────────────────────────────────
CUSTOM_CONFIGS="[]"
if [[ -f ".env" ]]; then
  CUSTOM_CONFIGS=$(grep -E '^(DEBUG|CORS|CSRF|NODE_ENV|FLASK_DEBUG|DJANGO_DEBUG)' .env 2>/dev/null | \
    sed 's/=/ = /' | \
    python3 -c "
import sys, json
configs = [line.strip() for line in sys.stdin if line.strip()]
print(json.dumps(configs))
" 2>/dev/null || echo "[]")
fi

# ─── Output JSON summary ───────────────────────────────────────────────
cat <<JSONEOF
{
  "status": "$( $HEALTHY && echo running || echo starting )",
  "healthy": $( $HEALTHY && echo true || echo false ),
  "app_url": "http://${HOST_IP}:${HOST_PORT}",
  "app_ip": "${HOST_IP}",
  "app_port": "${HOST_PORT}",
  "db_port": "${DB_PORT:-none}",
  "seeded": $( $SEEDED && echo true || echo false ),
  "credentials": {
    "admin": "${ADMIN_USER}:${ADMIN_PASS}",
    "user1": "${TEST_USER1}:${TEST_PASS1}",
    "user2": "${TEST_USER2}:${TEST_PASS2}"
  },
  "services": "$(echo $SERVICES)",
  "project_name": "${PROJECT_NAME}",
  "custom_configs": ${CUSTOM_CONFIGS},
  "target_dir": "${TARGET_DIR}"
}
JSONEOF
