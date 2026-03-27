#!/usr/bin/env bash
set -euo pipefail

# setup-workspace.sh — Deterministic security audit workspace setup
# Co-located with the claude-init skill that invokes it.
#
# Usage:
#   ./setup-workspace.sh --source <path> --project-dir <path> \
#     [--ip HOST] [--port PORT] [--creds user:pass] \
#     [--rules FILE] [--report-template FILE] [--threat-model FILE]

# ─── Defaults ───────────────────────────────────────────────────────────
SOURCE=""
PROJECT_DIR=""
TARGET_IP="N/A"
TARGET_PORT="N/A"
CREDENTIALS="N/A"
RULES_FILE=""
REPORT_TEMPLATE=""
THREAT_MODEL=""

# ─── Parse arguments ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)       SOURCE="$2"; shift 2 ;;
    --project-dir)  PROJECT_DIR="$2"; shift 2 ;;
    --ip)           TARGET_IP="$2"; shift 2 ;;
    --port)         TARGET_PORT="$2"; shift 2 ;;
    --creds)        CREDENTIALS="$2"; shift 2 ;;
    --rules)        RULES_FILE="$2"; shift 2 ;;
    --report-template) REPORT_TEMPLATE="$2"; shift 2 ;;
    --threat-model) THREAT_MODEL="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$SOURCE" ]]; then
  echo '{"error": "Missing required --source argument"}' >&2
  exit 1
fi

# ─── Step 1: Validate target directory ──────────────────────────────────
if [[ ! -d "$SOURCE" ]]; then
  echo "{\"error\": \"Source directory does not exist: $SOURCE\"}" >&2
  exit 1
fi

SOURCE="$(cd "$SOURCE" && pwd)"
SOURCE_NAME="$(basename "$SOURCE")"

if [[ -z "$PROJECT_DIR" ]]; then
  PROJECT_DIR="$(dirname "$SOURCE")"
fi
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

AUDIT_DIR="${PROJECT_DIR}/security_audit"

# ─── Step 2: Detect tech stack ──────────────────────────────────────────
detect_tech_stack() {
  local src="$1"
  local languages=()
  local frameworks=()
  local manifests=()

  # Count files by extension
  local py_count js_count ts_count go_count java_count php_count rb_count rs_count c_count cpp_count cs_count
  py_count=$(find "$src" -name '*.py' -not -path '*/node_modules/*' -not -path '*/.venv/*' 2>/dev/null | wc -l)
  js_count=$(find "$src" \( -name '*.js' -o -name '*.jsx' \) -not -path '*/node_modules/*' 2>/dev/null | wc -l)
  ts_count=$(find "$src" \( -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' 2>/dev/null | wc -l)
  go_count=$(find "$src" -name '*.go' -not -path '*/vendor/*' 2>/dev/null | wc -l)
  java_count=$(find "$src" -name '*.java' 2>/dev/null | wc -l)
  php_count=$(find "$src" -name '*.php' -not -path '*/vendor/*' 2>/dev/null | wc -l)
  rb_count=$(find "$src" -name '*.rb' 2>/dev/null | wc -l)
  rs_count=$(find "$src" -name '*.rs' 2>/dev/null | wc -l)
  c_count=$(find "$src" -name '*.c' 2>/dev/null | wc -l)
  cpp_count=$(find "$src" \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' \) 2>/dev/null | wc -l)
  cs_count=$(find "$src" -name '*.cs' 2>/dev/null | wc -l)

  [[ $py_count -gt 0 ]]   && languages+=("Python:$py_count")
  [[ $js_count -gt 0 ]]   && languages+=("JavaScript:$js_count")
  [[ $ts_count -gt 0 ]]   && languages+=("TypeScript:$ts_count")
  [[ $go_count -gt 0 ]]   && languages+=("Go:$go_count")
  [[ $java_count -gt 0 ]] && languages+=("Java:$java_count")
  [[ $php_count -gt 0 ]]  && languages+=("PHP:$php_count")
  [[ $rb_count -gt 0 ]]   && languages+=("Ruby:$rb_count")
  [[ $rs_count -gt 0 ]]   && languages+=("Rust:$rs_count")
  [[ $c_count -gt 0 ]]    && languages+=("C:$c_count")
  [[ $cpp_count -gt 0 ]]  && languages+=("C++:$cpp_count")
  [[ $cs_count -gt 0 ]]   && languages+=("C#:$cs_count")

  # Detect frameworks via manifests
  [[ -f "$src/package.json" ]]      && manifests+=("package.json") && frameworks+=("Node.js")
  [[ -f "$src/requirements.txt" ]]  && manifests+=("requirements.txt")
  [[ -f "$src/setup.py" ]]          && manifests+=("setup.py")
  [[ -f "$src/pyproject.toml" ]]    && manifests+=("pyproject.toml")
  [[ -f "$src/pom.xml" ]]           && manifests+=("pom.xml") && frameworks+=("Maven/Java")
  [[ -f "$src/build.gradle" ]]      && manifests+=("build.gradle") && frameworks+=("Gradle/Java")
  [[ -f "$src/go.mod" ]]            && manifests+=("go.mod") && frameworks+=("Go")
  [[ -f "$src/Cargo.toml" ]]        && manifests+=("Cargo.toml") && frameworks+=("Rust/Cargo")
  [[ -f "$src/Gemfile" ]]           && manifests+=("Gemfile") && frameworks+=("Ruby")
  [[ -f "$src/composer.json" ]]     && manifests+=("composer.json") && frameworks+=("PHP/Composer")
  [[ -f "$src/Makefile" ]]          && manifests+=("Makefile")
  [[ -f "$src/Dockerfile" ]]        && manifests+=("Dockerfile")
  [[ -f "$src/docker-compose.yml" ]] && manifests+=("docker-compose.yml")

  # Detect specific frameworks from manifest contents
  if [[ -f "$src/package.json" ]]; then
    grep -q '"express"' "$src/package.json" 2>/dev/null && frameworks+=("Express.js")
    grep -q '"@nestjs' "$src/package.json" 2>/dev/null && frameworks+=("NestJS")
    grep -q '"react"' "$src/package.json" 2>/dev/null && frameworks+=("React")
    grep -q '"next"' "$src/package.json" 2>/dev/null && frameworks+=("Next.js")
    grep -q '"fastify"' "$src/package.json" 2>/dev/null && frameworks+=("Fastify")
  fi
  if [[ -f "$src/requirements.txt" ]]; then
    grep -qi 'django' "$src/requirements.txt" 2>/dev/null && frameworks+=("Django")
    grep -qi 'flask' "$src/requirements.txt" 2>/dev/null && frameworks+=("Flask")
    grep -qi 'fastapi' "$src/requirements.txt" 2>/dev/null && frameworks+=("FastAPI")
    grep -qi 'frappe' "$src/requirements.txt" 2>/dev/null && frameworks+=("Frappe")
  fi
  if [[ -f "$src/pyproject.toml" ]]; then
    grep -qi 'django' "$src/pyproject.toml" 2>/dev/null && frameworks+=("Django")
    grep -qi 'flask' "$src/pyproject.toml" 2>/dev/null && frameworks+=("Flask")
    grep -qi 'fastapi' "$src/pyproject.toml" 2>/dev/null && frameworks+=("FastAPI")
  fi
  if [[ -f "$src/Gemfile" ]]; then
    grep -qi 'rails' "$src/Gemfile" 2>/dev/null && frameworks+=("Rails")
    grep -qi 'sinatra' "$src/Gemfile" 2>/dev/null && frameworks+=("Sinatra")
  fi
  if [[ -f "$src/composer.json" ]]; then
    grep -q '"laravel' "$src/composer.json" 2>/dev/null && frameworks+=("Laravel")
    grep -q '"symfony' "$src/composer.json" 2>/dev/null && frameworks+=("Symfony")
  fi

  # Find primary language (most files)
  local primary_lang="Unknown"
  local max_count=0
  for entry in "${languages[@]:-}"; do
    local lang="${entry%%:*}"
    local count="${entry##*:}"
    if [[ $count -gt $max_count ]]; then
      max_count=$count
      primary_lang=$lang
    fi
  done

  local total_files
  total_files=$(find "$src" -type f -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/vendor/*' 2>/dev/null | wc -l)

  # Output as JSON-compatible values
  echo "DETECTED_LANGUAGE=${primary_lang}"
  echo "DETECTED_LANGUAGES=$(IFS=,; echo "${languages[*]:-}")"
  echo "DETECTED_FRAMEWORKS=$(IFS=,; echo "${frameworks[*]:-}")"
  echo "DETECTED_MANIFESTS=$(IFS=,; echo "${manifests[*]:-}")"
  echo "TOTAL_FILES=${total_files}"
}

TECH_OUTPUT=$(detect_tech_stack "$SOURCE")
eval "$TECH_OUTPUT"

# ─── Step 3: Install semgrep if missing ─────────────────────────────────
SEMGREP_VERSION="not installed"
if command -v semgrep &>/dev/null; then
  SEMGREP_VERSION=$(semgrep --version 2>/dev/null || echo "installed (version unknown)")
else
  echo "Installing semgrep..." >&2
  if [[ -d "/home/kali/.venv" ]]; then
    source /home/kali/.venv/bin/activate 2>/dev/null || true
  fi
  if command -v pipx &>/dev/null; then
    pipx install semgrep 2>&1 >&2 || pip3 install semgrep 2>&1 >&2 || true
  else
    pip3 install semgrep 2>&1 >&2 || true
  fi
  if command -v semgrep &>/dev/null; then
    SEMGREP_VERSION=$(semgrep --version 2>/dev/null || echo "installed")
  else
    echo "WARNING: semgrep installation failed" >&2
  fi
fi

# ─── Step 4: Install gitnexus if missing ────────────────────────────────
GITNEXUS_STATUS="not installed"
if command -v gitnexus &>/dev/null; then
  GITNEXUS_STATUS="already installed"
else
  echo "Installing gitnexus..." >&2
  npm install -g gitnexus 2>&1 >&2 || true
  if command -v gitnexus &>/dev/null; then
    GITNEXUS_STATUS="installed"
  else
    echo "WARNING: gitnexus installation failed" >&2
    GITNEXUS_STATUS="failed"
  fi
fi

# ─── Step 5: Index codebase with gitnexus ───────────────────────────────
GITNEXUS_INDEX="skipped"
if command -v gitnexus &>/dev/null; then
  echo "Indexing codebase with gitnexus..." >&2
  if gitnexus index "$SOURCE" 2>&1 >&2; then
    GITNEXUS_INDEX="success"
  else
    echo "WARNING: gitnexus indexing failed" >&2
    GITNEXUS_INDEX="failed"
  fi
fi

# ─── Step 6: Configure gitnexus MCP server ──────────────────────────────
MCP_CONFIG="${PROJECT_DIR}/.mcp.json"
if command -v gitnexus &>/dev/null; then
  GITNEXUS_PATH=$(command -v gitnexus)
  if [[ -f "$MCP_CONFIG" ]]; then
    # Merge gitnexus into existing .mcp.json using python
    python3 -c "
import json, sys
with open('$MCP_CONFIG', 'r') as f:
    config = json.load(f)
config.setdefault('mcpServers', {})
config['mcpServers']['gitnexus'] = {
    'command': '$GITNEXUS_PATH',
    'args': ['mcp', '--project', '$SOURCE']
}
with open('$MCP_CONFIG', 'w') as f:
    json.dump(config, f, indent=2)
" 2>/dev/null || true
  else
    cat > "$MCP_CONFIG" <<MCPEOF
{
  "mcpServers": {
    "gitnexus": {
      "command": "$GITNEXUS_PATH",
      "args": ["mcp", "--project", "$SOURCE"]
    }
  }
}
MCPEOF
  fi
fi

# ─── Step 7: Create workspace directories ───────────────────────────────
mkdir -p "${AUDIT_DIR}"/{recon,findings,logs}

# ─── Step 8: Generate CLAUDE.md from template ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/claude-md-template.md"

if [[ -f "$TEMPLATE" ]]; then
  # Classify system type
  CLASSIFIED_TYPE="Web API"
  if echo "$DETECTED_FRAMEWORKS" | grep -qi "django\|flask\|fastapi\|express\|nestjs\|rails\|laravel\|fastify"; then
    CLASSIFIED_TYPE="Web API"
  fi
  if echo "$DETECTED_FRAMEWORKS" | grep -qi "react\|next"; then
    CLASSIFIED_TYPE="Web Application"
  fi

  # Read priority focus
  PRIORITY_FILE="${SCRIPT_DIR}/priority-focus.md"
  PRIORITY_SECTION=""
  if [[ -f "$PRIORITY_FILE" ]]; then
    # Extract the section matching the classified type
    PRIORITY_SECTION=$(awk -v type="$CLASSIFIED_TYPE" '
      /^## / { found=0 }
      $0 ~ type { found=1; next }
      found && /^## / { found=0 }
      found { print }
    ' "$PRIORITY_FILE" | head -20)
  fi
  if [[ -z "$PRIORITY_SECTION" ]]; then
    # Default to Web API priority
    PRIORITY_SECTION=$(awk '/^## Web API/,/^## [^W]/' "$PRIORITY_FILE" 2>/dev/null | tail -n +2 | head -20)
  fi

  # Generate CLAUDE.md
  sed \
    -e "s|{target_source}|${SOURCE}|g" \
    -e "s|{source_name}|${SOURCE_NAME}|g" \
    -e "s|{project_dir}|${PROJECT_DIR}|g" \
    -e "s|{target_ip}|${TARGET_IP}|g" \
    -e "s|{target_port}|${TARGET_PORT}|g" \
    -e "s|{credentials}|${CREDENTIALS}|g" \
    -e "s|{detected_language}|${DETECTED_LANGUAGE}|g" \
    -e "s|{detected_framework}|${DETECTED_FRAMEWORKS}|g" \
    -e "s|{classified_type}|${CLASSIFIED_TYPE}|g" \
    -e "s|{system_description}|Security audit target|g" \
    -e "s|{key_features}|See source code analysis|g" \
    "$TEMPLATE" > "${PROJECT_DIR}/CLAUDE.md"

  # Append priority section (can't do multiline with sed easily)
  if [[ -n "$PRIORITY_SECTION" ]]; then
    sed -i "s|{priority_section}|${PRIORITY_SECTION%%$'\n'*}|g" "${PROJECT_DIR}/CLAUDE.md"
  else
    sed -i "s|{priority_section}|See priority-focus.md for details|g" "${PROJECT_DIR}/CLAUDE.md"
  fi

  # Append gitnexus section to CLAUDE.md
  cat >> "${PROJECT_DIR}/CLAUDE.md" <<'GITNEXUSEOF'

## Code Intelligence

- gitnexus MCP server configured for source-to-sink flow queries
- Use gitnexus to trace data flows across modules and identify cross-file chains
- Query gitnexus for call graphs, data flow paths, and symbol references
GITNEXUSEOF
else
  echo "WARNING: CLAUDE.md template not found at $TEMPLATE" >&2
fi

# ─── Step 9: Copy user-provided files ───────────────────────────────────
if [[ -n "$RULES_FILE" && -f "$RULES_FILE" ]]; then
  cp "$RULES_FILE" "${PROJECT_DIR}/RULES.md"
fi

if [[ -n "$REPORT_TEMPLATE" && -f "$REPORT_TEMPLATE" ]]; then
  cp "$REPORT_TEMPLATE" "${PROJECT_DIR}/REPORT.md"
fi

if [[ -n "$THREAT_MODEL" && -f "$THREAT_MODEL" ]]; then
  cp "$THREAT_MODEL" "${AUDIT_DIR}/recon/threat-model-input.md"
fi

# ─── Step 10: Write initialization log ──────────────────────────────────
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
cat > "${AUDIT_DIR}/logs/orchestrator.log" <<LOGEOF
[$TIMESTAMP] INIT: Security audit initialized
[$TIMESTAMP] TARGET: $SOURCE
[$TIMESTAMP] LIVE_TARGET: ${TARGET_IP}:${TARGET_PORT}
[$TIMESTAMP] DETECTED: Language=$DETECTED_LANGUAGE, Frameworks=$DETECTED_FRAMEWORKS, Type=$CLASSIFIED_TYPE
[$TIMESTAMP] WORKSPACE: $AUDIT_DIR
[$TIMESTAMP] SEMGREP: $SEMGREP_VERSION
[$TIMESTAMP] GITNEXUS: $GITNEXUS_STATUS (index: $GITNEXUS_INDEX)
[$TIMESTAMP] STATUS: Ready for security audit
LOGEOF

# ─── Step 11: Output JSON summary ───────────────────────────────────────
cat <<JSONEOF
{
  "status": "success",
  "source": "$SOURCE",
  "source_name": "$SOURCE_NAME",
  "project_dir": "$PROJECT_DIR",
  "audit_dir": "$AUDIT_DIR",
  "target_ip": "$TARGET_IP",
  "target_port": "$TARGET_PORT",
  "credentials": "$CREDENTIALS",
  "detected_language": "$DETECTED_LANGUAGE",
  "detected_languages": "$DETECTED_LANGUAGES",
  "detected_frameworks": "$DETECTED_FRAMEWORKS",
  "detected_manifests": "$DETECTED_MANIFESTS",
  "classified_type": "$CLASSIFIED_TYPE",
  "total_files": "$TOTAL_FILES",
  "semgrep_version": "$SEMGREP_VERSION",
  "gitnexus_status": "$GITNEXUS_STATUS",
  "gitnexus_index": "$GITNEXUS_INDEX",
  "claude_md": "${PROJECT_DIR}/CLAUDE.md",
  "mcp_config": "$MCP_CONFIG",
  "rules_copied": "$( [[ -n "$RULES_FILE" ]] && echo true || echo false )",
  "report_template_copied": "$( [[ -n "$REPORT_TEMPLATE" ]] && echo true || echo false )",
  "threat_model_copied": "$( [[ -n "$THREAT_MODEL" ]] && echo true || echo false )"
}
JSONEOF
