---
name: setup-target
description: Create a Docker Compose testing environment from the target source code. Builds from existing Dockerfiles, public images, or source code. Seeds test data, applies custom security configurations, and auto-updates CLAUDE.md with live target info for PoC execution. Use before or after the orchestrator to get a live target for testing.
argument-hint: "[custom config description, e.g. 'debug mode enabled, weak CORS, PostgreSQL 13.2']"
user-invocable: true
---

# Setup Target — Testing Environment Creator

## Goal

Create a live, configurable Docker Compose testing environment from the target source code. This enables:
- Executing PoCs against real targets (verify CONFIRMED-THEORETICAL findings)
- Testing with intentionally weakened security configs (technique development)
- Reproducing specific conditions for hypothesis testing during iterative audits

## When to Use

- **Before orchestrator**: Set up a live target so the audit has dynamic testing from the start
- **After orchestrator**: Spin up the app to verify theoretical findings with real PoC execution
- **During iterative-audit**: Test specific hypotheses with custom configurations
- **Standalone**: Technique development with intentionally vulnerable configs

## Inputs

- `TARGET_SOURCE`: From CLAUDE.md or user input — path to source code
- `AUDIT_DIR`: From CLAUDE.md — path to audit workspace (optional, creates `./target-env/` if missing)
- `$ARGUMENTS`: Optional free-text describing desired state (e.g., "debug mode enabled, weak CORS, PostgreSQL 13.2")
- Recon artifacts (optional, enhances seeding): `intelligence.md`, `architecture.md`

---

## Step 1: Gather Context

Read CLAUDE.md for TARGET_SOURCE and AUDIT_DIR paths.

If CLAUDE.md doesn't exist:
- Ask user: "Where is the target source code?"
- Set AUDIT_DIR to `{parent_of_source}/security_audit`
- Create AUDIT_DIR if it doesn't exist

If recon artifacts exist, read:
- `{AUDIT_DIR}/recon/intelligence.md` — tech stack, versions, database, framework
- `{AUDIT_DIR}/recon/architecture.md` — endpoints, role model, auth flows

Parse `$ARGUMENTS` for custom configuration requests. If the user's request is unclear, ask a follow-up question.

---

## Step 2: Analyze Source & Determine Image Strategy

Determine the best way to containerize the target. Check in this priority order:

### 2a: Check for Existing Docker Artifacts in Source

```bash
ls ${TARGET_SOURCE}/Dockerfile ${TARGET_SOURCE}/docker-compose.yml ${TARGET_SOURCE}/docker-compose.yaml \
   ${TARGET_SOURCE}/compose.yml ${TARGET_SOURCE}/compose.yaml 2>/dev/null
```

If found:
- **Use the existing docker-compose.yml as the base** — copy to target-env/
- If only a Dockerfile exists: generate a docker-compose.yml that uses it
- Apply custom config overrides on top via `.env` and `docker-compose.override.yml`

### 2b: Check for Public Docker Images

If no Docker artifacts in source:

```
WebSearch: "{project_name} docker image site:hub.docker.com OR site:ghcr.io"
WebSearch: "{project_name} official docker"
```

Look for:
- Official images on Docker Hub (e.g., `frappe/erpnext`, `keycloak/keycloak`)
- GitHub Container Registry images (ghcr.io)
- Community-maintained images

If found:
- Use the public image in docker-compose.yml
- Mount source code for config overrides if needed
- Add required services (DB, cache) based on image documentation

### 2c: Build from Source (Fallback)

If no existing artifacts and no public images:

1. Detect primary language and framework from manifests and file extensions
2. Find the application entry point:
   - Python: `manage.py`, `app.py`, `wsgi.py`, `main.py`
   - Node: `server.js`, `index.js`, `app.js` (check `package.json` "main" or "start" script)
   - Go: `main.go`, `cmd/server/main.go`
   - Java: `src/main/java/**/Application.java`, `pom.xml` (Spring Boot)
   - PHP: `public/index.php`, `artisan` (Laravel)
   - Ruby: `config.ru`, `bin/rails`
3. Read dependency manifest to determine runtime version
4. Generate Dockerfile:
   ```dockerfile
   FROM {runtime}:{version}
   WORKDIR /app
   COPY {manifest} .
   RUN {install_deps_command}
   COPY . .
   EXPOSE {port}
   CMD {start_command}
   ```
5. Identify required services from source code:
   - Database: check config files, ORM settings, connection strings
   - Cache: check for Redis/Memcached usage
   - Queue: check for RabbitMQ/Kafka/Celery usage

---

## Step 3: Generate Docker Artifacts

Create `{AUDIT_DIR}/target-env/` directory and write:

### docker-compose.yml

```yaml
version: "3.8"
services:
  app:
    build: .  # or image: official/image:tag
    ports:
      - "${APP_PORT:-8080}:${INTERNAL_PORT:-8080}"
    env_file: .env
    depends_on:
      db:
        condition: service_healthy  # if db has healthcheck
    restart: unless-stopped

  db:
    image: postgres:15  # or mysql:8, mongo:7, etc.
    environment:
      POSTGRES_DB: testdb
      POSTGRES_USER: testuser
      POSTGRES_PASSWORD: testpass
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U testuser"]
      interval: 5s
      timeout: 5s
      retries: 5

  # Add redis, elasticsearch, etc. as detected
```

Adapt based on what was detected in Step 2.

### .env

```bash
# Database
DATABASE_URL=postgresql://testuser:testpass@db:5432/testdb
DB_HOST=db
DB_PORT=5432
DB_USER=testuser
DB_PASSWORD=testpass
DB_NAME=testdb

# App
SECRET_KEY=insecure-test-key-do-not-use-in-production
DEBUG=True
ALLOWED_HOSTS=*

# Test credentials for seeding
ADMIN_USER=admin
ADMIN_PASS=admin123
TEST_USER1=testuser1
TEST_PASS1=test123
TEST_USER2=testuser2
TEST_PASS2=test123
```

### Seed Script

Generate `seed.sh` (or `seed.py` / `seed.js` depending on framework):

**If architecture.md exists** — read the role model and create accounts matching detected roles:

| Role | Username | Password | Purpose |
|---|---|---|---|
| Admin | admin | admin123 | Privilege escalation testing |
| User A | testuser1 | test123 | IDOR testing (owns objects 1-5) |
| User B | testuser2 | test123 | IDOR testing (owns objects 6-10) |
| {other roles} | {role}user | test123 | One per detected role |

**If no recon artifacts** — create minimal accounts: admin + two regular users.

Create sample data objects owned by different users for cross-user access testing.

**Framework-specific seeding approach:**

| Framework | Seed Method |
|---|---|
| Django | Generate `seed.py` using Django ORM, run via `python manage.py shell < seed.py` |
| Rails | Generate `seed.rb`, run via `rails runner seed.rb` |
| Express/Node | Generate `seed.js`, run via `node seed.js` |
| Spring Boot | Generate `seed.sql`, mount to DB container init |
| Laravel | Generate seeder, run via `php artisan db:seed` |
| Flask | Generate `seed.py` using SQLAlchemy, run via `flask shell < seed.py` |
| Go | Generate `seed.sql`, load into DB container |

---

## Step 4: Apply Custom Configurations

If the user provided custom config in `$ARGUMENTS`, apply overrides:

| User Request | Action |
|---|---|
| "debug mode" | Set: `DEBUG=True`, `DJANGO_DEBUG=True`, `NODE_ENV=development`, `FLASK_DEBUG=1`, `spring.profiles.active=dev` (framework-specific) |
| "weak CORS" | Set: `CORS_ALLOW_ALL_ORIGINS=True`, `CORS_ALLOW_CREDENTIALS=True`, `ACCESS_CONTROL_ALLOW_ORIGIN=*` |
| "no CSRF" / "disable CSRF" | Disable CSRF middleware via env var or config override |
| "PostgreSQL 13.2" / specific version | Pin DB image: `postgres:13.2` in docker-compose.yml |
| "no rate limiting" | Set rate limit to very high values or disable middleware |
| "verbose errors" | Enable detailed error pages (stack traces, debug info) |
| "specific feature flag" | Set the flag in .env |

Write overrides to `.env`. If structural changes are needed (different DB, extra services), modify `docker-compose.yml` directly.

If the user's request needs clarification, ask a specific follow-up question.

---

## Step 5: Run Deploy Script

```bash
bash SKILL_DIR/deploy-target.sh \
  --dir ${AUDIT_DIR}/target-env/ \
  --project-name security-audit \
  --app-port ${DETECTED_PORT}
```

The script path is the same directory as this SKILL.md file. Use the absolute path based on the plugin location.

Parse the JSON output to get:
- `app_url`, `app_ip`, `app_port` — for CLAUDE.md
- `credentials` — for CLAUDE.md
- `healthy` — to verify the app started
- `seeded` — to confirm test data was created
- `services` — for the summary

If the script reports an error, show it to the user with diagnostic suggestions.

---

## Step 6: Update CLAUDE.md

After containers are running successfully, update CLAUDE.md:

1. **Update Live Target section:**
   - Set `{target_ip}` to the app IP (typically `127.0.0.1`)
   - Set `{target_port}` to the mapped port
   - Set `{credentials}` to `admin:admin123` (or custom)

2. **Add Testing Environment section** (append to CLAUDE.md):

```markdown
## Testing Environment

- **Docker project**: security-audit
- **App URL**: http://localhost:{port}
- **Services**: {app, db, redis, ...}
- **Image source**: {existing Dockerfile / Docker Hub: image:tag / built from source}
- **Test accounts**:
  - admin:admin123 (admin role)
  - testuser1:test123 (regular user, owns objects 1-5)
  - testuser2:test123 (regular user, owns objects 6-10)
- **Custom configs**: {list of applied overrides, or "default"}
- **Manage**:
  - Stop: `/security-research:setup-target` with "stop" or "down"
  - Status: `/security-research:setup-target` with "status"
  - Logs: `/security-research:setup-target` with "logs"
  - Rebuild: `/security-research:setup-target` with "rebuild" or new config
```

---

## Step 7: Display Summary

```
TESTING ENVIRONMENT READY
═══════════════════════════════════════════
App URL:       http://localhost:{port}
Image Source:  {existing Dockerfile / Docker Hub: image:tag / built from source}
Services:      {app, db, redis, ...}
Healthy:       {yes / starting (check logs)}

Test Accounts:
  admin:admin123 (admin)
  testuser1:test123 (user, owns objects 1-5)
  testuser2:test123 (user, owns objects 6-10)

Custom Configs:
  {DEBUG=True, CORS=permissive, ... or "default"}

Seeded:        {yes / no / partial}
CLAUDE.md:     Updated with live target info

Next Steps:
  - /security-research:verify-finding   → Execute PoCs against the live target
  - /security-research:security-orchestrator → Run audit with live target
  - /security-research:iterative-audit  → Test hypotheses against live target
  - "stop" or "down"                     → Stop and clean up containers
  - "logs"                               → View container logs
  - "status"                             → Check container status
═══════════════════════════════════════════
```

---

## Lifecycle Management

When the user invokes this skill with lifecycle commands (instead of setup):

| User says | Action |
|---|---|
| "stop" / "down" | Run `deploy-target.sh --down` — stop and remove all containers + volumes |
| "status" | Run `deploy-target.sh --status` — show running containers |
| "logs" | Run `deploy-target.sh --logs` — tail container logs |
| "rebuild" / new config | Stop existing, regenerate artifacts with new config, redeploy |

Detect the intent from `$ARGUMENTS`. If it matches a lifecycle command, run the script in the appropriate mode instead of the full setup procedure.

---

## Error Handling

| Condition | Action |
|---|---|
| Docker not installed | Show install link, stop |
| Docker daemon not running | Show start command, stop |
| CLAUDE.md missing + no user input | Ask user for source code path |
| No Dockerfile, no public image, undetectable framework | Ask user: "How do you normally run this app?" and generate Docker artifacts from their answer |
| Build fails | Show build output, suggest fixes (missing deps, wrong base image, port) |
| Health check timeout | Show container logs, suggest checking entry point or port config |
| Seed script fails | Warn but continue — app is running, just unseeded |
| Port already in use | Try next available port (8081, 8082, ...), update CLAUDE.md accordingly |
| Containers already running | Ask: "Containers from a previous run are still active. Stop and recreate, or keep existing?" |
