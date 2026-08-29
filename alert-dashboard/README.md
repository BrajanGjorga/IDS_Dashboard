# Intrusion Alert Dashboard

A FastAPI service that receives authenticated intrusion-detection alerts, stores them in PostgreSQL, and gives each user a private dashboard for their registered servers.

For hosted deployment, see [Deploying the Network Monitoring Dashboard on Render](RENDER_DEPLOYMENT_GUIDE.md). The repository includes a Render Blueprint that creates the web service and PostgreSQL database.

The ownership model is intentionally small:

```text
User -> many Servers -> many Alerts
```

There are no organizations, roles, teams, subscriptions, or invitations.

## Features

- Username and email registration with signed, HTTP-only session cookies
- Salted `scrypt` password hashes; passwords are never stored in plaintext
- Multiple registered servers per user
- A cryptographically random API token for every server
- Only a SHA-256 token hash is stored; plaintext appears once after registration
- Bearer-authenticated `POST /api/alerts` ingestion
- Per-user dashboard totals, filters, alert details, API reads, and acknowledgements
- Server disable control and `last_seen_at` tracking
- PostgreSQL through SQLAlchemy, including complete flow payloads in `JSONB`
- Alembic migrations and rotating application logs

## Project layout

```text
alert-dashboard/
|-- alembic/
|   |-- versions/
|   |   |-- 0001_create_alerts.py
|   |   |-- 0002_add_users_and_servers.py
|   |   `-- 0003_add_usernames.py
|   |-- env.py
|   `-- script.py.mako
|-- app/
|   |-- static/styles.css
|   |-- templates/
|   |   |-- alert_detail.html
|   |   |-- base.html
|   |   |-- dashboard.html
|   |   |-- login.html
|   |   |-- register.html
|   |   |-- register_server.html
|   |   |-- server_created.html
|   |   `-- servers.html
|   |-- config.py
|   |-- database.py
|   |-- logging_config.py
|   |-- main.py
|   |-- models.py
|   |-- schemas.py
|   |-- security.py
|   `-- services.py
|-- tests/
|   |-- conftest.py
|   `-- test_alerts.py
|-- .env.example
|-- alembic.ini
|-- pytest.ini
|-- requirements-dev.txt
`-- requirements.txt
```

## Setup

Prerequisites are Python 3.11 or newer and a reachable PostgreSQL instance.

From `alert-dashboard/`, create the environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Linux/macOS activation is `source .venv/bin/activate`.

### Create PostgreSQL database

Create the database manually as a PostgreSQL administrator, choosing a strong password:

```sql
CREATE USER alert_dashboard WITH PASSWORD 'replace-with-a-strong-password';
CREATE DATABASE alert_dashboard OWNER alert_dashboard;
```

### Configure `.env`

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value in `SESSION_SECRET` and configure the database:

```dotenv
DB_HOST=localhost
DB_PORT=5432
DB_NAME=alert_dashboard
DB_USER=alert_dashboard
DB_PASSWORD=replace-with-your-real-password
APP_HOST=0.0.0.0
APP_PORT=8001
LOG_LEVEL=INFO
SESSION_SECRET=replace-with-the-generated-random-value
SESSION_HTTPS_ONLY=false
```

Set `SESSION_HTTPS_ONLY=true` when serving the dashboard over HTTPS. Do not commit `.env`; it is ignored by Git.

### Apply database migrations

For a new or existing dashboard database, run:

```powershell
alembic upgrade head
```

Migration `0002` creates `users` and `servers`, then adds the indexed, nullable `alerts.server_id` foreign key. Migration `0003` adds unique usernames and safely backfills existing accounts from their email prefix. Existing alerts keep `server_id = NULL` because their old `server_name` text was unauthenticated and cannot safely establish ownership. They remain in PostgreSQL but are excluded from user dashboards. Every newly accepted alert receives an authenticated server ID.

### Start the dashboard

```powershell
python -m app
```

Open `http://127.0.0.1:8001/`. API documentation is at `/docs` and health status is at `/health`.

## Register a user and server

1. Open `/register` and create an account with a username, email, and password.
2. Select **Register server**.
3. Enter a recognizable server name.
4. Copy the generated API token from the confirmation page.
5. Store it immediately; the dashboard stores only its hash and cannot show it again.
6. On that monitored server, set `PREDICTION_AGENT_API_TOKEN` to the copied token.

The **Servers** page lists only the logged-in user's servers. It provides per-server alert links and a disable action. A disabled server's token receives HTTP `403` on ingestion.

## Configure a prediction agent

Set its endpoint in `prediction-agent/config.json`:

```json
"alert_endpoint_url": "http://<dashboard-server-ip>:8001/api/alerts"
```

Set the generated token on that machine without putting it in `config.json`.

Linux shell:

```bash
export PREDICTION_AGENT_API_TOKEN='paste-the-generated-token-here'
```

PowerShell:

```powershell
$env:PREDICTION_AGENT_API_TOKEN = "paste-the-generated-token-here"
```

For a long-running service, place the variable in the service manager's protected environment configuration. Ensure it is available both for normal prediction delivery and later queued-alert retries.

The prediction agent now reports a configuration error and refuses to send if this variable is missing.

## Expected alert request

The JSON contract is unchanged. Ownership comes only from the bearer token, never from `server_name`, `server_id`, or `user_id` in the body.

```http
POST /api/alerts HTTP/1.1
Host: dashboard.example:8001
Authorization: Bearer <server-api-token>
Content-Type: application/json

{
  "event_id": "unique-event-id",
  "server_name": "monitored-server-1",
  "timestamp": "2026-08-21T12:30:00Z",
  "prediction": "MALICIOUS",
  "predicted_label": "MALICIOUS",
  "confidence": 0.99,
  "source_csv": "capture.pcap_Flow.csv",
  "model_version": null,
  "flow": {}
}
```

Example with curl:

```powershell
curl.exe -X POST "http://127.0.0.1:8001/api/alerts" `
  -H "Authorization: Bearer paste-the-generated-token-here" `
  -H "Content-Type: application/json" `
  -d '{"event_id":"manual-test-001","server_name":"body-name-is-not-trusted","timestamp":"2026-08-21T12:30:00Z","prediction":"MALICIOUS","predicted_label":"MALICIOUS","confidence":0.99,"flow":{}}'
```

Responses:

- Missing or invalid bearer token: HTTP `401`
- Disabled server: HTTP `403`
- First accepted event: HTTP `201`, `created: true`
- Same `event_id` retried by the same server: HTTP `200`, `created: false`
- Same `event_id` presented by another server: HTTP `409`

## User-facing API access

`GET /api/alerts`, `GET /api/alerts/{id}`, and acknowledgement endpoints require a logged-in browser session and are restricted to the user's own servers. Changing an ID does not bypass ownership checks; inaccessible objects return `404`.

Supported list filters include `server_id`, `server_name`, `prediction`, `acknowledged`, `start`, `end`, `limit`, and `offset`.

## Tests

Install test dependencies and run from `alert-dashboard/`:

```powershell
pip install -r requirements-dev.txt
pytest
```

The tests use temporary SQLite databases and do not use `.env` or real PostgreSQL credentials. Passing them does not prove live PostgreSQL connectivity. Verify PostgreSQL separately with `alembic upgrade head` and `/health`.

## Operational notes

- Application logs are written to `logs/alert-dashboard.log`, rotated at 10 MB with five backups, and also sent to the console.
- Use HTTPS in production because bearer tokens must be protected in transit.
- Session cookies are HTTP-only, use `SameSite=Lax`, and last eight hours.
- Back up PostgreSQL according to your alert retention requirements.
