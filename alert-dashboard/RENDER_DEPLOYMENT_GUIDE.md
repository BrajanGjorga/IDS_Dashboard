# Deploying the Network Monitoring Dashboard on Render

This guide deploys the FastAPI dashboard and a PostgreSQL database to Render. The repository includes a `render.yaml` Blueprint at the Git repository root, so the recommended deployment creates and connects both resources automatically.

Last verified against Render's documentation: August 28, 2026.

## What the included Blueprint creates

The repository-root `render.yaml` creates:

- a Python web service named `aegis-ids-dashboard`;
- a PostgreSQL database named `aegis-ids-database`;
- both resources in Render's Frankfurt region;
- a private `DATABASE_URL` link from the web service to PostgreSQL;
- a Render-generated `SESSION_SECRET`;
- HTTPS-only session cookies;
- an HTTP health check at `/health`; and
- automatic Alembic migrations before Uvicorn starts.

The Blueprint currently selects Render's Free instance type for both resources so it can be tested without choosing a paid instance. Read [Production versus free-tier deployment](#production-versus-free-tier-deployment) before storing important alerts.

## Files prepared for Render

### Repository-root `render.yaml`

Render reads this file to create the web service and database. The important commands are:

```text
Build: pip install -r requirements.txt
Start: alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT
Health check: /health
Root directory: alert-dashboard
```

`$PORT` is supplied by Render. Do not replace it with port `8001` in the Render start command.

### Repository-root `.python-version`

This pins the service to Python 3.13. Without a version file or `PYTHON_VERSION` environment variable, Render uses its current platform default, which can change.

### `app/config.py`

Render provides database connection strings beginning with `postgresql://`. The application converts that scheme to `postgresql+psycopg://` so SQLAlchemy uses the installed Psycopg 3 driver. The application also accepts local SQLite URLs unchanged for tests.

## Prerequisites

Before opening Render:

1. Create a GitHub, GitLab, or Bitbucket repository for this project. The current configured Git remote is the GitHub repository `BrajanGjorga/Network_Monitoring_Dashboard`.
2. Commit all deployment files and application changes.
3. Push the commit to the branch you intend to deploy, normally `main`.
4. Confirm that `.env` is not committed. It can contain local database credentials and must remain private.
5. Create a Render account and connect it to the Git provider that hosts the repository.

### Important credential cleanup

An earlier version of `app/config.py` contained a database password as a source-code default. The current version removes it, but removing a secret from the latest file does not erase it from Git history. If that value was ever used by a real PostgreSQL user, rotate that user's password before deployment and update any local `.env` file that connects with it. Render generates a separate database credential automatically; never reuse the old value on Render.

From `C:\Users\bryan\Network_Monitoring_Dashboard`, a typical Git workflow is:

```powershell
git status
git add .python-version render.yaml alert-dashboard
git commit -m "Add Render deployment configuration and guide"
git push origin main
```

Review `git status` and the staged diff before committing. Do not add `alert-dashboard/.env`.

## Recommended deployment: Render Blueprint

1. Sign in at [dashboard.render.com](https://dashboard.render.com/).
2. Select **New** and then **Blueprint**.
3. Connect the `Network_Monitoring_Dashboard` repository. Grant Render repository access if prompted.
4. Select the deployment branch, normally `main`.
5. Render should find `render.yaml` at the repository root automatically.
6. Enter a Blueprint name such as `aegis-ids-dashboard`.
7. Review the two proposed resources:
   - web service: `aegis-ids-dashboard`;
   - PostgreSQL: `aegis-ids-database`.
8. Select **Deploy Blueprint** or **Apply**.
9. Wait for PostgreSQL creation, dependency installation, migrations, and web-service startup to complete.
10. Open the web service's **Logs** page. A successful first deployment should show Alembic upgrading through revision `0003`, followed by Uvicorn starting without an exception.

The Blueprint supplies every required environment variable. You should not paste a database password or connection string into the repository.

## Environment variables on the web service

After deployment, open the web service and select **Environment**. Confirm these variables exist:

| Variable | Required value/source | Purpose |
|---|---|---|
| `DATABASE_URL` | From `aegis-ids-database`, property `connectionString` | Uses Render's internal PostgreSQL address. |
| `SESSION_SECRET` | Render-generated secret | Signs login session cookies. Keep this value stable and private. |
| `SESSION_HTTPS_ONLY` | `true` | Sends login cookies only over HTTPS. |
| `LOG_LEVEL` | `INFO` | Sets normal production logging verbosity. |

Do not add `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, or `DB_PASSWORD` on Render when `DATABASE_URL` is present. `DATABASE_URL` takes precedence in the application.

Render automatically provides `PORT`; do not create or hardcode it yourself.

## Verify the deployment

Render shows the public address near the top of the web-service page. It will look similar to:

```text
https://aegis-ids-dashboard.onrender.com
```

The exact subdomain can differ if that name is already taken.

### 1. Check application and database health

Open:

```text
https://YOUR-RENDER-HOSTNAME.onrender.com/health
```

Expected response:

```json
{
  "status": "healthy",
  "application": "running",
  "database": "available"
}
```

The endpoint executes `SELECT 1`, so a healthy response checks both the FastAPI process and its database connection.

### 2. Create the dashboard account

1. Open `https://YOUR-RENDER-HOSTNAME.onrender.com/register`.
2. Create the first user account with a strong, unique password.
3. Sign in and confirm the Alerts page loads.

This application intentionally has public user registration. If only you should be able to create accounts, disable or protect registration before sharing the public URL.

### 3. Register the monitored server

1. Open **Manage servers**.
2. Select **Register server**.
3. Give the server a recognizable name.
4. Copy the generated API token immediately. It is shown once; only its SHA-256 hash is stored.

### 4. Configure the prediction agent

Set its public ingestion endpoint to:

```text
https://YOUR-RENDER-HOSTNAME.onrender.com/api/alerts
```

Set the token copied during server registration in the prediction agent's protected environment:

```text
PREDICTION_AGENT_API_TOKEN=the-generated-server-token
```

Do not put this token in Git or in a public configuration file. Every monitored server should have its own registered server record and token.

### 5. Send a test alert

PowerShell example:

```powershell
$renderUrl = "https://YOUR-RENDER-HOSTNAME.onrender.com"
$serverToken = "PASTE-THE-SERVER-TOKEN"
$eventId = "render-test-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
$body = @{
    event_id = $eventId
    timestamp = [DateTime]::UtcNow.ToString("o")
    prediction = "MALICIOUS"
    predicted_label = "MALICIOUS"
    confidence = 0.99
    flow = @{
        source_ip = "192.0.2.10"
        destination_ip = "198.51.100.20"
        protocol = 6
    }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod `
    -Method Post `
    -Uri "$renderUrl/api/alerts" `
    -Headers @{ Authorization = "Bearer $serverToken" } `
    -ContentType "application/json" `
    -Body $body
```

The first accepted event should return `created: true`. Refresh the dashboard and confirm that the event is visible under the registered server.

## Manual Render Dashboard setup

Use this only if you do not want to deploy the included Blueprint.

### 1. Create PostgreSQL

In Render, select **New > Postgres** and use:

| Field | Value |
|---|---|
| Name | `network-monitoring-database` |
| Database | `network_monitoring` |
| User | `network_monitoring` |
| Region | `Frankfurt` |
| PostgreSQL version | Render default |
| Instance type | Free for temporary testing; paid Basic or higher for durable use |

Create the database. In its networking settings, disable public/external access unless you specifically need to connect from outside Render. The web service can still use the private connection when both resources are in the same region.

### 2. Create the web service

Select **New > Web Service**, connect the repository, and enter:

| Field | Value |
|---|---|
| Name | `network-monitoring-dashboard` |
| Language/runtime | `Python 3` |
| Branch | `main` or your deployment branch |
| Region | `Frankfurt`, matching PostgreSQL |
| Root Directory | `alert-dashboard` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/health` |
| Instance type | Free for testing; paid Starter or higher for production |

Add the four environment variables listed earlier. For `DATABASE_URL`, use the database's **Internal Database URL**, not its external URL. Generate `SESSION_SECRET` in Render or locally with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Do not surround environment-variable values with extra quotation marks in Render's value fields.

### Paid-service migration command

Render's separate **Pre-Deploy Command** is available to paid web services and is the preferred place for migrations on a paid deployment:

```text
alembic upgrade head
```

If you configure that field, change the Start Command to:

```text
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

On Free web services, leave the migration and Uvicorn commands combined as provided in `render.yaml`.

## Production versus free-tier deployment

The included Blueprint uses Free resources to make the first deployment accessible, but Render explicitly describes Free instances as unsuitable for production:

- a Free web service spins down after 15 minutes without inbound traffic and can take about a minute to wake up;
- the workspace receives a limited monthly pool of Free instance hours;
- a Free PostgreSQL database has 1 GB of storage;
- a Free PostgreSQL database expires after 30 days;
- after expiration, there is a 14-day upgrade grace period before deletion;
- Free PostgreSQL has no backups or managed connection pooling; and
- the web service's local filesystem is ephemeral.

For a real monitoring deployment, upgrade PostgreSQL to at least a paid Basic instance before storing important records. Also use a paid web-service instance if alert ingestion must respond continuously without cold starts. Configure backups and retention appropriate for the alert data.

Application records live in PostgreSQL and survive web-service restarts. The rotating file under `logs/` is ephemeral on Render; use the Render **Logs** page or a supported external log stream for durable operational logs. Do not attach a disk solely for alert data—the database is the system of record.

## Security checklist

- Keep `.env`, `DATABASE_URL`, `SESSION_SECRET`, user passwords, and server API tokens out of Git.
- Use only the HTTPS Render URL for browsers and alert ingestion.
- Leave `SESSION_HTTPS_ONLY=true` on Render.
- Restrict PostgreSQL external access; the Blueprint uses `ipAllowList: []`.
- Give each monitored server its own token and disable tokens that are no longer used.
- Keep `SESSION_SECRET` stable. Changing it logs out every browser session.
- Use a paid database with backups for important or regulated alert data.
- Consider disabling public account registration before exposing the application broadly.
- Review `/docs` exposure. FastAPI API documentation is public unless it is disabled in application configuration.

## Updating the deployed application

With automatic deployment enabled, the normal update flow is:

```powershell
git add <changed-files>
git commit -m "Describe the change"
git push origin main
```

Render builds the new commit, runs migrations, starts the new process, and checks `/health`. Watch the service's **Events** and **Logs** pages until the deploy is live.

Alembic migration files must always be committed with model/schema changes. Never use `Base.metadata.create_all()` as a replacement for production migrations.

## Troubleshooting

### Build command cannot find `requirements.txt`

Confirm **Root Directory** is exactly `alert-dashboard`. If deploying by Blueprint, confirm `rootDir: alert-dashboard` remains in the repository-root `render.yaml`.

### `ModuleNotFoundError: No module named 'app'`

The service is starting from the wrong directory. Set the root directory to `alert-dashboard` and use `uvicorn app.main:app`.

### `ModuleNotFoundError: No module named 'psycopg2'`

Confirm the latest `app/config.py` is deployed. It must convert Render's `postgresql://` URL to `postgresql+psycopg://`, which selects the installed Psycopg 3 package.

### Database connection failure or `/health` returns 503

Check that:

- `DATABASE_URL` exists on the web service;
- it references the Render database's internal connection string;
- the database and web service are both in Frankfurt;
- the database is available and has not expired; and
- the Render logs do not show a password, DNS, or TLS error.

Do not paste an internal Render database URL into software running on your local computer; internal hostnames are reachable only from Render resources in the same account and region.

### `relation "users" does not exist` or `relation "alerts" does not exist`

The migrations did not complete. Confirm the Start Command begins with `alembic upgrade head &&`. Read the deploy logs for an Alembic error before restarting the service.

### Render reports that no port was detected or returns 502

Use the exact host and port flags:

```text
--host 0.0.0.0 --port $PORT
```

Do not use `127.0.0.1` and do not replace `$PORT` with the local development port.

### Login immediately redirects back to login

Confirm `SESSION_SECRET` is present and stable. Access the service through `https://`, because `SESSION_HTTPS_ONLY=true` intentionally prevents the browser from sending its session cookie over HTTP.

### Alert request returns 401

Confirm the request has this header, using the token generated for that registered server:

```text
Authorization: Bearer YOUR_SERVER_TOKEN
```

### Alert request returns 409

`event_id` must be unique. Generate a new event ID for a new alert. Retrying the same ID from its original server is idempotent, but another server cannot claim it.

### Blueprint database creation fails

Render permits only one active Free PostgreSQL database per workspace. Delete an unused Free database or change the database `plan` in `render.yaml` to a paid plan such as `basic-256mb`, then push and sync again.

## Official Render references

- [Deploy a FastAPI app](https://render.com/docs/deploy-fastapi)
- [Render Blueprints](https://render.com/docs/infrastructure-as-code)
- [Blueprint YAML reference](https://render.com/docs/blueprint-spec)
- [Create and connect to Render Postgres](https://render.com/docs/postgresql-creating-connecting)
- [Environment variables and secrets](https://render.com/docs/configure-environment-variables)
- [Health checks](https://render.com/docs/health-checks)
- [Python version selection](https://render.com/docs/python-version)
- [Free instance limitations](https://render.com/docs/free)
- [Deploy and pre-deploy commands](https://render.com/docs/deploys)
