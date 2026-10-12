# n8n-Based Intrusion Detection and Prevention System (IDS/IPS)

A Flask-based web application that monitors HTTP requests, identifies suspicious activity using rule-based detection, streams request events to a web dashboard, and stores event history in PostgreSQL. The project also includes an n8n webhook endpoint for automation workflows.

> **Project status:** Educational/prototype security monitoring project. Detection is rule-based and can produce false positives or miss attacks. Blocking is application-level only; this application does not configure Render's network firewall or provide host-level `iptables` protection.

## Features

- **HTTP request monitoring** — records request metadata such as timestamp, client IP, method, path, and user agent.
- **Rule-based threat detection** — checks request data for patterns associated with SQL injection, cross-site scripting (XSS), command injection, path traversal, remote code execution (RCE), encoded payloads, and suspicious scanner user agents.
- **Rate anomaly detection** — flags clients that exceed the configured request threshold within a time window.
- **Live dashboard updates** — uses Flask-SocketIO to emit request and blocking events to connected dashboard clients.
- **PostgreSQL persistence** — stores request events and blocked-IP records in PostgreSQL, including Render PostgreSQL.
- **n8n integration** — accepts POST requests at `/n8n-webhook` for automation workflows.
- **Monitoring endpoints** — provides access to logs, blocked-IP records, and threat statistics.

## Technology stack

- Python 3
- Flask
- Flask-SocketIO
- Flask-CORS
- PostgreSQL
- Psycopg 3
- Gunicorn (deployment)
- n8n (optional workflow automation)

## Project structure

```text
n8n_Based_IDS/
├── app.py
├── requirements.txt
├── templates/
│   ├── dashboard.html
│   ├── dashboard2.html
│   └── dash/
│       └── dashboard.html
├── static/
│   ├── logo.png
│   └── ids-logo.png
└── README.md
```

The application currently renders `templates/dashboard.html` for the `/` route. Keep the `templates/` and `static/` directories in the repository.

## Requirements

- Python 3.10 or newer recommended
- A PostgreSQL database
- Git (for GitHub/Render deployment)
- An n8n instance if workflow automation is required

## Run locally on Kali Linux or another Linux system

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

Replace the URL with your own GitHub repository URL.

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

If Kali reports `externally-managed-environment`, use the virtual environment rather than installing packages system-wide.

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

The app requires `DATABASE_URL`. For a local run connecting to a Render PostgreSQL database, copy the database's **External Database URL** from the Render dashboard. Use the **Internal Database URL** when the application itself is running within Render and the services are in the same region/network.

```bash
export DATABASE_URL='YOUR_POSTGRESQL_CONNECTION_URL'
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Replace the URL placeholder with the real connection string. Do not share it or commit it to Git. If Render's database plan or access settings do not allow external connections, connect from a Render-hosted service or use a plan that supports them.

### 5. Start the application

```bash
python app.py
```

Open the local address printed by the app, typically:

- Dashboard: `http://127.0.0.1:5000/`
- Health/test endpoint: `http://127.0.0.1:5000/test`

To stop the server, press `Ctrl+C`.

## Deploy to Render

### 1. Create a Render PostgreSQL database

1. Open the [Render Dashboard](https://dashboard.render.com/).
2. Choose **New + → PostgreSQL**.
3. Create a database and wait until it is available.
4. Keep the database credentials private.

### 2. Create a Render Web Service

1. Push this project to GitHub.
2. In Render, choose **New + → Web Service** and connect the repository.
3. Set the runtime to Python if prompted.
4. Configure the commands:

**Build command**

```bash
pip install -r requirements.txt
```

**Start command**

```bash
gunicorn --worker-class gthread --threads 100 --bind 0.0.0.0:$PORT app:app
```

The command above exposes the Flask WSGI application. If you need production WebSocket support for Flask-SocketIO, follow the current Flask-SocketIO deployment guidance and choose a compatible server/worker configuration; verify live dashboard updates after deployment.

### 3. Add environment variables

In the Render web service's **Environment** settings, add:

| Key | Value |
|---|---|
| `DATABASE_URL` | Render PostgreSQL **Internal Database URL** |
| `SECRET_KEY` | A strong, unique secret value |

Save the changes and deploy. The app initializes its database tables when it starts. Check the service logs if startup fails.

## API and monitoring endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Renders the security monitoring dashboard |
| `/test` | GET | Basic application test endpoint |
| `/access.log` | GET | Returns stored request events as text |
| `/blocked-ips` | GET | Returns the list of blocked IP addresses |
| `/threat-stats` | GET | Returns threat and blocked-IP statistics |
| `/unblock/<ip>` | GET / POST | Removes an IP from the application's blocked list |
| `/api/soc-summary` | POST | Receives a SOC summary payload |
| `/n8n-webhook` | POST | Receives an event from an n8n workflow |

**Security note:** These endpoints are not a complete authenticated administration API. Before making the service public, add authentication and authorization to sensitive endpoints, especially the unblock route and any endpoint that reveals logs or security data. Prefer POST for state-changing operations and restrict access at the application or proxy layer.

## n8n webhook integration

In n8n, create a workflow with a **Webhook** node configured for `POST`, then point the workflow or upstream alerting system to:

```text
https://YOUR-RENDER-SERVICE.onrender.com/n8n-webhook
```

Replace the example hostname with your deployed service URL. Send JSON with the event information expected by your workflow/application. A minimal test body is:

```json
{
  "event": "security_alert",
  "message": "Test alert",
  "severity": "HIGH",
  "source": "n8n"
}
```

Confirm the exact response and stored fields in your current `app.py` before relying on a specific payload schema. Secure the webhook with a shared secret or another authentication mechanism before using it outside a trusted test environment.

## Configuration reference

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection URL |
| `SECRET_KEY` | Yes for secure deployment | Secret used by Flask/session configuration |

Never commit `.env` files, passwords, connection URLs, or secret keys. If credentials are exposed, rotate them.

## Database notes

The application creates the tables it uses when it initializes the database. Keep the PostgreSQL database available when running the app. PostgreSQL stores events and blocked-IP records so they can persist across app restarts; in-memory counters and rate-window tracking may reset when the process restarts or when multiple instances are running.

## Limitations and security considerations

- This is a pattern-based detection prototype, not a replacement for a production WAF, EDR, SIEM, or independently tested IPS.
- Request patterns are heuristic indicators. Legitimate requests can trigger alerts, and novel or obfuscated attacks can evade detection.
- On Render's managed web service, `iptables` and host-level firewall operations are not available. IP blocking here is enforced by the application and should not be described as network-level blocking.
- Client IP detection behind proxies must be configured carefully. Do not blindly trust forwarded headers from arbitrary clients.
- Protect the dashboard, logs, webhook, and administration endpoints with authentication, authorization, rate limiting, and appropriate logging before public use.
- Do not test against systems or networks unless you own them or have explicit authorization.
- Review and validate all alerts before taking operational action.

## Troubleshooting

### `DATABASE_URL is not configured`

Set `DATABASE_URL` in the shell before running locally, or add it under your Render web service's Environment settings.

### Database connection errors

- Check that the URL is copied correctly and credentials have not expired.
- Use the External Database URL for a local laptop connection and the Internal Database URL for a Render-hosted service when available.
- Check network access and database plan restrictions.
- Never paste your real connection string into public issues or source code.

### `ModuleNotFoundError`

Activate the virtual environment and install dependencies again:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Render build fails

Confirm the dependency file is named exactly `requirements.txt` (not `requirments.txt`) and that it is committed to the repository root.

## Contributing

1. Create a feature branch.
2. Make a focused change.
3. Test locally with a non-production database.
4. Open a pull request describing the change and any security implications.

## License

No license is specified yet. Add a `LICENSE` file before allowing others to reuse, modify, or distribute this project.
