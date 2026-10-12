# n8n-Based IDS/IPS

## What is this project?

This project is a web-based Intrusion Detection and Prevention System (IDS/IPS) built with Python and Flask. It monitors incoming web requests, checks for suspicious patterns, and records security events. It can identify potential threats such as SQL injection, cross-site scripting (XSS), command injection, and unusual request activity.

The dashboard helps you view request activity and security events. PostgreSQL can be used to store event records, and an n8n webhook can connect alerts to automated workflows.

This is an educational security-monitoring project. Its detection is rule-based, so it may produce false positives or miss attacks. IP blocking is application-level; it does not configure Render's network firewall.

## How to use it

### 1. Get the project

Clone your GitHub repository and enter its directory:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

Replace the example URL with your repository URL.

### 2. Install dependencies

Create and activate a virtual environment, then install the requirements:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 3. Configure PostgreSQL

Create a PostgreSQL database in Render. Copy the database connection URL from the Render dashboard.

For running the app on your own computer, use the **External Database URL**. For an app hosted on Render, use the **Internal Database URL** when the database and web service are in the same region and internal connection is available.

Set the connection URL and a secret key in your terminal before running locally:

```bash
export DATABASE_URL='YOUR_POSTGRESQL_CONNECTION_URL'
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Replace the placeholder with your actual connection URL. Keep the URL and secret private; do not commit them to GitHub.

### 4. Run locally

Start the application:

```bash
python app.py
```

Open the local URL shown in the terminal, usually `http://127.0.0.1:5000/`.

### 5. Deploy on Render (optional)

1. Push the project to GitHub.
2. In Render, create a **Web Service** and connect the repository.
3. Set the build command to:

   ```bash
   pip install -r requirements.txt
   ```

4. Set the start command to:

   ```bash
   gunicorn --worker-class gthread --threads 100 --bind 0.0.0.0:$PORT app:app
   ```

5. In the web service's **Environment** settings, add `DATABASE_URL` with the Render PostgreSQL **Internal Database URL**, and add `SECRET_KEY` with a strong secret value.
6. Deploy the service and open its published URL.

### 6. Use n8n (optional)

Configure an n8n workflow to send a `POST` request to the deployed app's `/n8n-webhook` endpoint. Use the JSON payload expected by your current workflow and application. Secure the webhook before connecting it to external systems.

## Important

Only test against systems and networks you own or have explicit permission to assess. Before exposing the dashboard publicly, protect administrative endpoints, logs, and webhook access with authentication.
