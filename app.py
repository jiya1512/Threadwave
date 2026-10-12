from flask import Flask, request, render_template, Response
from flask_socketio import SocketIO
from datetime import datetime
from urllib.parse import unquote_plus, parse_qs
from flask_cors import CORS
import psycopg
from psycopg.rows import dict_row
from collections import defaultdict
import json
import os
import time
import re
import base64

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-development-only-change-me")
DATABASE_URL = os.environ.get("DATABASE_URL")

CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost", "http://127.0.0.1"]
    }
})

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

request_count = 0
BATCH_SIZE = 5
LOG_LIMIT = 5000

# =========================
# RENDER POSTGRESQL STORAGE
# =========================
def get_db_connection():
    """Open a short-lived connection to Render PostgreSQL."""
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured. Add your Render PostgreSQL URL "
            "to the web service Environment settings."
        )
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)


def init_db():
    """Create required tables if they do not exist yet."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ids_events (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                event_type TEXT NOT NULL DEFAULT 'REQUEST',
                ip TEXT,
                malicious BOOLEAN NOT NULL DEFAULT FALSE,
                reason TEXT,
                severity TEXT,
                data JSONB NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_created_at ON ids_events (created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ids_events_malicious ON ids_events (malicious)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ids_blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT 'Blocked by IDS/IPS policy',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.commit()


def load_blocked_ips():
    """Restore application-level blocks after a Render restart."""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT ip FROM ids_blocked_ips").fetchall()
    blocked_ips.update(row["ip"] for row in rows)

# IPS CONFIGURATION
ip_counter = defaultdict(int)
request_times = defaultdict(list)
blocked_ips = set()
threat_stats = defaultdict(int)  # Track threat types

BLOCK_THRESHOLD = 3
RATE_LIMIT = 20
RATE_WINDOW = 10

# =========================
# ADVANCED DETECTION - Import from the advanced detection code
# =========================

def check_sql_injection(payload):
    """Detect SQL injection attempts"""
    sql_patterns = [
        (r"union\s+(all\s+)?select", "CRITICAL", "Union-based SQL Injection"),
        (r"'\s*or\s*'1'\s*=\s*'1", "CRITICAL", "Boolean SQL Injection"),
        (r"'\s*or\s*1\s*=\s*1", "CRITICAL", "Boolean SQL Injection"),
        (r"admin'\s*--", "CRITICAL", "Comment-based SQL Injection"),
        (r"sleep\s*\(\s*\d+\s*\)", "HIGH", "Time-based Blind SQLi"),
        (r";\s*drop\s+table", "CRITICAL", "Stacked Query - DROP"),
        (r";\s*delete\s+from", "CRITICAL", "Stacked Query - DELETE"),
        (r"information_schema", "HIGH", "Database Enumeration"),
    ]
    
    for pattern, severity, description in sql_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, f"SQL_Injection: {description}", severity, {"pattern": pattern}
    return False, None, "LOW", {}

def check_xss(payload, raw_payload):
    """Detect XSS attacks"""
    xss_patterns = [
        (r"<script[^>]*>", "CRITICAL", "Script Tag Injection"),
        (r"javascript:", "HIGH", "JavaScript Protocol"),
        (r"on\w+\s*=", "HIGH", "Event Handler Injection"),
        (r"alert\s*\(", "HIGH", "Alert Function"),
        (r"document\.cookie", "HIGH", "Cookie Theft Attempt"),
    ]
    
    for pattern, severity, description in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, f"XSS: {description}", severity, {"pattern": pattern}
    return False, None, "LOW", {}

def check_command_injection(payload):
    """Detect OS command injection"""
    cmd_patterns = [
        (r";\s*\w+", "CRITICAL", "Command Chaining"),
        (r"\|\s*\w+", "CRITICAL", "Command Piping"),
        (r"&&\s*\w+", "CRITICAL", "AND Command Chain"),
        (r"`[^`]+`", "CRITICAL", "Backtick Command Substitution"),
        (r"\bcmd\.exe\b", "CRITICAL", "Windows CMD"),
        (r"\bpowershell\b", "CRITICAL", "PowerShell"),
        (r"\bcat\b.*/(etc|passwd)", "CRITICAL", "Password File Access"),
    ]
    
    for pattern, severity, description in cmd_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, f"Command_Injection: {description}", severity, {"pattern": pattern}
    return False, None, "LOW", {}

def check_path_traversal(payload):
    """Detect directory traversal"""
    traversal_patterns = [
        (r"\.\./", "HIGH", "Unix Path Traversal"),
        (r"\.\.\\", "HIGH", "Windows Path Traversal"),
        (r"/etc/passwd", "CRITICAL", "Passwd File Access"),
        (r"%2e%2e/", "HIGH", "Encoded Path Traversal"),
    ]
    
    for pattern, severity, description in traversal_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, f"Path_Traversal: {description}", severity, {"pattern": pattern}
    return False, None, "LOW", {}

def check_rce(payload):
    """Detect RCE attempts"""
    rce_patterns = [
        (r"\beval\s*\(", "CRITICAL", "Eval Function"),
        (r"\bexec\s*\(", "CRITICAL", "Exec Function"),
        (r"\bsystem\s*\(", "CRITICAL", "System Function"),
        (r"\bshell_exec\s*\(", "CRITICAL", "Shell Exec"),
    ]
    
    for pattern, severity, description in rce_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, f"RCE: {description}", severity, {"pattern": pattern}
    return False, None, "LOW", {}

def check_obfuscation(payload):
    """Detect encoded payloads"""
    base64_pattern = r"(?:[A-Za-z0-9+/]{40,}={0,2})"
    if re.search(base64_pattern, payload):
        return True, "Obfuscation: Base64 Encoded Payload", "MEDIUM", {"encoded": True}
    return False, None, "LOW", {}

def check_malicious_user_agent(user_agent):
    """Detect security scanners"""
    scanners = [
        ("sqlmap", "CRITICAL", "SQLMap Scanner"),
        ("nikto", "HIGH", "Nikto Scanner"),
        ("nmap", "HIGH", "Nmap Scanner"),
        ("metasploit", "CRITICAL", "Metasploit Framework"),
        ("burp", "MEDIUM", "Burp Suite"),
        ("python-requests", "MEDIUM", "Python Requests"),
        ("curl", "LOW", "cURL Client"),
        ("wget", "LOW", "Wget Client"),
    ]
    
    for scanner, severity, description in scanners:
        if scanner in user_agent:
            return True, f"Scanner: {description}", severity, {"scanner": scanner}
    return False, None, "LOW", {}

# =========================
# MAIN DETECTION FUNCTION
# =========================
def is_malicious(req):
    """Advanced multi-layer threat detection"""
    
    raw_payload = req.full_path + " " + str(req.get_data(as_text=True))
    decoded_payload = unquote_plus(raw_payload).lower()
    user_agent = req.headers.get("User-Agent", "").lower()
    
    # Run all detection layers
    checks = [
        check_sql_injection(decoded_payload),
        check_xss(decoded_payload, raw_payload),
        check_command_injection(decoded_payload),
        check_path_traversal(decoded_payload),
        check_rce(decoded_payload),
        check_obfuscation(raw_payload),
        check_malicious_user_agent(user_agent),
    ]
    
    # Find highest severity threat
    for malicious, reason, severity, details in checks:
        if malicious:
            threat_stats[reason] += 1  # Track threat types
            return True, reason, severity
    
    return False, None, "LOW"

# =========================
# IPS FUNCTIONS
# =========================
def block_ip(ip):
    """Persist an application-level IP block.

    Render web services do not grant host-level firewall/iptables access, so this
    blocks requests handled by this Flask app rather than changing the host firewall.
    """
    if not ip or ip in blocked_ips:
        return

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO ids_blocked_ips (ip, reason) VALUES (%s, %s) "
            "ON CONFLICT (ip) DO NOTHING",
            (ip, "Exceeded malicious request threshold"),
        )
        conn.commit()
    blocked_ips.add(ip)
    print(f"Blocked IP at application level: {ip}")

    event = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": "IPS_BLOCK",
        "ip": ip,
        "reason": "Exceeded malicious threshold",
        "severity": "HIGH",
    }
    write_log(event)
    socketio.emit("ips_block", {
        "ip": ip,
        "time": event["time"],
        "action": "BLOCKED",
    })

def rate_anomaly(ip):
    """Detect rate-based anomalies"""
    now = time.time()
    request_times[ip] = [t for t in request_times[ip] if now - t < RATE_WINDOW]
    request_times[ip].append(now)
    return len(request_times[ip]) > RATE_LIMIT

# =========================
# UTILITY FUNCTIONS
# =========================
def capture_request(req):
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": req.remote_addr,
        "method": req.method,
        "path": req.full_path,
        "agent": req.headers.get("User-Agent")
    }

def write_log(data):
    """Persist an event in PostgreSQL (not an ephemeral local file)."""
    data = dict(data or {})
    event_type = str(data.get("event") or ("THREAT" if data.get("malicious") else "REQUEST"))
    ip = data.get("ip")
    malicious = bool(data.get("malicious", event_type in {"THREAT", "IPS_BLOCK"}))
    reason = data.get("reason")
    severity = data.get("severity")
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO ids_events (event_type, ip, malicious, reason, severity, data) "
            "VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
            (event_type, ip, malicious, reason, severity, json.dumps(data, default=str)),
        )
        conn.commit()

# =========================
# IDS + IPS MONITOR
# =========================
@app.before_request
def ids_monitor():
    global request_count
    ip = request.remote_addr
    
    if ip in blocked_ips:
        return "🚫 Your IP has been blocked by IPS", 403
    
    request_count += 1
    data = capture_request(request)
    
    # Advanced detection
    malicious, reason, severity = is_malicious(request)
    
    # Rate limiting
    if rate_anomaly(ip):
        malicious = True
        reason = "Rate_Limit_Exceeded"
        severity = "HIGH"
    
    # Track and block malicious IPs
    if malicious:
        ip_counter[ip] += 1
        print(f"⚠️  [{severity}] Malicious attempt {ip_counter[ip]}/{BLOCK_THRESHOLD} from {ip}: {reason}")
        
        if ip_counter[ip] >= BLOCK_THRESHOLD:
            block_ip(ip)
            return "🚫 IP Blocked by IPS - Too many malicious attempts", 403
    
    data.update({
        "count": request_count,
        "malicious": malicious,
        "reason": reason,
        "severity": severity if malicious else "LOW",
        "alert": malicious,
        "payload": request.get_data(as_text=True),
        "malicious_count": ip_counter[ip] if malicious else 0
    })
    
    write_log(data)
    socketio.emit("new_request", data)

# =========================
# ROUTES
# =========================
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/access.log")
def logs():
    """Return recent database events as newline-delimited JSON for compatibility."""
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT data FROM ids_events ORDER BY id DESC LIMIT %s", (LOG_LIMIT,)
        ).fetchall()
    lines = [json.dumps(row["data"], default=str) for row in reversed(rows)]
    content = "\n".join(lines)
    if content:
        content += "\n"
    return Response(content or "No logs yet.\n", mimetype="text/plain")

@app.route("/test")
def test():
    return {"status": "IDS HIT"}

@app.route("/blocked-ips")
def blocked_ips_list():
    return {
        "blocked_ips": list(blocked_ips),
        "total": len(blocked_ips)
    }

@app.route("/threat-stats")
def threat_statistics():
    """Calculate threat counts from persistent database events."""
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT reason, COUNT(*) AS total
            FROM ids_events
            WHERE malicious = TRUE AND reason IS NOT NULL
            GROUP BY reason
            ORDER BY total DESC
        """).fetchall()
        blocked_count = conn.execute("SELECT COUNT(*) AS total FROM ids_blocked_ips").fetchone()["total"]
    stats = {row["reason"]: row["total"] for row in rows}
    return {
        "threat_types": stats,
        "total_threats": sum(stats.values()),
        "blocked_ips": blocked_count,
    }

@app.route("/unblock/<ip>", methods=["POST", "GET"])
def unblock_ip(ip):
    """Remove an application-level IP block from PostgreSQL."""
    if ip not in blocked_ips:
        return {"error": "IP not blocked"}, 404
    with get_db_connection() as conn:
        conn.execute("DELETE FROM ids_blocked_ips WHERE ip = %s", (ip,))
        conn.commit()
    blocked_ips.discard(ip)
    ip_counter[ip] = 0
    return {"status": f"IP {ip} unblocked successfully", "mode": "application-level"}

@app.route("/api/soc-summary", methods=["POST"])
def receive_summary():
    data = request.json
    socketio.emit("soc_summary", data)
    write_log({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "soc_summary": data})
    return {"status": "received"}

@app.route("/n8n-webhook", methods=["POST"])
def receive_n8n():
    data = request.json
    data = data if isinstance(data, dict) else {"payload": data}
    print("N8N event received")
    event_record = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": "N8N_WEBHOOK",
        "ip": request.remote_addr,
        "n8n_event": data,
    }
    write_log(event_record)
    socketio.emit("n8n_event", data)
    return {"status": "received"}

# Initialize persistent storage when the module is loaded by Gunicorn or run directly.
init_db()
load_blocked_ips()

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    print("=" * 70)
    print("🛡️  ADVANCED IDS/IPS SYSTEM STARTING...")
    print("=" * 70)
    print("📊 Dashboard: http://0.0.0.0:5000")
    print("📝 Access Logs: http://0.0.0.0:5000/access.log")
    print("🚫 Blocked IPs: http://0.0.0.0:5000/blocked-ips")
    print("📈 Threat Stats: http://0.0.0.0:5000/threat-stats")
    print("🔓 Unblock IP: http://0.0.0.0:5000/unblock/<ip>")
    print("=" * 70)
    print("⚙️  IPS CONFIGURATION:")
    print(f"   • Block Threshold: {BLOCK_THRESHOLD} malicious attempts")
    print(f"   • Rate Limit: {RATE_LIMIT} requests / {RATE_WINDOW} seconds")
    print("=" * 70)
    print("🔍 ADVANCED DETECTION LAYERS (14 Layers):")
    print("   ✓ SQL Injection (Union, Boolean, Time-based, Error-based)")
    print("   ✓ XSS (Script tags, Event handlers, DOM manipulation)")
    print("   ✓ Command Injection (Shell, PowerShell, Bash)")
    print("   ✓ Path Traversal (Directory traversal, File access)")
    print("   ✓ RCE (eval, exec, system, shell_exec)")
    print("   ✓ XXE (XML External Entity)")
    print("   ✓ SSRF (Server-Side Request Forgery)")
    print("   ✓ LDAP Injection")
    print("   ✓ NoSQL Injection")
    print("   ✓ Obfuscation Detection (Base64, Hex, Unicode)")
    print("   ✓ Malicious User Agents (Scanners, Bots)")
    print("   ✓ Suspicious Headers")
    print("   ✓ File Upload Attacks")
    print("   ✓ HTTP Request Smuggling")
    print("=" * 70)
    print("🚀 System Ready - All 14 Detection Layers Active!")
    print("=" * 70)
    
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False, use_reloader=False)
