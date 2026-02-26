import time
import os
from collections import defaultdict
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, session, url_for
from flask_socketio import SocketIO

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

socketio = SocketIO(app, async_mode="threading")

ALERT_FILE = "alerts.log"
AUDIT_FILE = "audit.log"

USERS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "analyst": {"password": "analyst123", "role": "Analyst"}
}

# ================= UTILITY FUNCTIONS =================

def parse_alerts():
    alerts = []
    brute_force = 0
    port_scan = 0
    timeline = defaultdict(int)

    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            lines = f.readlines()

        for line in lines:
            parts = line.strip().split("|")
            if len(parts) >= 5:
                timestamp, attack_type, ip, severity, mitre = [p.strip() for p in parts[:5]]

                alerts.append({
                    "time": timestamp,
                    "type": attack_type,
                    "ip": ip,
                    "severity": severity,
                    "mitre": mitre
                })

                if attack_type == "BRUTE FORCE":
                    brute_force += 1
                elif attack_type == "PORT SCAN":
                    port_scan += 1

                try:
                    dt = datetime.strptime(timestamp.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    timeline[dt.strftime("%H:%M")] += 1
                except:
                    pass

    total = brute_force + port_scan
    sorted_timeline = dict(sorted(timeline.items()))

    return total, brute_force, port_scan, alerts[-10:][::-1]


def get_audit_logs():
    logs = []
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "r") as f:
            lines = f.readlines()[-10:]

        for line in lines:
            parts = line.strip().split("|")
            if len(parts) >= 4:
                logs.append({
                    "time": parts[0].strip(),
                    "user": parts[1].strip(),
                    "role": parts[2].strip(),
                    "action": parts[3].strip()
                })
    return logs[::-1]


def log_audit(action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = session.get("user", "Unknown")
    role = session.get("role", "Unknown")

    with open(AUDIT_FILE, "a") as f:
        f.write(f"{timestamp} | {user} | {role} | {action}\n")


# ================= REAL-TIME MONITOR =================

def monitor_alert_file():
    print("🔥 Monitor thread started")
    last_line_count = 0

    while True:
        try:
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, "r") as f:
                    lines = f.readlines()

                if len(lines) > last_line_count:
                    new_lines = lines[last_line_count:]

                    for line in new_lines:
                        parts = line.strip().split("|")
                        if len(parts) >= 5:
                            alert = {
                                "time": parts[0].strip(),
                                "type": parts[1].strip(),
                                "ip": parts[2].strip(),
                                "severity": parts[3].strip(),
                                "mitre": parts[4].strip()
                            }
                            socketio.emit("new_alert", alert)

                    last_line_count = len(lines)

        except Exception as e:
            print("❌ Monitor error:", e)

        time.sleep(2)


# ================= ROUTES =================

@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = USERS.get(username)

        if user and user["password"] == password:
            session["user"] = username
            session["role"] = user["role"]
            log_audit("Logged In")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Credentials"

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise SOC Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">

    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Orbitron', sans-serif;
        }}

        body {{
            height: 100vh;
            overflow: hidden;
            background: #0f172a;
            display: flex;
            justify-content: center;
            align-items: center;
        }}

        /* Animated Background */
        body::before {{
            content: "";
            position: absolute;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, #00ffff33 1px, transparent 1px);
            background-size: 40px 40px;
            animation: moveBackground 20s linear infinite;
        }}

        @keyframes moveBackground {{
            from {{ transform: translate(0,0); }}
            to {{ transform: translate(-200px,-200px); }}
        }}

        .login-box {{
            position: relative;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            padding: 50px;
            border-radius: 20px;
            width: 400px;
            box-shadow: 0 0 40px #00ffff55;
            text-align: center;
            color: white;
            z-index: 1;
            animation: fadeIn 1s ease-in-out;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: scale(0.9); }}
            to {{ opacity: 1; transform: scale(1); }}
        }}

        .title {{
            font-size: 18px;
            margin-bottom: 10px;
            color: #00ffff;
            letter-spacing: 3px;
        }}

        h2 {{
            margin-bottom: 30px;
        }}

        .input-group {{
            position: relative;
            margin-bottom: 20px;
        }}

        input {{
            width: 100%;
            padding: 14px;
            border-radius: 10px;
            border: none;
            background: rgba(255,255,255,0.1);
            color: white;
            outline: none;
        }}

        input::placeholder {{
            color: #ccc;
        }}

        .toggle-password {{
            position: absolute;
            right: 15px;
            top: 14px;
            cursor: pointer;
            color: #00ffff;
        }}

        button {{
            width: 100%;
            padding: 14px;
            border-radius: 10px;
            border: none;
            background: #00ffff;
            color: black;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s;
        }}

        button:hover {{
            background: #00cccc;
            box-shadow: 0 0 20px #00ffff;
        }}

        .error {{
            color: red;
            margin-bottom: 15px;
            animation: shake 0.3s;
        }}

        @keyframes shake {{
            0% {{ transform: translateX(0); }}
            25% {{ transform: translateX(-5px); }}
            50% {{ transform: translateX(5px); }}
            75% {{ transform: translateX(-5px); }}
            100% {{ transform: translateX(0); }}
        }}

        .footer {{
            margin-top: 20px;
            font-size: 12px;
            color: #aaa;
        }}
    </style>
</head>

<body>

<div class="login-box">
    <div class="title">SECURITY OPERATIONS CENTER</div>
    <h2>🔐 Enterprise SOC Login</h2>

    {"<div class='error'>" + error + "</div>" if error else ""}

    <form method="POST">
        <div class="input-group">
            <input name="username" placeholder="Username" required>
        </div>

        <div class="input-group">
            <input type="password" id="password" name="password" placeholder="Password" required>
            <span class="toggle-password" onclick="togglePassword()">👁</span>
        </div>

        <button type="submit">Authenticate</button>
    </form>

    <div class="footer">
        Powered by Mohit SOC Engine ⚡
    </div>
</div>

<script>
function togglePassword() {{
    var x = document.getElementById("password");
    if (x.type === "password") {{
        x.type = "text";
    }} else {{
        x.type = "password";
    }}
}}
</script>

</body>
</html>
"""
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    total, brute_force, port_scan, alerts = parse_alerts()
    audit_logs = get_audit_logs()

    role_color = "#ef4444" if session["role"] == "Admin" else "#3b82f6"
    role_bg = "rgba(239,68,68,0.2)" if session["role"] == "Admin" else "rgba(59,130,246,0.2)"

    return f"""
<!DOCTYPE html>
<html>
<head>
<title>SOC Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">

<style>
* {{
    margin:0;
    padding:0;
    box-sizing:border-box;
    font-family:'Orbitron', sans-serif;
}}

body {{
    background: linear-gradient(135deg,#0f172a,#1e293b);
    color:white;
}}

.header {{
    padding:25px;
    text-align:center;
    background:rgba(255,255,255,0.05);
    backdrop-filter:blur(10px);
}}

.role-badge {{
    display:inline-block;
    padding:6px 14px;
    border-radius:20px;
    background:{role_bg};
    color:{role_color};
    margin-left:10px;
    font-size:12px;
    box-shadow:0 0 10px {role_color};
}}

.cards {{
    display:flex;
    justify-content:center;
    gap:30px;
    margin:40px;
    flex-wrap:wrap;
}}

.card {{
    background:rgba(255,255,255,0.05);
    backdrop-filter:blur(15px);
    padding:30px;
    width:250px;
    border-radius:15px;
    text-align:center;
    transition:0.3s;
}}

.card:hover {{
    transform:translateY(-8px);
    box-shadow:0 0 25px {role_color};
}}

.card h1 {{
    font-size:35px;
    color:{role_color};
}}

.table-container {{
    width:90%;
    margin:40px auto;
    background:rgba(255,255,255,0.05);
    backdrop-filter:blur(15px);
    border-radius:15px;
    padding:20px;
}}

table {{
    width:100%;
    border-collapse:collapse;
}}

th, td {{
    padding:12px;
    text-align:center;
}}

th {{
    background:{role_bg};
    color:{role_color};
}}

tr:hover {{
    background:rgba(255,255,255,0.08);
}}

.logout {{
    color:#f87171;
    text-decoration:none;
    font-size:14px;
}}

</style>
</head>

<body>

<div class="header">
    <h1>🛡 Security Operations Center</h1>
    <p>
        Welcome {session['user']}
        <span class="role-badge">{session['role']}</span>
    </p>
    <a href="/logout" class="logout">Logout</a>
</div>

<div class="cards">
    <div class="card">
        <h2>Total Alerts</h2>
        <h1>{total}</h1>
    </div>
    <div class="card">
        <h2>Brute Force</h2>
        <h1>{brute_force}</h1>
    </div>
    <div class="card">
        <h2>Port Scan</h2>
        <h1>{port_scan}</h1>
    </div>
</div>

<div class="table-container">
<h2 style="text-align:center;margin-bottom:20px;">Recent Alerts</h2>
<table id="alertTable">
<tr>
<th>Time</th>
<th>Type</th>
<th>IP</th>
<th>Severity</th>
<th>MITRE</th>
</tr>

{''.join(f"<tr><td>{a['time']}</td><td>{a['type']}</td><td>{a['ip']}</td><td>{a['severity']}</td><td>{a['mitre']}</td></tr>" for a in alerts)}

</table>
</div>

<script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
<script>
var socket = io();

socket.on("new_alert", function(data) {{
    var table = document.getElementById("alertTable");
    var row = table.insertRow(1);
    row.insertCell(0).innerHTML = data.time;
    row.insertCell(1).innerHTML = data.type;
    row.insertCell(2).innerHTML = data.ip;
    row.insertCell(3).innerHTML = data.severity;
    row.insertCell(4).innerHTML = data.mitre;
}});
</script>

</body>
</html>
"""
@app.route("/logout")
def logout():
    if "user" in session:
        log_audit("Logged Out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/clear_alerts")
def clear_alerts():
    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access Denied ❌"

    log_audit("Cleared Alerts")
    open(ALERT_FILE, "w").close()
    return redirect(url_for("dashboard"))


# ================= RUN =================
if __name__ == "__main__":
    socketio.start_background_task(monitor_alert_file)
    socketio.run(app, debug=True, use_reloader=False)