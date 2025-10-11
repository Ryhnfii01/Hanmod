from flask import Flask, request, redirect, render_template_string, session, jsonify
import sqlite3, datetime, hashlib

app = Flask(__name__)
app.secret_key = "supersecretkey"
ADMIN_PASSWORD = "admin123"

# ---------- Database ----------
def db_conn():
    conn = sqlite3.connect('keys.db', check_same_thread=False)
    conn.execute('''CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        revoked INTEGER DEFAULT 0,
        created_at TEXT,
        duration_days INTEGER DEFAULT 7
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS ip_map (
        ip TEXT,
        key TEXT,
        created_at TEXT,
        revoked INTEGER DEFAULT 0
    )''')
    conn.commit()
    return conn

def hash_key(s):
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]

def is_logged_in():
    return session.get("admin_logged")

# ---------- User ----------
@app.route("/")
def home():
    return """
    <html><head><title>License Activation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      body {background:#0d1117;color:#e6eef6;font-family:'Segoe UI';
            display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
      .box {background:#161b22;padding:30px;border-radius:14px;
            box-shadow:0 0 12px rgba(0,0,0,0.4);width:90%;max-width:360px;}
      input,button {width:100%;padding:12px;margin-top:10px;border:none;border-radius:8px;}
      input {background:#21262d;color:#fff;}
      button {background:#238636;color:white;font-weight:bold;}
    </style></head>
    <body><div class="box">
      <h2>Masukkan License Key</h2>
      <form action="/submit" method="POST">
        <input type="text" name="key" placeholder="License key..." required>
        <button type="submit">Aktifkan</button>
      </form>
    </div></body></html>
    """

@app.route("/submit", methods=["POST"])
def submit():
    key = request.form.get("key", "").strip()
    client_ip = request.remote_addr
    if not key:
        return "Missing key", 400

    conn = db_conn()
    cur = conn.cursor()
    cur.execute('SELECT revoked, duration_days, created_at FROM keys WHERE key=?', (key,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return "❌ Invalid key", 400
    revoked, days, created_at = row
    if revoked:
        conn.close()
        return "❌ Key revoked", 400

    created_dt = datetime.datetime.fromisoformat(created_at)
    if datetime.datetime.utcnow() > created_dt + datetime.timedelta(days=days):
        conn.close()
        return "❌ Key expired", 400

    cur.execute('DELETE FROM ip_map WHERE ip=?', (client_ip,))
    cur.execute('INSERT INTO ip_map (ip, key, created_at, revoked) VALUES (?, ?, ?, 0)',
                (client_ip, key, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    return f"<html><body style='background:#081019;color:#e6eef6;padding:30px;font-family:Arial;text-align:center'>✅ Key {key} aktif untuk IP {client_ip}.<br><br>Tutup browser dan kembali ke game.</body></html>"

# ---------- Admin ----------
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin_logged"] = True
            return redirect("/dashboard")
        return "❌ Wrong password"
    return '''
    <html><body style="background:#0d1117;color:white;text-align:center;padding-top:10%">
    <h2>Admin Login</h2>
    <form method="POST">
      <input type="password" name="password" placeholder="Password"
             style="padding:10px;border-radius:8px;border:none;width:200px;"><br><br>
      <button type="submit" style="padding:10px 25px;border:none;border-radius:8px;background:#238636;color:white;">Login</button>
    </form></body></html>'''

@app.route("/logout")
def logout():
    session.pop("admin_logged", None)
    return redirect("/admin")

@app.route("/dashboard")
def dashboard():
    if not is_logged_in(): return redirect("/admin")
    conn = db_conn()
    cur = conn.cursor()
    keys = cur.execute("SELECT * FROM keys ORDER BY key ASC").fetchall()
    ip_map = cur.execute("SELECT ip,key,created_at,revoked FROM ip_map ORDER BY key ASC, created_at DESC").fetchall()
    conn.close()

    html = """
    <html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Dashboard</title><style>
      body{background:#0d1117;color:#e6eef6;font-family:'Segoe UI';margin:20px;}
      table{width:100%;border-collapse:collapse;margin-top:10px;}
      th,td{padding:8px;border:1px solid #30363d;text-align:center;}
      th{background:#161b22;} tr:nth-child(even){background:#151a21;}
      .btn{padding:5px 10px;border:none;border-radius:6px;color:white;cursor:pointer;}
      .revoke{background:#d73a49;} .unrevoke{background:#28a745;}
      .delete{background:#6a737d;} .unsign{background:#f1c40f;color:black;}
    </style>
    <script>
      async function refreshLogs(){
        const res = await fetch('/api/logs');
        const data = await res.text();
        document.getElementById('ip_table').innerHTML = data;
      }
      setInterval(refreshLogs, 5000);
      window.onload = refreshLogs;
    </script>
    </head><body>
    <h2>🔐 Admin Dashboard</h2><a href="/logout" style="color:#58a6ff;">Logout</a>
    <div style="background:#161b22;padding:15px;border-radius:10px;">
      <h3>Buat Key Baru</h3>
      <form method="POST" action="/create_key">
        <input name="key" placeholder="Custom key (optional)" style="padding:8px;width:40%;">
        <input name="days" placeholder="Durasi (hari)" type="number" value="7" style="padding:8px;width:20%;">
        <button type="submit" class="btn unrevoke">Create</button>
      </form>
    </div>
    <h3>📦 Semua Key</h3>
    <table><tr><th>Key</th><th>Dibuat</th><th>Durasi</th><th>Expired</th><th>Status</th><th>Aksi</th></tr>
    {% for k in keys %}
      <tr><td>{{k[0]}}</td><td>{{k[2]}}</td><td>{{k[3]}} hari</td>
          <td>{% set exp=(datetime.datetime.fromisoformat(k[2])+datetime.timedelta(days=k[3])) %}
              {{exp.strftime("%Y-%m-%d")}}</td>
          <td>{{'Revoked' if k[1] else 'Active'}}</td>
          <td>{% if k[1]==0 %}
                <a href="/revoke/{{k[0]}}" class="btn revoke">Revoke</a>
              {% else %}
                <a href="/unrevoke/{{k[0]}}" class="btn unrevoke">Unrevoke</a>
              {% endif %}
              <a href="/delete/{{k[0]}}" class="btn delete">Delete</a>
          </td></tr>{% endfor %}
    </table>

    <h3>🌐 Daftar IP (Auto Update)</h3>
    <div id="ip_table"></div>
    </body></html>
    """
    import datetime
    return render_template_string(html, keys=keys, datetime=datetime)

# ---------- Admin Actions ----------
@app.route("/create_key", methods=["POST"])
def create_key():
    if not is_logged_in(): return redirect("/admin")
    key = request.form.get("key","").strip() or hash_key(datetime.datetime.utcnow().isoformat())
    days = int(request.form.get("days") or 7)
    conn = db_conn()
    conn.execute("INSERT OR REPLACE INTO keys (key, revoked, created_at, duration_days) VALUES (?,?,?,?)",
                 (key, 0, datetime.datetime.utcnow().isoformat(), days))
    conn.commit(); conn.close()
    return redirect("/dashboard")

@app.route("/revoke/<key>")
def revoke(key):
    if not is_logged_in(): return redirect("/admin")
    conn = db_conn()
    conn.execute("UPDATE keys SET revoked=1 WHERE key=?", (key,))
    conn.execute("UPDATE ip_map SET revoked=1 WHERE key=?", (key,))
    conn.commit(); conn.close()
    return redirect("/dashboard")

@app.route("/unrevoke/<key>")
def unrevoke(key):
    if not is_logged_in(): return redirect("/admin")
    conn = db_conn()
    conn.execute("UPDATE keys SET revoked=0 WHERE key=?", (key,))
    conn.execute("UPDATE ip_map SET revoked=0 WHERE key=?", (key,))
    conn.commit(); conn.close()
    return redirect("/dashboard")

@app.route("/delete/<key>")
def delete(key):
    if not is_logged_in(): return redirect("/admin")
    conn = db_conn()
    conn.execute("DELETE FROM keys WHERE key=?", (key,))
    conn.execute("DELETE FROM ip_map WHERE key=?", (key,))
    conn.commit(); conn.close()
    return redirect("/dashboard")

@app.route("/unsign/<ip>/<key>")
def unsign(ip, key):
    if not is_logged_in(): return redirect("/admin")
    conn = db_conn()
    conn.execute("DELETE FROM ip_map WHERE ip=? AND key=?", (ip, key))
    conn.commit(); conn.close()
    return redirect("/dashboard")

# ---------- API (Auto Update Logs) ----------
@app.route("/api/logs")
def api_logs():
    if not is_logged_in(): return "Unauthorized", 403
    conn = db_conn()
    cur = conn.cursor()
    ip_map = cur.execute("SELECT ip,key,created_at,revoked FROM ip_map ORDER BY key ASC, created_at DESC").fetchall()
    conn.close()
    html = "<table><tr><th>IP</th><th>Key</th><th>Login</th><th>Status</th><th>Aksi</th></tr>"
    for i in ip_map:
        status = "Revoked" if i[3] else "Active"
        html += f"<tr><td>{i[0]}</td><td>{i[1]}</td><td>{i[2]}</td><td>{status}</td>" \
                f"<td><a href='/unsign/{i[0]}/{i[1]}' class='btn unsign'>Unsign</a></td></tr>"
    html += "</table>"
    return html

# ---------- API untuk Game ----------
@app.route("/api/check_ip")
def check_ip():
    client_ip = request.remote_addr
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT key, revoked FROM ip_map WHERE ip=?", (client_ip,))
    row = cur.fetchone()
    if not row:
        conn.close(); return "NO_KEY"
    key, revoked = row
    if revoked:
        conn.close(); return "REVOKED"
    cur.execute("SELECT revoked, duration_days, created_at FROM keys WHERE key=?", (key,))
    krow = cur.fetchone()
    if not krow:
        conn.close(); return "INVALID"
    k_rev, days, k_created = krow
    if k_rev:
        conn.close(); return "REVOKED"
    k_dt = datetime.datetime.fromisoformat(k_created)
    if datetime.datetime.utcnow() > k_dt + datetime.timedelta(days=days):
        conn.close(); return "EXPIRED"
    conn.close()
    return "OK"

# ---------- No Cache ----------
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

if __name__ == "__main__":
    db_conn().close()

