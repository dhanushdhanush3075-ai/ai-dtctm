from flask import Flask, request, jsonify, session, redirect, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_12345"  # VULNERABILITY: hardcoded secret

DB = "/tmp/vuln_demo.db"

LOGIN_HTML = """
<!DOCTYPE html><html><head>
<title>Demo Login</title>
<style>
body{font-family:monospace;background:#1a1a2e;color:#eee;display:flex;
     align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:40px;width:320px}
h2{color:#e94560;margin-bottom:24px;text-align:center}
input{width:100%;padding:10px;margin:8px 0;background:#0f3460;border:1px solid #e94560;
      color:#fff;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:4px;
       cursor:pointer;font-size:1rem;margin-top:12px}
.err{color:#ff6b6b;font-size:0.85rem;margin-top:8px;text-align:center}
.note{color:#888;font-size:0.72rem;text-align:center;margin-top:16px;line-height:1.5}
</style></head>
<body><div class='box'>
<h2>Vulnerable Login Demo</h2>
<form method=POST>
  <input name='username' placeholder='Username' autocomplete='off'>
  <input name='password' type='password' placeholder='Password'>
  <button type='submit'>Sign In</button>
</form>
{% if msg %}<div class='err'>{{ msg }}</div>{% endif %}
<div class='note'>AI-DTCTM Demo Target<br>SQLi &bull; XSS &bull; No CSRF &bull; No rate-limit</div>
</div></body></html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html><html><head><title>Dashboard</title>
<style>
body{font-family:monospace;background:#1a1a2e;color:#eee;padding:40px}
h2{color:#4ade80}.badge{display:inline-block;background:#0f3460;padding:4px 12px;border-radius:12px;font-size:.8rem}
a{color:#e94560;text-decoration:none}
</style></head>
<body>
<h2>Welcome, {{ user }}!</h2>
<p>Role: <span class='badge'>{{ role }}</span></p>
<p><a href='/logout'>Logout</a> &nbsp; <a href='/api/users'>View all users (no auth!)</a></p>
</body></html>
"""


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password1','user')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3,'bob','qwerty','user')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_HTML, msg="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ══════════════════════════════════════════════════════════
    # INTENTIONAL VULNERABILITY: String concatenation SQLi
    # A real app would use: conn.execute("... WHERE username=?", (username,))
    # This is for AI-DTCTM attack demonstration ONLY.
    # ══════════════════════════════════════════════════════════
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        conn = sqlite3.connect(DB)
        row = conn.execute(query).fetchone()
        conn.close()
    except Exception as e:
        # VULNERABILITY: raw DB error leaked to user → reveals query structure
        return render_template_string(LOGIN_HTML, msg=f"DB Error: {e}")

    if row:
        session["user"] = row[1]
        session["role"] = row[3]
        return redirect("/dashboard")

    # VULNERABILITY: no rate-limiting, no lockout, no CSRF token
    return render_template_string(LOGIN_HTML, msg="Invalid credentials")


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect("/login")
    return render_template_string(
        DASHBOARD_HTML, user=user, role=session.get("role", "?")
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/api/users")
def api_users():
    # VULNERABILITY: no authentication check — exposes all user records
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])


@app.route("/api/search")
def api_search():
    # VULNERABILITY: reflected XSS — user input echoed into HTML without escaping
    q = request.args.get("q", "")
    return f"<html><body><h3>Search: {q}</h3></body></html>"


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
