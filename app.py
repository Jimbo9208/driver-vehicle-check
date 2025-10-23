import os
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, flash
)

from sqlalchemy import (
    create_engine, MetaData, Table, Column,
    Integer, String, Text, DateTime
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import select, insert, text as sqltext

# ----------------------- Config -----------------------
APP_NAME = os.getenv("APP_NAME", "Driver / Vehicle Check")
PIN_CODE = os.getenv("PIN_CODE", "6633")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "")
RUNNING_ON_RENDER = os.getenv("RENDER", "") != ""
CLEANUP_LEGACY = os.getenv("CLEANUP_LEGACY", "0") == "1"  # drop old 'vehicle' table if present

# If we’re on Render, a DATABASE_URL is mandatory
if RUNNING_ON_RENDER and not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. On Render you must provide a Postgres DATABASE_URL."
    )

# ----------------------- Flask ------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ----------------------- Database ---------------------
engine = None
metadata = MetaData()
checks_table = None
db_enabled = False
db_error = None

def _engine_from_url(db_url: str):
    # Ensure sslmode=require for Render Postgres if not present
    if db_url and "postgres" in db_url and "sslmode=" not in db_url:
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}sslmode=require"
    return create_engine(db_url, pool_pre_ping=True, future=True)

def init_db():
    """Create engine, create tables, optionally drop legacy table."""
    global engine, checks_table, db_enabled, db_error

    if not DATABASE_URL:
        db_enabled = False
        return

    try:
        engine = _engine_from_url(DATABASE_URL)
        is_postgres = urlparse(DATABASE_URL).scheme.startswith("postgres")
        checklist_type = JSONB if is_postgres else Text

        checks_table = Table(
            "vehicle_checks",
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("created_at", DateTime, nullable=False, default=datetime.utcnow),
            Column("driver_name", String(120), nullable=False),
            Column("vehicle_reg", String(40), nullable=False),
            Column("mileage", String(40), nullable=True),
            Column("checklist", checklist_type, nullable=False),  # {label: "OK"/"Issue"}
            Column("defect_notes", Text, nullable=True),
            Column("follow_up", String(10), nullable=False, default="No"),
        )

        metadata.create_all(engine)

        # Optional: clean up legacy table called 'vehicle'
        if CLEANUP_LEGACY:
            with engine.begin() as conn:
                conn.execute(sqltext("DROP TABLE IF EXISTS vehicle CASCADE"))

        # Simple ping
        with engine.begin() as conn:
            conn.exec_driver_sql("SELECT 1")

        db_enabled = True
    except Exception as e:
        db_error = str(e)
        db_enabled = False

init_db()

# In-memory fallback ONLY for local dev when DATABASE_URL is absent
memory_store = {"seq": 0, "rows": []}

# -------------------- Auth helpers --------------------
def logged_in():
    return session.get("logged_in") is True

# ----------------------- Templates --------------------
BASE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>{{ title or app_name }}</title>
    <style>
      :root { color-scheme: light dark; }
      body { font-family: system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
             margin:0; padding:0; background:#0b0d10; color:#e8eaed; }
      .wrap { max-width: 900px; margin: 0 auto; padding: 24px; }
      .card { background:#111418; border:1px solid #22252a; border-radius:16px; padding:20px; }
      label { display:block; margin-bottom:6px; font-weight:600; }
      input, select, textarea {
        width:100%; padding:10px 12px; border-radius:10px;
        border:1px solid #30343a; background:#0c0f13; color:#e8eaed;
      }
      textarea { min-height: 110px; }
      .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
      .checks { display:grid; grid-template-columns:repeat(auto-fill, minmax(200px,1fr)); gap:12px; }
      .check-item { border:1px solid #22252a; border-radius:12px; padding:10px; background:#0c0f13; }
      .btn { display:inline-block; padding:10px 16px; border-radius:10px; border:1px solid #3a6df0;
             background:#2a5ae8; color:white; text-decoration:none; font-weight:600; cursor:pointer; }
      .btn.secondary { background:transparent; border:1px solid #3a3f46; color:#e8eaed; }
      .flash { margin:12px 0; padding:10px 12px; border-radius:10px; background:#143d1f; border:1px solid #235a2f; }
      .error { background:#3d1414; border-color:#5a2323; }
      small.muted { color:#9aa0a6; }
      @media (max-width: 700px) { .row { grid-template-columns:1fr; } }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <h1>{{ app_name }}</h1>
        {% if session.get('logged_in') %}
          <div>
            <a class="btn secondary" href="{{ url_for('admin') }}">Admin</a>
            <a class="btn secondary" href="{{ url_for('logout') }}" style="margin-left:8px;">Logout</a>
          </div>
        {% endif %}
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for cat, msg in messages %}
          <div class="flash {% if cat=='error' %}error{% endif %}">{{ msg }}</div>
        {% endfor %}
      {% endwith %}

      <div class="card">{% block content %}{% endblock %}</div>

      <p style="margin-top:18px;"><small class="muted">
        {% if db_enabled %}Backed by PostgreSQL (persistent).{% else %}
          Running without persistent DB (fallback). Set DATABASE_URL to enable Postgres.
          {% if db_error %}<br/>DB error: {{ db_error }}{% endif %}
        {% endif %}
      </small></p>
    </div>
  </body>
</html>
"""

PIN_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Enter PIN</h2>
  <form method="post" style="margin-top:12px;">
    <label for="pin">PIN Code</label>
    <input id="pin" name="pin" type="text" inputmode="numeric" autofocus />
    <button class="btn" type="submit" style="margin-top:8px;">Continue</button>
  </form>
{% endblock %}
"""

CHECK_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Daily Vehicle Check</h2>
  <form method="post" style="margin-top:12px;">
    <div class="row">
      <div>
        <label for="driver_name">Driver Name</label>
        <input id="driver_name" name="driver_name" required />
      </div>
      <div>
        <label for="vehicle_reg">Vehicle Reg</label>
        <input id="vehicle_reg" name="vehicle_reg" required />
      </div>
    </div>
    <div class="row" style="margin-top:12px;">
      <div>
        <label for="mileage">Mileage (optional)</label>
        <input id="mileage" name="mileage" />
      </div>
      <div>
        <label for="follow_up">Requires Follow-up?</label>
        <select id="follow_up" name="follow_up"><option>No</option><option>Yes</option></select>
      </div>
    </div>

    <h3 style="margin-top:12px;">Checklist</h3>
    <div class="checks">
      {% for item in checklist %}
        <div class="check-item">
          <label>{{ item }}</label>
          <select name="check__{{ loop.index0 }}">
            <option>OK</option><option>Issue</option>
          </select>
          <input type="hidden" name="check_label__{{ loop.index0 }}" value="{{ item }}"/>
        </div>
      {% endfor %}
    </div>

    <div style="margin-top:12px;">
      <label for="defect_notes">Defect Notes (if any)</label>
      <textarea id="defect_notes" name="defect_notes" placeholder="Describe any issues..."></textarea>
    </div>

    <button class="btn" type="submit" style="margin-top:12px;">Submit Check</button>
  </form>
{% endblock %}
"""

SUCCESS_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Submitted ✅</h2>
  <p>Your check has been recorded.</p>
  <p><small class="muted">Reference ID: {{ check_id }}</small></p>
  <div style="margin-top:12px;">
    <a class="btn" href="{{ url_for('check') }}">Submit Another</a>
    <a class="btn secondary" href="{{ url_for('admin') }}" style="margin-left:8px;">View Recent</a>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Recent Checks</h2>
  {% if rows %}
    <div style="display:grid; gap:12px; margin-top:12px;">
      {% for r in rows %}
        <div class="card" style="border-radius:12px;">
          <div style="display:flex; justify-content:space-between;">
            <strong>#{{ r.id }}</strong>
            <small class="muted">{{ r.created_at }}</small>
          </div>
          <div class="row" style="margin-top:8px;">
            <div><strong>Driver:</strong> {{ r.driver_name }}</div>
            <div><strong>Reg:</strong> {{ r.vehicle_reg }}</div>
          </div>
          {% if r.mileage %}<div style="margin-top:6px;"><strong>Mileage:</strong> {{ r.mileage }}</div>{% endif %}
          <div style="margin-top:6px;"><strong>Follow-up:</strong> {{ r.follow_up }}</div>
          <div style="margin-top:10px;">
            <strong>Checklist</strong>
            <ul style="margin:6px 0 0 18px;">
              {% for k, v in r.checklist.items() %}<li>{{ k }} — {{ v }}</li>{% endfor %}
            </ul>
          </div>
          {% if r.defect_notes %}
            <div style="margin-top:10px;"><strong>Defects</strong><div>{{ r.defect_notes }}</div></div>
          {% endif %}
          <div style="margin-top:10px;">
            <a class="btn secondary" href="{{ url_for('success', check_id=r.id) }}">Permalink</a>
          </div>
        </div>
      {% endfor %}
    </div>
  {% else %}
    <p>No checks yet.</p>
  {% endif %}
{% endblock %}
"""

# ----------------------- Routes -----------------------
from jinja2 import DictLoader
app.jinja_loader = DictLoader({"base.html": BASE_HTML})

@app.context_processor
def inject_globals():
    return {"app_name": APP_NAME, "db_enabled": db_enabled, "db_error": db_error}

@app.route("/")
def index():
    return redirect(url_for("check") if logged_in() else url_for("pin"))

@app.route("/pin", methods=["GET", "POST"])
def pin():
    if request.method == "POST":
        if request.form.get("pin", "").strip() == PIN_CODE:
            session["logged_in"] = True
            flash("Logged in.", "success")
            return redirect(url_for("check"))
        flash("Incorrect PIN.", "error")
    return render_template_string(PIN_HTML, title="Enter PIN")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("pin"))

@app.route("/check", methods=["GET", "POST"])
def check():
    if not logged_in():
        return redirect(url_for("pin"))

    checklist_items = [
        "Tyres & tread", "Lights & indicators", "Brakes", "Horn", "Mirrors",
        "Windscreen & wipers", "Screenwash", "Oil level", "Coolant level",
        "Seatbelts", "Doors secure", "Loads secured",
        "Bodywork damage", "Interior clean", "Exterior clean",
    ]

    if request.method == "POST":
        driver_name = request.form.get("driver_name", "").strip()
        vehicle_reg = request.form.get("vehicle_reg", "").strip()
        mileage = request.form.get("mileage", "").strip()
        follow_up = request.form.get("follow_up", "No").strip() or "No"
        defect_notes = request.form.get("defect_notes", "").strip()

        checklist = {}
        i = 0
        while True:
            lk = f"check_label__{i}"
            vk = f"check__{i}"
            if lk not in request.form:
                break
            checklist[request.form[lk]] = request.form.get(vk, "OK")
            i += 1

        if not driver_name or not vehicle_reg:
            flash("Driver name and Vehicle reg are required.", "error")
            return render_template_string(CHECK_HTML, title="Vehicle Check", checklist=checklist_items)

        try:
            if db_enabled and checks_table is not None:
                with engine.begin() as conn:
                    new_id = conn.execute(
                        insert(checks_table).values(
                            created_at=datetime.utcnow(),
                            driver_name=driver_name,
                            vehicle_reg=vehicle_reg.upper(),
                            mileage=mileage,
                            checklist=checklist,
                            defect_notes=defect_notes,
                            follow_up=follow_up,
                        ).returning(checks_table.c.id)
                    ).scalar_one()
                return redirect(url_for("success", check_id=new_id))
            else:
                memory_store["seq"] += 1
                rid = memory_store["seq"]
                memory_store["rows"].append({
                    "id": rid,
                    "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "driver_name": driver_name,
                    "vehicle_reg": vehicle_reg.upper(),
                    "mileage": mileage,
                    "checklist": checklist,
                    "defect_notes": defect_notes,
                    "follow_up": follow_up,
                })
                return redirect(url_for("success", check_id=rid))
        except OperationalError as e:
            flash(f"Database error: {e}", "error")

    return render_template_string(CHECK_HTML, title="Vehicle Check", checklist=checklist_items)

@app.route("/success/<int:check_id>")
def success(check_id: int):
    if not logged_in():
        return redirect(url_for("pin"))
    return render_template_string(SUCCESS_HTML, title="Submitted", check_id=check_id)

@app.route("/admin")
def admin():
    if not logged_in():
        return redirect(url_for("pin"))

    rows = []
    if db_enabled and checks_table is not None:
        try:
            with engine.begin() as conn:
                res = conn.execute(
                    select(
                        checks_table.c.id,
                        checks_table.c.created_at,
                        checks_table.c.driver_name,
                        checks_table.c.vehicle_reg,
                        checks_table.c.mileage,
                        checks_table.c.checklist,
                        checks_table.c.defect_notes,
                        checks_table.c.follow_up,
                    ).order_by(checks_table.c.id.desc()).limit(50)
                ).mappings().all()
            for r in res:
                rows.append({
                    "id": r["id"],
                    "created_at": r["created_at"].strftime("%Y-%m-%d %H:%M:%S"),
                    "driver_name": r["driver_name"],
                    "vehicle_reg": r["vehicle_reg"],
                    "mileage": r["mileage"],
                    "checklist": r["checklist"],
                    "defect_notes": r["defect_notes"],
                    "follow_up": r["follow_up"],
                })
        except Exception as e:
            flash(f"Failed to load admin list: {e}", "error")
    else:
        rows = memory_store["rows"][::-1][:50]

    return render_template_string(ADMIN_HTML, title="Recent Checks", rows=rows)

# ----------------------- Entrypoint -------------------
if __name__ == "__main__":
    # Create tables on startup if DB is enabled
    if db_enabled:
        metadata.create_all(engine)
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port)
