import os
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)

# --- Optional, but recommended for DB-backed persistence ---
from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    String,
    Text,
    DateTime,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import select, insert

# -----------------------
# Config
# -----------------------
PIN_CODE = os.getenv("PIN_CODE", "6633")  # keep your existing PIN unless overridden
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-please")  # set this in Render
DATABASE_URL = os.getenv("DATABASE_URL")  # e.g. Render Postgres connection string
APP_NAME = os.getenv("APP_NAME", "Driver / Vehicle Check")

# -----------------------
# Flask app
# -----------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# -----------------------
# Database (no disk usage)
# -----------------------
engine = None
metadata = MetaData()
checks_table = None
db_enabled = False
db_error = None

def _build_engine(db_url: str):
    """
    Builds an engine that works on Render. Render Postgres often needs SSL mode require.
    If the URL doesn’t include sslmode, add it.
    """
    if "sslmode=" not in db_url:
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}sslmode=require"
    return create_engine(db_url, pool_pre_ping=True)

def init_db():
    global engine, metadata, checks_table, db_enabled, db_error
    if not DATABASE_URL:
        db_enabled = False
        return

    try:
        engine = _build_engine(DATABASE_URL)

        # Use JSONB if Postgres, otherwise fall back to Text (e.g. for SQLite during dev)
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
            Column("checklist", checklist_type, nullable=False),  # dict of items -> "OK"/"Issue"
            Column("defect_notes", Text, nullable=True),
            Column("follow_up", String(10), nullable=False, default="No"),  # Yes/No
        )

        metadata.create_all(engine)
        # quick ping
        with engine.begin() as conn:
            conn.exec_driver_sql("SELECT 1")
        db_enabled = True
    except Exception as e:
        # If DB fails, app still runs (non-persistent mode)
        db_error = str(e)
        db_enabled = False

init_db()

# In-memory fallback store when DB is unavailable
memory_store = {
    "seq": 0,
    "rows": []
}

# -----------------------
# Auth helpers
# -----------------------
def logged_in():
    return session.get("logged_in") is True

def require_login():
    if not logged_in():
        return redirect(url_for("pin"))

# -----------------------
# Templates (inline to keep a single file)
# -----------------------
BASE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>{{ title or app_name }}</title>
    <style>
      :root { color-scheme: light dark; }
      body {
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        margin: 0; padding: 0; background: #0b0d10; color: #e8eaed;
      }
      .wrap { max-width: 900px; margin: 0 auto; padding: 24px; }
      .card { background: #111418; border: 1px solid #22252a; border-radius: 16px; padding: 20px; }
      h1, h2, h3 { margin: 0 0 12px; }
      label { display: block; margin-bottom: 6px; font-weight: 600; }
      input[type="text"], input[type="number"], textarea, select {
        width: 100%; padding: 10px 12px; border-radius: 10px;
        border: 1px solid #30343a; background: #0c0f13; color: #e8eaed;
      }
      textarea { min-height: 100px; }
      .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      .row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
      .row-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
      .row + .row, .row-3 + .row-3, .row-4 + .row-4 { margin-top: 12px; }
      .btn {
        display: inline-block; padding: 10px 16px; border-radius: 10px; border: 1px solid #3a6df0;
        background: #2a5ae8; color: white; text-decoration: none; cursor: pointer; font-weight: 600;
      }
      .btn.secondary { background: transparent; border: 1px solid #3a3f46; color: #e8eaed; }
      .grid { display: grid; gap: 12px; }
      .checks { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
      .check-item {
        border: 1px solid #22252a; border-radius: 12px; padding: 10px; background:#0c0f13;
      }
      .topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
      .flash { margin-bottom:12px; padding:10px 12px; border-radius:10px; background:#143d1f; border:1px solid #235a2f; }
      a { color: #7ea8ff; }
      @media (max-width: 700px) {
        .row, .row-3, .row-4 { grid-template-columns: 1fr; }
      }
      small.muted { color: #9aa0a6; }
      .error { background:#3d1414; border-color:#5a2323; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <h1>{{ app_name }}</h1>
        <div>
          {% if session.get('logged_in') %}
            <a href="{{ url_for('admin') }}" class="btn secondary">Admin</a>
            <a href="{{ url_for('logout') }}" class="btn secondary" style="margin-left:8px;">Logout</a>
          {% endif %}
        </div>
      </div>

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for cat, msg in messages %}
            <div class="flash {% if cat=='error' %}error{% endif %}">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      <div class="card">
        {% block content %}{% endblock %}
      </div>

      <p style="margin-top:18px;"><small class="muted">
        {% if not db_enabled %}
          Running without persistent DB (fallback). Set DATABASE_URL for persistence.
          {% if db_error %}<br/>DB error: {{ db_error }}{% endif %}
        {% else %}
          Backed by PostgreSQL (persistent).
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
  <form method="post" class="grid" style="margin-top:12px;">
    <label for="pin">PIN Code</label>
    <input id="pin" name="pin" type="text" inputmode="numeric" autocomplete="one-time-code" autofocus />
    <button class="btn" type="submit" style="margin-top:8px;">Continue</button>
  </form>
{% endblock %}
"""

CHECK_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Daily Vehicle Check</h2>
  <form method="post" class="grid" style="margin-top:12px;">
    <div class="row">
      <div>
        <label for="driver_name">Driver Name</label>
        <input id="driver_name" name="driver_name" type="text" required />
      </div>
      <div>
        <label for="vehicle_reg">Vehicle Reg</label>
        <input id="vehicle_reg" name="vehicle_reg" type="text" required />
      </div>
    </div>
    <div class="row">
      <div>
        <label for="mileage">Mileage (optional)</label>
        <input id="mileage" name="mileage" type="text" />
      </div>
      <div>
        <label for="follow_up">Requires Follow-up?</label>
        <select id="follow_up" name="follow_up">
          <option>No</option>
          <option>Yes</option>
        </select>
      </div>
    </div>

    <h3 style="margin-top:12px;">Checklist</h3>
    <div class="checks">
      {% for item in checklist %}
      <div class="check-item">
        <label>{{ item }}</label>
        <select name="check__{{ loop.index0 }}">
          <option>OK</option>
          <option>Issue</option>
        </select>
        <input type="hidden" name="check_label__{{ loop.index0 }}" value="{{ item }}" />
      </div>
      {% endfor %}
    </div>

    <div style="margin-top:12px;">
      <label for="defect_notes">Defect Notes (if any)</label>
      <textarea id="defect_notes" name="defect_notes" placeholder="Describe any issues found..."></textarea>
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
    <a class="btn secondary" style="margin-left:8px;" href="{{ url_for('admin') }}">View Recent</a>
  </div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Recent Checks</h2>
  {% if rows %}
    <div class="grid" style="margin-top:12px;">
      {% for r in rows %}
        <div class="card" style="border-radius:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong>#{{ r.id }}</strong>
            <small class="muted">{{ r.created_at }}</small>
          </div>
          <div class="row" style="margin-top:8px;">
            <div><strong>Driver:</strong> {{ r.driver_name }}</div>
            <div><strong>Reg:</strong> {{ r.vehicle_reg }}</div>
          </div>
          {% if r.mileage %}
          <div style="margin-top:6px;"><strong>Mileage:</strong> {{ r.mileage }}</div>
          {% endif %}
          <div style="margin-top:6px;"><strong>Follow-up:</strong> {{ r.follow_up }}</div>

          <div style="margin-top:10px;">
            <strong>Checklist</strong>
            <ul style="margin:6px 0 0 18px;">
              {% for k, v in r.checklist.items() %}
                <li>{{ k }} — {{ v }}</li>
              {% endfor %}
            </ul>
          </div>

          {% if r.defect_notes %}
          <div style="margin-top:10px;">
            <strong>Defects</strong>
            <div>{{ r.defect_notes }}</div>
          </div>
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

# -----------------------
# Routes
# -----------------------
@app.route("/")
def index():
    if not logged_in():
        return redirect(url_for("pin"))
    return redirect(url_for("check"))

@app.route("/pin", methods=["GET", "POST"])
def pin():
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        if pin == PIN_CODE:
            session["logged_in"] = True
            flash("Logged in.", "success")
            return redirect(url_for("check"))
        flash("Incorrect PIN.", "error")
    return render_template_string(PIN_HTML, title="Enter PIN", app_name=APP_NAME, db_enabled=db_enabled, db_error=db_error)

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
        "Tyres & tread",
        "Lights & indicators",
        "Brakes",
        "Horn",
        "Mirrors",
        "Windscreen & wipers",
        "Screenwash",
        "Oil level",
        "Coolant level",
        "Seatbelts",
        "Doors secure",
        "Loads secured",
        "Bodywork damage",
        "Interior clean",
        "Exterior clean",
    ]

    if request.method == "POST":
        driver_name = request.form.get("driver_name", "").strip()
        vehicle_reg = request.form.get("vehicle_reg", "").strip()
        mileage = request.form.get("mileage", "").strip()
        follow_up = request.form.get("follow_up", "No").strip() or "No"
        defect_notes = request.form.get("defect_notes", "").strip()

        # Build checklist dict from posted fields
        checklist = {}
        idx = 0
        while True:
            label_key = f"check_label__{idx}"
            value_key = f"check__{idx}"
            if label_key not in request.form:
                break
            label = request.form.get(label_key)
            value = request.form.get(value_key, "OK")
            checklist[label] = value
            idx += 1

        if not driver_name or not vehicle_reg:
            flash("Driver name and Vehicle reg are required.", "error")
            return render_template_string(
                CHECK_HTML,
                title="Vehicle Check",
                app_name=APP_NAME,
                checklist=checklist_items,
                db_enabled=db_enabled,
                db_error=db_error
            )

        # Persist
        try:
            if db_enabled and checks_table is not None:
                with engine.begin() as conn:
                    stmt = insert(checks_table).values(
                        created_at=datetime.utcnow(),
                        driver_name=driver_name,
                        vehicle_reg=vehicle_reg.upper(),
                        mileage=mileage,
                        checklist=checklist,
                        defect_notes=defect_notes,
                        follow_up=follow_up,
                    ).returning(checks_table.c.id)
                    new_id = conn.execute(stmt).scalar_one()
                return redirect(url_for("success", check_id=new_id))
            else:
                # Fallback (non-persistent)
                memory_store["seq"] += 1
                new_id = memory_store["seq"]
                memory_store["rows"].append({
                    "id": new_id,
                    "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "driver_name": driver_name,
                    "vehicle_reg": vehicle_reg.upper(),
                    "mileage": mileage,
                    "checklist": checklist,
                    "defect_notes": defect_notes,
                    "follow_up": follow_up,
                })
                return redirect(url_for("success", check_id=new_id))
        except OperationalError as e:
            flash(f"Database error: {e}", "error")

    return render_template_string(
        CHECK_HTML,
        title="Vehicle Check",
        app_name=APP_NAME,
        checklist=checklist_items,
        db_enabled=db_enabled,
        db_error=db_error
    )

@app.route("/success/<int:check_id>")
def success(check_id: int):
    if not logged_in():
        return redirect(url_for("pin"))
    return render_template_string(
        SUCCESS_HTML,
        title="Submitted",
        app_name=APP_NAME,
        check_id=check_id,
        db_enabled=db_enabled,
        db_error=db_error
    )

@app.route("/admin")
def admin():
    if not logged_in():
        return redirect(url_for("pin"))

    rows = []
    if db_enabled and checks_table is not None:
        try:
            with engine.begin() as conn:
                stmt = select(
                    checks_table.c.id,
                    checks_table.c.created_at,
                    checks_table.c.driver_name,
                    checks_table.c.vehicle_reg,
                    checks_table.c.mileage,
                    checks_table.c.checklist,
                    checks_table.c.defect_notes,
                    checks_table.c.follow_up,
                ).order_by(checks_table.c.id.desc()).limit(50)
                res = conn.execute(stmt).mappings().all()
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

    return render_template_string(
        ADMIN_HTML,
        title="Recent Checks",
        app_name=APP_NAME,
        rows=rows,
        db_enabled=db_enabled,
        db_error=db_error
    )

# -----------------------
# Jinja template loader
# -----------------------
@app.context_processor
def inject_globals():
    return {"app_name": APP_NAME, "db_enabled": db_enabled, "db_error": db_error}

@app.before_request
def set_base_template():
    # Register the base template each request (keeps single-file ergonomics)
    app.jinja_env.globals["base_html"] = BASE_HTML

@app.route("/_base_template")  # debug helper if needed
def _base_template():
    return render_template_string(BASE_HTML, title="Base", app_name=APP_NAME, db_enabled=db_enabled, db_error=db_error)

# Jinja needs a named template for extends; we provide it via a loader trick.
from jinja2 import DictLoader
app.jinja_loader = DictLoader({
    "base.html": BASE_HTML,
})

# -----------------------
# Entrypoint
# -----------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port)
# app.py
import os
import io
import csv
import json
import base64
import secrets
import datetime as dt
import threading
import smtplib
import socket
from email.message import EmailMessage

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    session, send_from_directory, flash, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from PIL import Image

# --------------------------- App / Config ---------------------------
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'sqlite:///app.db'
).replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
DRIVER_PIN = os.getenv('DRIVER_PIN', '6633')
CRON_SECRET = os.getenv('CRON_SECRET', '')

# Email (optional)
MAIL_HOST = os.getenv('MAIL_HOST', '')
MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
MAIL_USER = os.getenv('MAIL_USER', '')
MAIL_PASS = os.getenv('MAIL_PASS', '')
MAIL_TO   = os.getenv('MAIL_TO', MAIL_USER or '')

db = SQLAlchemy(app)

# --------------------------- Models --------------------------------
class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg = db.Column(db.String(20), unique=True, nullable=False)
    make_model = db.Column(db.String(120), nullable=True)
    checks = db.relationship('Check', backref='vehicle', lazy=True)

class Check(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    driver_name = db.Column(db.String(120))
    mileage = db.Column(db.String(40))
    notes = db.Column(db.Text)
    items_json = db.Column(db.Text)  # list[dict]: section,label,status,comment
    signature_path = db.Column(db.String(255))  # filename only
    photos = db.relationship('Photo', backref='check', lazy=True, cascade="all,delete")

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey('check.id'), nullable=False)
    path = db.Column(db.String(255))         # filename only
    drive_file_id = db.Column(db.String(120))  # reserved (optional)

# --------------------------- Checklist Items ------------------------
CHECK_ITEMS = [
    {"section": "Tyre", "label": "Tyre – Tread Depth (min 1.6mm)"},
    {"section": "Tyre", "label": "Tyre – Inflation Pressure"},
    {"section": "Tyre", "label": "Tyre – Cracks and Cuts"},
    {"section": "Engine", "label": "Engine – Oil Level"},
    {"section": "Engine", "label": "Engine – Coolant Level"},
    {"section": "Engine", "label": "Engine – Brake Fluid Level"},
    {"section": "Engine", "label": "Engine – Clutch Fluid Level"},
    {"section": "Engine", "label": "Engine – Battery Water Level"},
    {"section": "Engine", "label": "Engine – Steering Fluid"},
    {"section": "Engine", "label": "Engine – Fuel"},
    {"section": "Engine", "label": "Engine – Battery (not leaking and secure)"},
    {"section": "Light", "label": "Light – Interior"},
    {"section": "Light", "label": "Light – Turn"},
    {"section": "Light", "label": "Light – Reverse"},
    {"section": "Light", "label": "Light – Tail"},
    {"section": "Light", "label": "Light – Emergency"},
    {"section": "Accessory", "label": "Accessory – Tape/Radio"},
    {"section": "Control", "label": "Control – Horn"},
    {"section": "Control", "label": "Control – Engine Start"},
    {"section": "Control", "label": "Control – Central Lock"},
    {"section": "Control", "label": "Control – Power Window"},
    {"section": "Control", "label": "Control – Heater/AC"},
    {"section": "Control", "label": "Control – Auto/Manual transmission Operation"},
    {"section": "Control", "label": "Control – Brake Operation"},
    {"section": "Control", "label": "Control – Wipers/washers"},
    {"section": "Control", "label": "Control – Steering Operation"},
    {"section": "Tool", "label": "Tool – Jack and Wheel Spanner"},
    {"section": "Tool", "label": "Tool – First Aid Kit"},
    {"section": "Exterior", "label": "Exterior – Mirrors and glass"},
    {"section": "Exterior", "label": "Exterior – Exhaust (doesn’t emit excessive smoke)"},
    {"section": "Exterior", "label": "Exterior – Body work & Doors (any damage)"},
    {"section": "Interior", "label": "Interior – Seats and seatbelts (secure, operate, no damage)"},
]

# --------------------------- Helpers --------------------------------
def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def _wrap(*a, **kw):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return fn(*a, **kw)
    return _wrap

def driver_required(fn):
    from functools import wraps
    @wraps(fn)
    def _wrap(*a, **kw):
        if not session.get('driver_ok'):
            return redirect(url_for('pin'))
        return fn(*a, **kw)
    return _wrap

def allowed_file(filename: str) -> bool:
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------------------------- PDF Builder ----------------------------
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

def build_pdf_bytes(check: Check, items: list[dict]) -> bytes:
    """Create a simple PDF summarising the check; return raw bytes."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    y = H - 20*mm

    def line(txt, size=10, dy=6*mm):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(20*mm, y, txt)
        y -= dy
        if y < 20*mm:
            c.showPage(); y = H - 20*mm

    # Header
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20*mm, y, "Vehicle Check")
    y -= 10*mm
    vm = f" ({check.vehicle.make_model})" if (check.vehicle and check.vehicle.make_model) else ""
    line(f"Vehicle: {check.vehicle.reg}{vm}")
    line(f"Date: {check.created_at.strftime('%Y-%m-%d %H:%M')}")
    if check.mileage: line(f"Mileage: {check.mileage}")
    if check.driver_name: line(f"Driver: {check.driver_name}")

    # Items
    y -= 4*mm
    c.setFont("Helvetica-Bold", 11); c.drawString(20*mm, y, "Checklist"); y -= 7*mm
    c.setFont("Helvetica", 10)
    current_section = None
    for it in items:
        sec = it.get('section') or ''
        if sec and sec != current_section:
            line(f"[{sec}]", size=11, dy=6*mm)
            current_section = sec
        label   = it.get('label', '')
        status  = (it.get('status') or '').upper() or '-'
        comment = it.get('comment') or ''
        line(f"{label} — {status}")
        if comment:
            line(f"   Notes: {comment}", size=9, dy=5*mm)

    # Photos
    if check.photos:
        y -= 5*mm
        c.setFont("Helvetica-Bold", 11); c.drawString(20*mm, y, "Photos"); y -= 7*mm
        x = 20*mm
        thumb_h = 35*mm
        for p in check.photos:
            path = os.path.join(app.config['UPLOAD_FOLDER'], p.path)
            if os.path.exists(path):
                try:
                    c.drawImage(path, x, y - thumb_h, width=50*mm, height=thumb_h,
                                preserveAspectRatio=True, anchor='sw')
                    x += 55*mm
                    if x > W - 60*mm:
                        x = 20*mm
                        y -= thumb_h + 8*mm
                        if y < 30*mm:
                            c.showPage(); y = H - 20*mm
                except Exception:
                    pass

    # Signature
    if check.signature_path:
        y -= 10*mm
        c.setFont("Helvetica-Bold", 11); c.drawString(20*mm, y, "Driver signature"); y -= 7*mm
        sigp = os.path.join(app.config['UPLOAD_FOLDER'], check.signature_path)
        if os.path.exists(sigp):
            try:
                c.drawImage(sigp, 20*mm, max(20*mm, y - 30*mm), width=60*mm, height=30*mm,
                            preserveAspectRatio=True, anchor='sw')
                y -= 35*mm
            except Exception:
                pass

    c.showPage(); c.save()
    pdf = buf.getvalue()
    buf.close()
    return pdf

# --------------------------- Email Sending --------------------------
def send_submission_email(check: Check, items: list[dict]):
    """Send PDF by email; never block request if SMTP is slow."""
    host = os.getenv('MAIL_HOST')
    if not host:
        app.logger.info('MAIL_HOST not set; skipping email.')
        return

    port = int(os.getenv('MAIL_PORT', '587'))
    user = os.getenv('MAIL_USER', '')
    pwd  = os.getenv('MAIL_PASS', '')
    to   = os.getenv('MAIL_TO') or user
    if not user or not pwd or not to:
        app.logger.info('MAIL_USER/MAIL_PASS/MAIL_TO not fully set; skipping email.')
        return

    msg = EmailMessage()
    msg['Subject'] = f"Vehicle Check - {check.vehicle.reg} - {check.created_at:%Y-%m-%d %H:%M}"
    msg['From'] = user
    msg['To'] = to
    msg.set_content("Attached: vehicle check PDF.")

    pdf_bytes = build_pdf_bytes(check, items)
    msg.add_attachment(pdf_bytes, maintype='application', subtype='pdf',
                       filename=f"check_{check.id}.pdf")

    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
        app.logger.info('Submission email sent.')
    except (smtplib.SMTPException, socket.timeout, OSError) as e:
        app.logger.warning(f'Submission email failed: {e}')

def send_simple_email(subject: str, body: str):
    host = os.getenv('MAIL_HOST')
    if not host:
        return
    port = int(os.getenv('MAIL_PORT', '587'))
    user = os.getenv('MAIL_USER', '')
    pwd  = os.getenv('MAIL_PASS', '')
    to   = os.getenv('MAIL_TO') or user
    if not user or not pwd or not to:
        return
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = user
    msg['To'] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo(); s.starttls(); s.login(user, pwd)
            s.send_message(msg)
    except Exception as e:
        app.logger.warning(f'Cron email failed: {e}')

# --------------------------- Routes (Driver) ------------------------
@app.route('/')
def home():
    return redirect(url_for('check') if session.get('driver_ok') else url_for('pin'))

@app.route('/pin', methods=['GET', 'POST'])
def pin():
    if request.method == 'POST':
        if request.form.get('pin') == str(DRIVER_PIN):
            session['driver_ok'] = True
            return redirect(url_for('check'))
        flash('Incorrect PIN')
    return render_template_string(TPL_PIN)

@app.route('/logout')
def logout():
    session.pop('driver_ok', None)
    return redirect(url_for('pin'))

@app.route('/check', methods=['GET', 'POST'])
@driver_required
def check():
    vehicles = Vehicle.query.order_by(Vehicle.reg).all()
    if request.method == 'POST':
        return new_check(vehicles)
    return render_template_string(
        TPL_FORM, vehicles=vehicles, CHECK_ITEMS=CHECK_ITEMS
    )

def new_check(vehicles):
    reg = request.form.get('vehicle_reg')
    vehicle = Vehicle.query.filter_by(reg=reg).first()
    if not vehicle:
        flash('Please select a vehicle')
        return render_template_string(TPL_FORM, vehicles=vehicles, CHECK_ITEMS=CHECK_ITEMS)

    c = Check(vehicle_id=vehicle.id)
    c.driver_name = (request.form.get('driver_name') or '').strip()
    c.mileage = (request.form.get('mileage') or '').strip()
    c.notes = (request.form.get('notes') or '').strip()

    # items
    items = []
    for idx, it in enumerate(CHECK_ITEMS):
        status = request.form.get(f'item_status_{idx}', '')
        comment = (request.form.get(f'item_comment_{idx}', '') or '').strip()
        items.append({'section': it['section'], 'label': it['label'],
                      'status': status, 'comment': comment})
    c.items_json = json.dumps(items)

    # signature (dataURL)
    sig_data = request.form.get('signature_data') or ''
    if sig_data.startswith('data:image/png;base64,'):
        img_b64 = sig_data.split(',', 1)[1]
        sig_name = f"sig_{dt.datetime.utcnow():%Y%m%d%H%M%S}_{secrets.token_hex(4)}.png"
        sig_path = os.path.join(app.config['UPLOAD_FOLDER'], sig_name)
        with open(sig_path, 'wb') as f:
            f.write(base64.b64decode(img_b64))
        c.signature_path = sig_name

    db.session.add(c)
    db.session.flush()  # ensure c.id

    # photos
    files = request.files.getlist('photos')
    for f in files:
        try:
            if not f or not getattr(f, 'filename', ''):
                continue
            filename = f.filename
            if not allowed_file(filename):
                continue
            safe = secure_filename(f"{c.id}_{int(dt.datetime.utcnow().timestamp())}_{filename}")
            fpath = os.path.join(app.config['UPLOAD_FOLDER'], safe)
            try:
                img = Image.open(f.stream)
                if img.mode not in ('RGB', 'RGBA'):
                    img = img.convert('RGB')
                img.thumbnail((2000, 2000))
                img.save(fpath, optimize=True, quality=85)
            except Exception:
                f.stream.seek(0)
                with open(fpath, 'wb') as out:
                    out.write(f.read())
            db.session.add(Photo(check_id=c.id, path=safe))
        except Exception:
            app.logger.exception('Failed to process uploaded photo')

    db.session.commit()

    # fire-and-forget email
    try:
        threading.Thread(target=send_submission_email, args=(c, items), daemon=True).start()
    except Exception:
        app.logger.exception('Failed to start email thread')

    return redirect(url_for('success', check_id=c.id))

@app.route('/success/<int:check_id>')
def success(check_id):
    return render_template_string(TPL_SUCCESS, check_id=check_id)

# --------------------------- Admin ---------------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == str(ADMIN_PASSWORD):
            session['admin'] = True
            return redirect(url_for('admin'))
        flash('Wrong password')
    return render_template_string(TPL_ADMIN_LOGIN)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin():
    checks = Check.query.order_by(Check.created_at.desc()).limit(200).all()
    vehicles = Vehicle.query.order_by(Vehicle.reg).all()
    return render_template_string(TPL_ADMIN, checks=checks, vehicles=vehicles)

@app.route('/admin/check/<int:check_id>')
@admin_required
def admin_check(check_id):
    c = Check.query.get_or_404(check_id)
    items = json.loads(c.items_json or '[]')
    return render_template_string(TPL_ADMIN_CHECK, c=c, items=items)

@app.route('/admin/vehicles', methods=['POST'])
@admin_required
def admin_vehicles():
    action = request.form.get('action')
    if action == 'add':
        reg = (request.form.get('reg') or '').strip().upper()
        mm  = (request.form.get('make_model') or '').strip()
        if reg and not Vehicle.query.filter_by(reg=reg).first():
            db.session.add(Vehicle(reg=reg, make_model=mm))
            db.session.commit()
    elif action == 'delete':
        vid = request.form.get('id')
        v = Vehicle.query.get(int(vid)) if vid else None
        if v:
            db.session.delete(v); db.session.commit()
    elif action == 'update':
        vid = request.form.get('id')
        mm  = (request.form.get('make_model') or '').strip()
        v = Vehicle.query.get(int(vid)) if vid else None
        if v:
            v.make_model = mm; db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/export.csv')
@admin_required
def export_csv():
    # quick CSV export of recent checks
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(['id','created_at','vehicle_reg','make_model','driver_name','mileage','notes','items_json'])
    for c in Check.query.order_by(Check.created_at.desc()).all():
        w.writerow([
            c.id, c.created_at.isoformat(timespec='seconds'),
            c.vehicle.reg if c.vehicle else '',
            c.vehicle.make_model if c.vehicle else '',
            c.driver_name or '', c.mileage or '', (c.notes or '').replace('\n',' '),
            c.items_json or '[]'
        ])
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename="checks.csv"'
    return resp

# --------------------------- Cron (monthly) -------------------------
def _ensure_cron_token():
    token = request.args.get('token', '')
    if not CRON_SECRET or token != CRON_SECRET:
        abort(403)

def _vehicles_missing_for_month(year: int, month: int):
    # vehicles without a check in given year/month
    start = dt.datetime(year, month, 1)
    end = (start + dt.timedelta(days=32)).replace(day=1)
    have = {c.vehicle_id for c in Check.query.filter(Check.created_at >= start, Check.created_at < end).all()}
    all_vs = Vehicle.query.all()
    return [v for v in all_vs if v.id not in have]

@app.route('/cron/monthly/due')
def cron_due():
    _ensure_cron_token()
    now = dt.datetime.utcnow()
    miss = _vehicles_missing_for_month(now.year, now.month)
    body = "Vehicles due for monthly checks (1st notice):\n" + "\n".join(f"{v.reg} {v.make_model or ''}" for v in miss) if miss else "All vehicles checked."
    send_simple_email("Monthly vehicle check – Due", body)
    return {"ok": True, "missing": [v.reg for v in miss]}

@app.route('/cron/monthly/amber')
def cron_amber():
    _ensure_cron_token()
    now = dt.datetime.utcnow()
    miss = _vehicles_missing_for_month(now.year, now.month)
    body = "Vehicles overdue (amber):\n" + "\n".join(f"{v.reg} {v.make_model or ''}" for v in miss) if miss else "All vehicles checked."
    send_simple_email("Monthly vehicle check – Overdue (Amber)", body)
    return {"ok": True, "missing": [v.reg for v in miss]}

@app.route('/cron/monthly/red')
def cron_red():
    _ensure_cron_token()
    now = dt.datetime.utcnow()
    miss = _vehicles_missing_for_month(now.year, now.month)
    body = "Vehicles overdue (RED):\n" + "\n".join(f"{v.reg} {v.make_model or ''}" for v in miss) if miss else "All vehicles checked."
    send_simple_email("Monthly vehicle check – OVERDUE (RED)", body)
    return {"ok": True, "missing": [v.reg for v in miss]}

# --------------------------- Static / PWA ---------------------------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/manifest.webmanifest')
def manifest():
    return make_response(TPL_MANIFEST, 200, {'Content-Type': 'application/manifest+json'})

@app.route('/sw.js')
def sw():
    resp = make_response(TPL_SW, 200)
    resp.headers['Content-Type'] = 'application/javascript'
    return resp

# --------------------------- CLI init -------------------------------
@app.cli.command('init-db')
def init_db():
    db.create_all()
    if not Vehicle.query.first():
        db.session.add(Vehicle(reg='AB12CDE', make_model='Ford Transit'))
        db.session.add(Vehicle(reg='XY34ZFG', make_model='VW Caddy'))
        db.session.commit()
    print('DB initialised ✅')

# --------------------------- Templates ------------------------------
TPL_BASE = r"""
<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="manifest" href="{{ url_for('manifest') }}">
  <link rel="icon" href="{{ url_for('static', filename='logo.png') }}">
  <title>{{ title or 'Vehicle Check' }}</title>
  <style>
    body{font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji'; margin:0; background:#111; color:#e9e9e9}
    .wrap{max-width:1100px;margin:0 auto;padding:16px}
    .card{background:#1a1a1a;border:1px solid #2b2b2b;border-radius:12px;margin:12px 0;padding:16px}
    input,select,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #2d2d2d;background:#0f0f0f;color:#e9e9e9}
    label{display:block;margin:6px 0 4px;color:#bbb}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .col{flex:1 1 260px}
    .btn{background:#0ea5e9;color:white;border:0;border-radius:10px;padding:10px 14px;cursor:pointer}
    .btn.alt{background:#2e2e2e}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #3b3b3b;font-size:12px}
    .grid{display:grid;grid-template-columns:1fr 120px 1fr;gap:8px;align-items:center}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #2a2a2a}
    h1,h2,h3,h4,h5{margin:0 0 8px}
    small{color:#9a9a9a}
    canvas.sig{border:1px dashed #666; width:100%; height:180px; background:#fff}
    .section{margin-top:16px;border-top:1px solid #2a2a2a;padding-top:12px}
  </style>
</head>
<body>
<div class="wrap">
  {% with msgs = get_flashed_messages() %}
  {% if msgs %}<div class="card" style="border-color:#ef4444;background:#1e1b1b">
    {% for m in msgs %}<div>{{ m }}</div>{% endfor %}
  </div>{% endif %}{% endwith %}
  {{ content|safe }}
</div>
<script>
  if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js'); }
</script>
</body></html>
"""

TPL_PIN = """
{% set title='Driver PIN' %}
{% set content %}
<div class="card">
  <h3>Driver sign-in</h3>
  <form method="post">
    <label>Enter PIN</label>
    <input name="pin" type="password" inputmode="numeric" autocomplete="one-time-code" required>
    <div style="margin-top:10px"><button class="btn">Continue</button></div>
    <div class="section"><small>Tip: save this page to your home screen to use it like an app.</small></div>
  </form>
</div>
{% endset %}
""" + TPL_BASE

TPL_FORM = """
{% set title='Vehicle Check' %}
{% set content %}
<div class="card">
  <h3>Vehicle & Driver</h3>
  <form method="post" enctype="multipart/form-data">
    <div class="row">
      <div class="col">
        <label>Vehicle (reg)</label>
        <select name="vehicle_reg" id="vehicle_reg" required>
          <option value="" disabled selected>Select vehicle</option>
          {% for v in vehicles %}
          <option value="{{ v.reg }}" data-mm="{{ v.make_model or '' }}">{{ v.reg }}</option>
          {% endfor %}
        </select>
        <small>Make & model autofill below.</small>
      </div>
      <div class="col">
        <label>Make & model</label>
        <input id="mm" type="text" readonly>
      </div>
      <div class="col">
        <label>Driver name</label>
        <input name="driver_name" placeholder="Optional">
      </div>
      <div class="col">
        <label>Mileage</label>
        <input name="mileage" inputmode="numeric" placeholder="e.g. 73421">
      </div>
    </div>

    <div class="section">
      <h4>Checklist</h4>
      <div class="grid" style="font-weight:600;color:#bbb"><div>Item</div><div>Status</div><div>Comment</div></div>
      {% for item in CHECK_ITEMS %}
        {% if loop.first or (item.section != CHECK_ITEMS[loop.index0-1].section) %}
        <div style="margin-top:12px;color:#9aa" class="section"><strong>{{ item.section }}</strong></div>
        {% endif %}
        <div class="grid">
          <div>{{ item.label }}</div>
          <div>
            <label class="pill"><input type="radio" name="item_status_{{ loop.index0 }}" value="pass"> Pass</label>
            <label class="pill"><input type="radio" name="item_status_{{ loop.index0 }}" value="fail"> Fail</label>
          </div>
          <div><input name="item_comment_{{ loop.index0 }}" placeholder="(optional)"></div>
        </div>
      {% endfor %}
    </div>

    <div class="section">
      <h4>Photos</h4>
      <input type="file" name="photos" accept="image/*" multiple capture="environment">
      <small>You can add multiple images.</small>
    </div>

    <div class="section">
      <h4>Driver Signature</h4>
      <canvas id="sig" class="sig"></canvas>
      <input type="hidden" name="signature_data" id="signature_data">
      <div style="margin-top:8px">
        <button type="button" class="btn alt" onclick="sigClear()">Clear</button>
      </div>
    </div>

    <div class="section">
      <label>Additional notes</label>
      <textarea name="notes" rows="3" placeholder="Anything else to record?"></textarea>
    </div>

    <div style="margin-top:12px">
      <button class="btn">Submit Check</button>
      <a href="{{ url_for('logout') }}" class="btn alt">Sign out</a>
    </div>
  </form>
</div>

<script>
  // Make/Model autofill
  const sel = document.getElementById('vehicle_reg');
  const mm  = document.getElementById('mm');
  sel?.addEventListener('change', e => {
    const opt = sel.selectedOptions[0];
    mm.value = opt ? (opt.getAttribute('data-mm') || '') : '';
  });

  // very small signature pad
  const canvas = document.getElementById('sig');
  const ctx = canvas.getContext('2d');
  function resize(){ const r = canvas.getBoundingClientRect();
    const tmp = ctx.getImageData(0,0,canvas.width,canvas.height);
    canvas.width = r.width; canvas.height = r.height; ctx.putImageData(tmp,0,0);
  }
  window.addEventListener('resize', resize); resize();
  ctx.lineWidth = 2; ctx.lineJoin='round'; ctx.strokeStyle='#111';
  let drawing=false; let last={x:0,y:0};
  function pos(ev){ const rect = canvas.getBoundingClientRect();
    const e = ev.touches? ev.touches[0] : ev; return {x:e.clientX-rect.left, y:e.clientY-rect.top}; }
  canvas.addEventListener('mousedown',e=>{drawing=true; last=pos(e);});
  canvas.addEventListener('touchstart',e=>{drawing=true; last=pos(e);});
  function draw(e){ if(!drawing) return; const p=pos(e); ctx.beginPath(); ctx.moveTo(last.x,last.y); ctx.lineTo(p.x,p.y); ctx.stroke(); last=p; e.preventDefault();}
  canvas.addEventListener('mousemove',draw); canvas.addEventListener('touchmove',draw,{passive:false});
  window.addEventListener('mouseup',()=>drawing=false); window.addEventListener('touchend',()=>drawing=false);
  function sigClear(){ ctx.clearRect(0,0,canvas.width,canvas.height); }
  window.sigClear = sigClear;

  // on submit pack signature
  document.querySelector('form').addEventListener('submit', ()=>{
    document.getElementById('signature_data').value = canvas.toDataURL('image/png');
  });
</script>
{% endset %}
""" + TPL_BASE

TPL_SUCCESS = """
{% set title='Submitted' %}
{% set content %}
<div class="card">
  <h3>Thanks!</h3>
  <p>Your check (#{{ check_id }}) has been submitted successfully.</p>
  <p><a class="btn" href="{{ url_for('check') }}">Do another</a></p>
</div>
{% endset %}
""" + TPL_BASE

TPL_ADMIN_LOGIN = """
{% set title='Admin Login' %}
{% set content %}
<div class="card">
  <h3>Admin login</h3>
  <form method="post">
    <label>Password</label>
    <input name="password" type="password" required>
    <div style="margin-top:10px"><button class="btn">Sign in</button></div>
  </form>
</div>
{% endset %}
""" + TPL_BASE

TPL_ADMIN = """
{% set title='Admin' %}
{% set content %}
<div class="row">
  <div class="col">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h3>Recent checks</h3>
        <div>
          <a class="btn alt" href="{{ url_for('export_csv') }}">Export CSV</a>
          <a class="btn alt" href="{{ url_for('admin_logout') }}">Logout</a>
        </div>
      </div>
      <table>
        <tr><th>ID</th><th>When</th><th>Vehicle</th><th>Driver</th><th></th></tr>
        {% for c in checks %}
        <tr>
          <td>#{{ c.id }}</td>
          <td>{{ c.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
          <td>{{ c.vehicle.reg if c.vehicle else '?' }} <small>{{ c.vehicle.make_model if c.vehicle else '' }}</small></td>
          <td>{{ c.driver_name or '-' }}</td>
          <td><a class="btn" href="{{ url_for('admin_check', check_id=c.id) }}">View</a></td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>
  <div class="col">
    <div class="card">
      <h3>Vehicles</h3>
      <form method="post" action="{{ url_for('admin_vehicles') }}">
        <input type="hidden" name="action" value="add">
        <div class="row">
          <div class="col"><label>Reg</label><input name="reg" required placeholder="AB12CDE"></div>
          <div class="col"><label>Make & model</label><input name="make_model" placeholder="Ford Transit"></div>
        </div>
        <div style="margin-top:8px"><button class="btn">Add vehicle</button></div>
      </form>
      <div class="section">
        <table>
          <tr><th>Reg</th><th>Make & model</th><th>Actions</th></tr>
          {% for v in vehicles %}
          <tr>
            <td>{{ v.reg }}</td>
            <td>
              <form method="post" action="{{ url_for('admin_vehicles') }}" style="display:flex;gap:6px;align-items:center">
                <input type="hidden" name="id" value="{{ v.id }}">
                <input type="hidden" name="action" value="update">
                <input name="make_model" value="{{ v.make_model or '' }}">
                <button class="btn alt">Save</button>
              </form>
            </td>
            <td>
              <form method="post" action="{{ url_for('admin_vehicles') }}" onsubmit="return confirm('Delete vehicle?');">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="id" value="{{ v.id }}">
                <button class="btn" style="background:#ef4444">Delete</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>
  </div>
</div>
{% endset %}
""" + TPL_BASE

TPL_ADMIN_CHECK = """
{% set title='Check #' ~ c.id %}
{% set content %}
<div class="card">
  <h3>Check #{{ c.id }}</h3>
  <p><strong>{{ c.vehicle.reg }}</strong> <small>{{ c.vehicle.make_model or '' }}</small></p>
  <p><small>{{ c.created_at.strftime('%Y-%m-%d %H:%M') }}</small></p>
  <p>Driver: {{ c.driver_name or '-' }} &nbsp; | &nbsp; Mileage: {{ c.mileage or '-' }}</p>
  {% if c.notes %}<p><em>Notes:</em> {{ c.notes }}</p>{% endif %}
  <div class="section">
    <h4>Items</h4>
    <table>
      <tr><th>Section</th><th>Item</th><th>Status</th><th>Comment</th></tr>
      {% for it in items %}
      <tr>
        <td>{{ it.section }}</td>
        <td>{{ it.label }}</td>
        <td>{{ (it.status or '').upper() }}</td>
        <td>{{ it.comment or '' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
  <div class="section">
    <h4>Photos</h4>
    {% if c.photos %}
      <div class="row">
      {% for p in c.photos %}
        <div class="col">
          <img src="{{ url_for('uploaded_file', filename=p.path) }}" style="max-width:100%;border:1px solid #333;border-radius:8px">
        </div>
      {% endfor %}
      </div>
    {% else %}
      <p><small>No photos</small></p>
    {% endif %}
  </div>
  <div class="section">
    <h4>Driver Signature</h4>
    {% if c.signature_path %}
      <img src="{{ url_for('uploaded_file', filename=c.signature_path) }}" style="max-width:320px;border:1px dashed #555;background:#fff">
    {% else %}
      <p><small>No signature</small></p>
    {% endif %}
  </div>
  <p><a class="btn alt" href="{{ url_for('admin') }}">Back</a></p>
</div>
{% endset %}
""" + TPL_BASE

# PWA resources
TPL_MANIFEST = """{
  "name": "Driver Vehicle Check",
  "short_name": "VehicleCheck",
  "start_url": "/pin",
  "display": "standalone",
  "background_color": "#111111",
  "theme_color": "#111111",
  "icons": [
    {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png"},
    {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png"}
  ]
}"""

TPL_SW = """
self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { self.clients.claim(); });
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/static/') || url.pathname.startsWith('/uploads/') || url.pathname == '/manifest.webmanifest') {
    e.respondWith(fetch(e.request));
  }
});
"""

# --------------------------- Main -----------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.getenv('PORT', '5001'))
    app.run(host='0.0.0.0', port=port, debug=True)

