import os
import io
import re
import json
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, flash
)

# DB
from sqlalchemy import (
    create_engine, MetaData, Table, Column,
    Integer, String, Text, DateTime
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import select, insert, text as sqltext

# Email
import smtplib
from email.message import EmailMessage

# Google Drive (Service Account auth)
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# PDF (summary doc)
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ----------------------- Config -----------------------
APP_NAME = os.getenv("APP_NAME", "Driver / Vehicle Check")
PIN_CODE = os.getenv("PIN_CODE", "6633")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "")
RUNNING_ON_RENDER = os.getenv("RENDER", "") != ""
CLEANUP_LEGACY = os.getenv("CLEANUP_LEGACY", "0") == "1"
# Fallback remote logo; will be overridden by /static/logo.png if present (see context_processor)
LOGO_URL = os.getenv("LOGO_URL", "https://drive.google.com/uc?export=view&id=1djWHjQFdDGO7qvrd4iMYTN8wpCiV_FD0")

# Google Drive
GDRIVE_ROOT = os.getenv("GDRIVE_ROOT", "Vehicle Checks")
GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")

# Email
MAIL_HOST = os.getenv("MAIL_HOST")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USER = os.getenv("MAIL_USER")
MAIL_PASS = os.getenv("MAIL_PASS")
MAIL_TO = os.getenv("MAIL_TO")  # comma-separated allowed
MAIL_FROM = os.getenv("MAIL_FROM", MAIL_USER or "noreply@example.com")

# If running on Render, a DATABASE_URL is mandatory
if RUNNING_ON_RENDER and not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. On Render you must provide a Postgres DATABASE_URL.")

# ----------------------- Flask ------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024  # 30MB limit for uploads

# ----------------------- Database ---------------------
engine = None
metadata = MetaData()
checks_table = None
db_enabled = False
db_error = None

def _engine_from_url(db_url: str):
    if db_url and "postgres" in db_url and "sslmode=" not in db_url:
        sep = "&" if "?" in db_url else "?"
        db_url = f"{db_url}{sep}sslmode=require"
    return create_engine(db_url, pool_pre_ping=True, future=True)

def init_db():
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
            Column("drive_folder_id", String(128), nullable=True),
            Column("dashboard_file_id", String(128), nullable=True),
            Column("front_file_id", String(128), nullable=True),
            Column("rear_file_id", String(128), nullable=True),
            Column("defect_file_ids", Text, nullable=True),  # comma-separated
            Column("pdf_file_id", String(128), nullable=True),
        )

        metadata.create_all(engine)

        if CLEANUP_LEGACY:
            with engine.begin() as conn:
                conn.execute(sqltext("DROP TABLE IF EXISTS vehicle CASCADE"))
        with engine.begin() as conn:
            conn.exec_driver_sql("SELECT 1")

        db_enabled = True
    except Exception as e:
        db_error = str(e)
        db_enabled = False

init_db()

# ----------------------- Google Drive helpers ---------------------
def _load_drive_service():
    """Build a Drive API service using a Google **service account** JSON file.

    Expects Render env var:
      GOOGLE_APPLICATION_CREDENTIALS=/etc/secrets/<your-service-account>.json
    """

    if not GOOGLE_APPLICATION_CREDENTIALS:
        raise RuntimeError(
            "GOOGLE_APPLICATION_CREDENTIALS is not set. "
            "In Render: Service → Environment → add GOOGLE_APPLICATION_CREDENTIALS "
            "with value like /etc/secrets/<service-account>.json, then redeploy."
        )

    scopes = ["https://www.googleapis.com/auth/drive"]
    creds = service_account.Credentials.from_service_account_file(
        GOOGLE_APPLICATION_CREDENTIALS,
        scopes=scopes,
    )

    # Fail fast: mint an access token now so auth issues surface immediately in logs
    creds.refresh(Request())

    return build("drive", "v3", credentials=creds, cache_discovery=False)

def _drive_find_or_create_folder(drive, name, parent_id=None):
    # Escape single quotes for Drive query
    safe_name = name.replace("'", "\\'")
    q_parts = [f"name = '{safe_name}'", "mimeType = 'application/vnd.google-apps.folder'", "trashed = false"]
    if parent_id:
        q_parts.append(f"'{parent_id}' in parents")
    q = " and ".join(q_parts)
    res = drive.files().list(
        q=q,
        fields="files(id,name)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    files = res.get("files", [])
    if files:
        return files[0]["id"]
    metadata = {"name": name, "mimeType": "application/vnd.google-apps.folder"}
    if parent_id:
        metadata["parents"] = [parent_id]
    folder = drive.files().create(
        body=metadata,
        fields="id",
        supportsAllDrives=True,
    ).execute()
    return folder["id"]

def _ensure_check_folder(drive, reg: str, date_str: str):
    root_id = _drive_find_or_create_folder(drive, GDRIVE_ROOT)
    reg_folder = _drive_find_or_create_folder(drive, reg, root_id)
    date_folder = _drive_find_or_create_folder(drive, date_str, reg_folder)
    return date_folder

def _sanitize_filename(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    return text[:150] or "file"

def _drive_upload(drive, folder_id: str, file_stream: io.BytesIO, filename: str, mimetype: str):
    media = MediaIoBaseUpload(file_stream, mimetype=mimetype, resumable=False)
    body = {"name": filename, "parents": [folder_id]}
    f = drive.files().create(
        body=body,
        media_body=media,
        fields="id,webViewLink",
        supportsAllDrives=True,
    ).execute()
    return f["id"], f.get("webViewLink")

# ----------------------- Email helper ---------------------
def send_email(subject: str, html_body: str):
    if not (MAIL_HOST and MAIL_PORT and MAIL_FROM and MAIL_TO):
        return  # email not configured; silently skip
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = [addr.strip() for addr in MAIL_TO.split(",") if addr.strip()]
    msg.set_content("This email contains HTML content. Please use an HTML-compatible client.")
    msg.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as s:
        s.starttls()
        if MAIL_USER and MAIL_PASS:
            s.login(MAIL_USER, MAIL_PASS)
        s.send_message(msg)

# ----------------------- PDF helper ---------------------
def build_pdf_summary(check: dict) -> bytes:
    """Return a PDF bytes for the check summary."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 50

    def line(txt, inc=18, bold=False):
        nonlocal y
        if bold:
            c.setFont("Helvetica-Bold", 12)
        else:
            c.setFont("Helvetica", 12)
        c.drawString(40, y, txt)
        y -= inc

    line(f"{APP_NAME} — Vehicle Check Summary", bold=True)
    line(f"Submitted: {check['created_at']}")
    line(f"Driver: {check['driver_name']}")
    line(f"Vehicle Reg: {check['vehicle_reg']}")
    if check.get("mileage"):
        line(f"Mileage: {check['mileage']}")
    line(f"Follow-up Required: {check['follow_up']}")
    y -= 10
    line("Checklist:", bold=True)

    for k, v in check["checklist"].items():
        if y < 80:
            c.showPage(); y = h - 50
        line(f"• {k}: {v}", inc=16)

    if check.get("defect_notes"):
        y -= 10
        line("Defect Notes:", bold=True)
        for part in re.findall(r".{1,90}(?:\s|$)", check["defect_notes"]):
            if y < 80:
                c.showPage(); y = h - 50
            line(part.strip(), inc=14)

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()

# -------------------- Auth helper --------------------
def logged_in():
    return session.get("logged_in") is True

# ----------------------- Templates --------------------
BASE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <!-- Mobile-friendly viewport -->
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <style>
  :root { color-scheme: light dark; }
  /* Mobile-first base */
  html, body { height: 100%; }
  body {
    font-family: system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
    margin: 0;
    padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
    background: #0b0d10;
    color: #e8eaed;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    font-size: 16px; /* readable base on mobile */
    line-height: 1.45;
  }

  .wrap {
    max-width: 960px;
    margin: 0 auto;
    padding: 16px;
  }

  .card {
    background: #111418;
    border: 1px solid #22252a;
    border-radius: 16px;
    padding: 20px;
    box-shadow: 0 8px 28px rgba(0,0,0,.35);
  }

  h1 { font-size: 1.15rem; margin: 0; }
  label { display: block; margin-bottom: 6px; font-weight: 600; font-size: .95rem; }

  input, select, textarea {
    width: 100%;
    height: 56px;                  /* bigger tap target */
    padding: 12px 14px;
    border-radius: 12px;
    border: 1px solid #30343a;
    background: #0c0f13;
    color: #e8eaed;
    font-size: 1rem;
  }
  input[type=file] { height: auto; padding: 10px; }
  textarea { min-height: 110px; height: auto; }

  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

  .btn {
    display: inline-block;
    width: 100%;
    height: 56px;                  /* bigger tap target */
    padding: 0 16px;
    border-radius: 14px;
    border: 1px solid #3a6df0;
    background: #2a5ae8;
    color: #fff;
    text-decoration: none;
    font-weight: 700;
    font-size: 1rem;
    cursor: pointer;
    text-align: center;
  }
  .btn.secondary {
    background: transparent;
    border: 1px solid #3a3f46;
    color: #e8eaed;
  }

  .flash { margin: 12px 0; padding: 12px; border-radius: 12px; background: #143d1f; border: 1px solid #235a2f; font-size: .95rem; }
  .error { background: #3d1414; border-color: #5a2323; }
  small.muted { color: #9aa0a6; }

  /* ---- Login Page tweaks ---- */
  .login {
    max-width: 420px;              /* nicer phone width */
    margin: 8vh auto 0;
    text-align: center;
  }
  .logo {
    max-height: 96px;
    width: auto;
    display: block;
    margin: 0 auto 14px;
    border-radius: 8px;
  }
  .login h2 {
    margin: 6px 0 12px;
    font-size: 1.25rem;            /* comfortable on phone */
    font-weight: 800;
  }
  .intro {
    color: #c7cbd1;
    background: #0c1015;
    border: 1px solid #22252a;
    padding: 12px 14px;
    border-radius: 14px;
    text-align: left;
    margin: 12px 0 18px;
    font-size: .98rem;
  }
  .intro strong { color: #ffffff; }
  .badge-req {
    display: inline-block; font-size: .78rem;
    border: 1px solid #3a6df0; color: #cfe0ff; background: #112046;
    padding: 3px 8px; border-radius: 999px; margin-left: 6px;
  }

  /* PIN wrapper for eye button */
  .pin-wrap { position: relative; }
  .pin-toggle {
    position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
    background: transparent; color: #cfd8ff; border: 0; font-weight: 700; cursor: pointer; padding: 6px 8px;
  }

  /* Larger touch targets on small screens */
  @media (max-width: 800px) {
    .row { grid-template-columns: 1fr; }
    .logo { max-height: 80px; }
    .wrap { padding: 12px; }
  }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <h1>{{ app_name }}</h1>
        {% if session.get('logged_in') %}
          <div style="display:flex; gap:8px;">
            <a class="btn secondary" href="{{ url_for('admin') }}" style="width:auto; height:auto; padding:8px 12px;">Admin</a>
            <a class="btn secondary" href="{{ url_for('logout') }}" style="width:auto; height:auto; padding:8px 12px;">Logout</a>
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
  <div class="login" role="main">
    {% if logo_url %}
      <img class="logo" src="{{ logo_url }}" alt="Taylor Roofing Services Ltd logo">
    {% endif %}
    <h2>Taylor roofing services ltd - Company vehicle check.</h2>

    <div class="intro" aria-live="polite">
      <strong>Welcome.</strong>
      <div style="margin-top:6px;">
        Please submit a minimum of <strong>1 vehicle check per month</strong>.
        Any <strong>accidents</strong> or <strong>urgent defects</strong> must be reported immediately.
      </div>
    </div>

    <form method="post" autocomplete="on" novalidate>
      <label for="pin">PIN Code <span class="badge-req">Required</span></label>

      <div class="pin-wrap">
        <input
          id="pin"
          name="pin"
          type="password"
          inputmode="numeric"
          pattern="[0-9]*"
          maxlength="8"
          placeholder="Enter your company PIN"
          aria-describedby="pin-help"
          autofocus
          autocomplete="one-time-code" />
        <button class="pin-toggle" type="button" aria-label="Show or hide PIN" onclick="
          const p = document.getElementById('pin');
          p.type = (p.type === 'password') ? 'text' : 'password';
          this.textContent = (p.type === 'password') ? 'Show' : 'Hide';
        ">Show</button>
      </div>
      <div id="pin-help" class="muted" style="text-align:left; margin:6px 2px 0;">Numbers only.</div>

      <button class="btn" type="submit" style="margin-top:14px;">Continue</button>
    </form>
  </div>
{% endblock %}
"""

CHECK_HTML = r"""
{% extends "base.html" %}
{% block content %}
  <style>
    :root{
      --bg:#0f1216; --card:#161a20; --text:#e9eef5; --muted:#9aa3af;
      --brand:#4aa3ff; --ok:#1bb36b; --warn:#f0b429; --crit:#ef5350; --bar:#263042;
      --shadow: 0 6px 22px rgba(0,0,0,.25); --radius:16px;
    }
    .ui-card{background:var(--card);border:1px solid rgba(140,150,170,.12);border-radius:var(--radius);box-shadow:var(--shadow);padding:14px;margin:12px 0}
    .tabs{display:flex;gap:8px;margin:10px 0 6px}
    .tab{flex:1;text-align:center;padding:10px;border-radius:999px;background:#111418;color:var(--muted);border:1px solid rgba(140,150,170,.15)}
    .tab.active{color:var(--text);border-color:var(--brand)}
    .progress{margin:10px 0;background:var(--bar);height:10px;border-radius:999px;overflow:hidden}
    .progress > span{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--brand),#78c3ff);transition:width .2s}
    .progress-legend{display:flex;justify-content:space-between;font-size:12px;color:var(--muted)}
    .item{padding:12px;border:1px solid rgba(140,150,170,.15);border-radius:12px;background:#0c0f13;margin:10px 0}
    .item h4{margin:0 0 8px;font-size:15px}
    .pill-row{display:flex;gap:8px}
    .pill{flex:1;text-align:center;padding:12px;border-radius:999px;border:1px solid rgba(140,150,170,.25);background:#12161c;color:var(--text);font-weight:700}
    .pill.ok{border-color:rgba(27,179,107,.35)} .pill.warn{border-color:rgba(240,180,41,.35)} .pill.crit{border-color:rgba(239,83,80,.35)}
    .pill.selected.ok{background:rgba(27,179,107,.15)} .pill.selected.warn{background:rgba(240,180,41,.15)} .pill.selected.crit{background:rgba(239,83,80,.18)}
    .details{display:none;margin-top:10px;border:1px dashed rgba(140,150,170,.25);border-radius:12px;padding:10px;background:rgba(140,150,170,.06)}
    .footerbar{padding-top:8px}
    .btn.big{padding:14px;border-radius:14px;font-weight:800}
    .muted{color:var(--muted);font-size:12px}
  </style>

  <div class="ui-card">
    <div class="tabs" role="tablist" aria-label="Sections">
      <button class="tab active" data-jump="#secA">A. Internal</button>
      <button class="tab" data-jump="#secB">B. External</button>
      <button class="tab" data-jump="#secC">C. Fluids & Mechanical</button>
    </div>
    <div class="progress"><span id="progressBar" style="width:0%"></span></div>
    <div class="progress-legend"><span id="progressText">0% complete</span><span id="sectionCount">0 / 3 sections done</span></div>
  </div>

  <form method="post" enctype="multipart/form-data">
    <!-- Top details -->
    <div class="row">
      <div><label for="driver_name">Driver Name</label><input id="driver_name" name="driver_name" required /></div>
      <div><label for="vehicle_reg">Vehicle Reg</label><input id="vehicle_reg" name="vehicle_reg" required /></div>
    </div>
    <div class="row" style="margin-top:12px;">
      <div><label for="mileage">Mileage</label><input id="mileage" name="mileage" inputmode="numeric" pattern="[0-9]*" /></div>
      <div>
        <label for="follow_up">Requires Follow-up?</label>
        <select id="follow_up" name="follow_up"><option>No</option><option>Yes</option></select>
      </div>
    </div>

    <!-- SECTION A -->
    <section id="secA" class="ui-card" data-section-index="0">
      <h3 style="margin:0 0 8px;">A. Internal Condition <small class="muted" id="badgeA">0/5</small></h3>
      {% set A = [
        "Internal instruments all operational (aircon, satnav, etc.)",
        "Seatbelts: condition & operation",
        "Horn operational",
        "Windscreen & mirrors clear; wipers/washers work",
        "Dashboard warning lights: none active"
      ] %}
      {% for label in A %}
        <div class="item" data-key="A{{ loop.index0 }}" data-label="{{ label }}">
          <h4>{{ label }}</h4>
          <div class="pill-row" role="radiogroup">
            <button type="button" class="pill ok"  data-val="OK">✅ OK</button>
            <button type="button" class="pill warn" data-val="Issue">⚠️ Defect</button>
            <button type="button" class="pill crit" data-val="Issue">❌ Critical</button>
          </div>
          <input type="hidden" name="check__{{ loop.index0 }}" value="" />
          <input type="hidden" name="check_label__{{ loop.index0 }}" value="{{ label }}" />
          <div class="details">
            <label class="muted">Notes (required for ⚠️/❌)</label>
            <textarea></textarea>
          </div>
        </div>
      {% endfor %}
    </section>

    <!-- SECTION B -->
    <section id="secB" class="ui-card" data-section-index="1">
      <h3 style="margin:0 0 8px;">B. External Condition <small class="muted" id="badgeB">0/5</small></h3>
      {% set B = [
        "No damage to bodywork or bumpers",
        "Lights & indicators operational",
        "Number plates clean / visible",
        "Tyres: tread, pressure, no cuts/bulges",
        "Glass & lenses intact (no cracks)"
      ] %}
      {% for label in B %}
        <div class="item" data-key="B{{ loop.index0 }}" data-label="{{ label }}">
          <h4>{{ label }}</h4>
          <div class="pill-row" role="radiogroup">
            <button type="button" class="pill ok"  data-val="OK">✅ OK</button>
            <button type="button" class="pill warn" data-val="Issue">⚠️ Defect</button>
            <button type="button" class="pill crit" data-val="Issue">❌ Critical</button>
          </div>
          <input type="hidden" name="check__{{ 5 + loop.index0 }}" value="" />
          <input type="hidden" name="check_label__{{ 5 + loop.index0 }}" value="{{ label }}" />
          <div class="details">
            <label class="muted">Notes (required for ⚠️/❌)</label>
            <textarea></textarea>
          </div>
        </div>
      {% endfor %}
    </section>

    <!-- SECTION C -->
    <section id="secC" class="ui-card" data-section-index="2">
      <h3 style="margin:0 0 8px;">C. Fluids & Mechanical <small class="muted" id="badgeC">0/6</small></h3>
      {% set C = [
        "Engine oil level OK (no leaks)",
        "Coolant level OK",
        "Screenwash level OK",
        "AdBlue level OK",
        "Brakes feel & fluid (no warning)",
        "Steering & suspension: no issues"
      ] %}
      {% for label in C %}
        <div class="item" data-key="C{{ loop.index0 }}" data-label="{{ label }}">
          <h4>{{ label }}</h4>
          <div class="pill-row" role="radiogroup">
            <button type="button" class="pill ok"  data-val="OK">✅ OK</button>
            <button type="button" class="pill warn" data-val="Issue">⚠️ Defect</button>
            <button type="button" class="pill crit" data-val="Issue">❌ Critical</button>
          </div>
          <input type="hidden" name="check__{{ 10 + loop.index0 }}" value="" />
          <input type="hidden" name="check_label__{{ 10 + loop.index0 }}" value="{{ label }}" />
          <div class="details">
            <label class="muted">Notes (required for ⚠️/❌)</label>
            <textarea></textarea>
          </div>
        </div>
      {% endfor %}
    </section>

    <!-- Photos -->
    <div class="ui-card">
      <h3 style="margin:0 0 10px;">Photos</h3>
      <div class="row">
        <div>
          <label>Dashboard / Mileage (required)</label>
          <input type="file" name="photo_dashboard" accept="image/*" capture="environment" required />
        </div>
        <div>
          <label>Front of Vehicle (required)</label>
          <input type="file" name="photo_front" accept="image/*" capture="environment" required />
        </div>
      </div>
      <div class="row" style="margin-top:12px;">
        <div>
          <label>Rear of Vehicle (required)</label>
          <input type="file" name="photo_rear" accept="image/*" capture="environment" required />
        </div>
        <div>
          <label>Damage / Defects (optional, multiple)</label>
          <input type="file" name="photo_defects" accept="image/*" multiple />
        </div>
      </div>
      <p class="muted" style="margin-top:8px;">
        Minimum of front, rear & dashboard photos are required. Any damage or defect needs a separate photo uploading on the damage/defect photo option.
      </p>
    </div>

    <!-- Any other comments -->
    <div class="ui-card">
      <h3 style="margin:0 0 10px;">Any other comments?</h3>
      <textarea name="comments" placeholder="Enter any additional comments here..." style="width:100%;min-height:80px;border-radius:12px;border:1px solid rgba(140,150,170,.25);padding:10px;background:transparent;color:var(--text);"></textarea>
    </div>

    <div class="footerbar">
      <button class="btn" type="submit" style="margin-top:10px;width:100%;">Submit Check</button>
    </div>
  </form>

  <script>
    const sections = Array.from(document.querySelectorAll('section.ui-card'));
    const tabs = Array.from(document.querySelectorAll('.tab'));
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const sectionCount = document.getElementById('sectionCount');

    function updateBadgesAndProgress(){
      let total = 0, done = 0;
      sections.forEach((sec)=>{
        const items = sec.querySelectorAll('.item');
        let completed = 0;
        items.forEach(it=>{
          total++;
          const hidden = it.querySelector('input[name^="check__"]');
          if(hidden && hidden.value){ completed++; done++; }
        });
        const badgeEl = sec.querySelector('small.muted[id^="badge"]');
        if(badgeEl) badgeEl.textContent = `${completed}/${items.length}`;
      });
      const pct = Math.round((done/total)*100) || 0;
      progressBar.style.width = pct + '%';
      progressText.textContent = pct + '% complete';
      const secDone = sections.filter(sec=>{
        const items = sec.querySelectorAll('.item');
        return Array.from(items).every(it=> it.querySelector('input[name^="check__"]').value);
      }).length;
      sectionCount.textContent = `${secDone} / ${sections.length} sections done`;
    }

    document.querySelectorAll('.item').forEach(item=>{
      const pills = item.querySelectorAll('.pill');
      const details = item.querySelector('.details');
      const hiddenVal = item.querySelector('input[name^="check__"]');
      pills.forEach(p=>{
        p.addEventListener('click', ()=>{
          pills.forEach(x=> x.classList.remove('selected'));
          p.classList.add('selected');
          hiddenVal.value = p.dataset.val;
          if(p.classList.contains('warn') || p.classList.contains('crit')){
            details.style.display = 'block';
          } else {
            details.style.display = 'none';
          }
          updateBadgesAndProgress();
        });
      });
    });

    tabs.forEach(t=> t.addEventListener('click', ()=>{
      tabs.forEach(x=> x.classList.remove('active'));
      t.classList.add('active');
      document.querySelector(t.dataset.jump).scrollIntoView({behavior:'smooth', block:'start'});
      updateBadgesAndProgress();
    }));

    updateBadgesAndProgress();
  </script>
{% endblock %}
"""

SUCCESS_HTML = """
{% extends "base.html" %}
{% block content %}
  <h2>Submitted ✅</h2>
  <p>Your check has been recorded and files saved to Google Drive.</p>
  <p><small class="muted">Reference ID: {{ check_id }}</small></p>
  {% if drive_link %}
    <p><a class="btn secondary" href="{{ drive_link }}" target="_blank" rel="noopener">Open Drive Folder</a></p>
  {% endif %}
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
          {% if r.drive_folder_id %}
            <div style="margin-top:10px;">
              <a class="btn secondary" href="https://drive.google.com/drive/folders/{{ r.drive_folder_id }}" target="_blank">Drive Folder</a>
            </div>
          {% endif %}
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
    # Prefer local static logo to avoid Drive hotlink issues; cache-bust with mtime
    logo_src = LOGO_URL
    local_logo = os.path.join("static", "logo.png")
    try:
        if os.path.exists(local_logo):
            ver = int(os.path.getmtime(local_logo))
            logo_src = url_for("static", filename="logo.png", v=ver)
    except Exception:
        pass

    return {
        "app_name": APP_NAME,
        "db_enabled": db_enabled,
        "db_error": db_error,
        "logo_url": logo_src,
    }

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
        # A. Internal
        "Internal instruments all operational (aircon, satnav, etc.)",
        "Seatbelts: condition & operation",
        "Horn operational",
        "Windscreen & mirrors clear; wipers/washers work",
        "Dashboard warning lights: none active",
        # B. External
        "No damage to bodywork or bumpers",
        "Lights & indicators operational",
        "Number plates clean / visible",
        "Tyres: tread, pressure, no cuts/bulges",
        "Glass & lenses intact (no cracks)",
        # C. Fluids & Mechanical
        "Engine oil level OK (no leaks)",
        "Coolant level OK",
        "Screenwash level OK",
        "AdBlue level OK",
        "Brakes feel & fluid (no warning)",
        "Steering & suspension: no issues",
    ]

    if request.method == "POST":
        driver_name = request.form.get("driver_name", "").strip()
        vehicle_reg = request.form.get("vehicle_reg", "").strip().upper()
        mileage = request.form.get("mileage", "").strip()
        follow_up = request.form.get("follow_up", "No").strip() or "No"
        comments = (request.form.get("comments") or "").strip()
        defect_notes = request.form.get("defect_notes", "").strip()

        # Build checklist dict
        checklist = {}
        i = 0
        while True:
            lk = f"check_label__{i}"; vk = f"check__{i}"
            if lk not in request.form: break
            checklist[request.form[lk]] = request.form.get(vk, "OK")
            i += 1

        # Validate required photos
        f_dash = request.files.get("photo_dashboard")
        f_front = request.files.get("photo_front")
        f_rear = request.files.get("photo_rear")
        if not (f_dash and f_dash.filename and f_front and f_front.filename and f_rear and f_rear.filename):
            flash("Dashboard, Front, and Rear photos are required.", "error")
            return render_template_string(CHECK_HTML, title="Vehicle Check", checklist=checklist_items)

        # Prepare Drive
        drive = _load_drive_service()
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        folder_id = _ensure_check_folder(drive, vehicle_reg, date_str)

        # Upload required photos
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        def _upload_file(file_storage, label):
            stream = io.BytesIO(file_storage.read())
            file_storage.stream.seek(0)
            fname = _sanitize_filename(f"{vehicle_reg}_{label}_{driver_name}_{ts}.jpg")
            fid, link = _drive_upload(drive, folder_id, stream, fname, "image/jpeg")
            return fid, link

        dash_id, dash_link = _upload_file(f_dash, "Dashboard")
        front_id, front_link = _upload_file(f_front, "Front")
        rear_id, rear_link = _upload_file(f_rear, "Rear")

        defect_ids = []
        defect_links = []
        if "photo_defects" in request.files:
            for fs in request.files.getlist("photo_defects"):
                if fs and fs.filename:
                    fid, lnk = _upload_file(fs, "Defect")
                    defect_ids.append(fid); defect_links.append(lnk)

        # Persist record
        created_at = datetime.utcnow()
        try:
            if db_enabled and checks_table is not None:
                with engine.begin() as conn:
                    new_id = conn.execute(
                        insert(checks_table).values(
                            created_at=created_at,
                            driver_name=driver_name,
                            vehicle_reg=vehicle_reg,
                            mileage=mileage,
                            checklist=checklist,
                            defect_notes=defect_notes,
                            follow_up=follow_up,
                            drive_folder_id=folder_id,
                            dashboard_file_id=dash_id,
                            front_file_id=front_id,
                            rear_file_id=rear_id,
                            defect_file_ids=",".join(defect_ids) if defect_ids else None,
                        ).returning(checks_table.c.id)
                    ).scalar_one()
            else:
                new_id = 0  # in-memory mode not used for Drive, but keep placeholder
        except OperationalError as e:
            flash(f"Database error: {e}", "error")
            return render_template_string(CHECK_HTML, title="Vehicle Check", checklist=checklist_items)

        # Build & upload PDF summary
        check_payload = {
            "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "driver_name": driver_name,
            "vehicle_reg": vehicle_reg,
            "mileage": mileage,
            "follow_up": follow_up,
            "checklist": checklist,
            "defect_notes": defect_notes,
        }
        pdf_bytes = build_pdf_summary(check_payload)
        pdf_stream = io.BytesIO(pdf_bytes)
        pdf_name = _sanitize_filename(f"{vehicle_reg}_CheckSummary_{ts}.pdf")
        pdf_id, pdf_link = _drive_upload(drive, folder_id, pdf_stream, pdf_name, "application/pdf")

        # Email notification
        folder_link = f"https://drive.google.com/drive/folders/{folder_id}"
        defect_notes_html = (defect_notes or "—").replace("\n", "<br/>")
        comments_html = (comments or "—").replace("\n", "<br/>")

        html = f"""
        <h3>{APP_NAME} – Vehicle Check Submitted</h3>
        <p><b>When:</b> {check_payload['created_at']}</p>
        <p><b>Driver:</b> {driver_name}<br/>
           <b>Vehicle:</b> {vehicle_reg} &nbsp; <b>Mileage:</b> {mileage or '—'}<br/>
           <b>Follow-up:</b> {follow_up}</p>
        <p><b>Drive Folder:</b> <a href="{folder_link}">{folder_link}</a></p>
        <p><b>Photos:</b><br/>
           Dashboard: <a href="{dash_link}">open</a><br/>
           Front: <a href="{front_link}">open</a><br/>
           Rear: <a href="{rear_link}">open</a><br/>
           {"Defects: " + ", ".join(f'<a href="{l}">open</a>' for l in defect_links) if defect_links else "Defects: —"}
        </p>
        <p><b>Summary PDF:</b> <a href="{pdf_link}">open</a></p>
        <hr/>
        <p><b>Checklist</b></p>
        <ul>
            {''.join(f'<li>{k}: {v}</li>' for k,v in checklist.items())}
        </ul>
        <p><b>Defect Notes:</b><br/>{defect_notes_html}</p>
        <p><b>Any other comments:</b><br/>{comments_html}</p>
        """
        try:
            send_email(subject=f"{APP_NAME}: {vehicle_reg} check submitted", html_body=html)
        except Exception as e:
            # don't block the flow on email errors
            flash(f"Email send failed: {e}", "error")

        # Update PDF id into DB
        if db_enabled and checks_table is not None:
            try:
                with engine.begin() as conn:
                    conn.execute(sqltext("UPDATE vehicle_checks SET pdf_file_id = :pdf WHERE id = :id"),
                                 {"pdf": pdf_id, "id": new_id})
            except Exception as e:
                flash(f"Failed to record PDF id: {e}", "error")

        return redirect(url_for("success", check_id=new_id, folder_id=folder_id))

    return render_template_string(CHECK_HTML, title="Vehicle Check", checklist=checklist_items)

@app.route("/success/<int:check_id>")
def success(check_id: int):
    if not logged_in():
        return redirect(url_for("pin"))
    folder_id = request.args.get("folder_id")
    drive_link = f"https://drive.google.com/drive/folders/{folder_id}" if folder_id else None
    return render_template_string(SUCCESS_HTML, title="Submitted", check_id=check_id, drive_link=drive_link)

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
                        checks_table.c.drive_folder_id,
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
                    "drive_folder_id": r["drive_folder_id"],
                })
        except Exception as e:
            flash(f"Failed to load admin list: {e}", "error")

    return render_template_string(ADMIN_HTML, title="Recent Checks", rows=rows)

# ----------------------- Entrypoint -------------------
if __name__ == "__main__":
    if db_enabled:
        metadata.create_all(engine)
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port)
