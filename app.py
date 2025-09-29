""" Driver Vehicle Check — Flask PWA (Full App) """
from __future__ import annotations
import os, io, json, csv, base64, datetime as dt, secrets
from flask import (Flask, render_template_string, request, redirect, url_for, flash,
                   send_file, send_from_directory, jsonify, abort)
from typing import Optional
from flask import (Flask, render_template_string, request, redirect, url_for, flash,
                   send_file, jsonify, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, IntegerField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Optional as VOptional, NumberRange, Length
from werkzeug.utils import secure_filename
from PIL import Image
from jinja2 import DictLoader

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret'),
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///vehicle_checks.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER', 'uploads'),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {"png","jpg","jpeg","webp"}

DEFAULT_FLEET_EMAIL = "Luke.Taylor@taylor-roofingServices.co.uk"
def _mail_cfg():
    return (
        os.getenv('MAIL_HOST'),
        int(os.getenv('MAIL_PORT', '587')),
        os.getenv('MAIL_USER'),
        os.getenv('MAIL_PASS'),
        os.getenv('MAIL_TO', DEFAULT_FLEET_EMAIL),
    )

GDRIVE_ENABLED = os.getenv('GDRIVE_ENABLED', '0') == '1'
GDRIVE_FOLDER_ID = os.getenv('GDRIVE_FOLDER_ID')
GDRIVE_SA_JSON   = os.getenv('GDRIVE_SERVICE_ACCOUNT_JSON')

DRIVER_PIN     = os.getenv('DRIVER_PIN', '0000')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

db = SQLAlchemy(app)

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg = db.Column(db.String(16), unique=True, nullable=False)
    make_model = db.Column(db.String(120))
    active = db.Column(db.Boolean, default=True)
    slug = db.Column(db.String(32), unique=True, default=lambda: secrets.token_hex(4))

class Check(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)
    driver_name = db.Column(db.String(80), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    odometer = db.Column(db.Integer)
    notes = db.Column(db.Text)
    defects = db.Column(db.Text)
    safe_to_drive = db.Column(db.Boolean, default=True)
    signature_path = db.Column(db.String(255))
    items_json = db.Column(db.Text)
    vehicle = db.relationship('Vehicle', backref=db.backref('checks', lazy=True))

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey('check.id'), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    drive_file_id = db.Column(db.String(128))
    check = db.relationship('Check', backref=db.backref('photos', lazy=True))

CHECK_ITEMS = [
    {"section":"Tyre","label":"Tread Depth (min 1.6mm)"},
    {"section":"Tyre","label":"Inflation Pressure"},
    {"section":"Tyre","label":"Cracks and Cuts"},
    {"section":"Engine","label":"Oil Level"},
    {"section":"Engine","label":"Coolant Level"},
    {"section":"Engine","label":"Brake Fluid Level"},
    {"section":"Engine","label":"Clutch Fluid Level"},
    {"section":"Engine","label":"Battery Water Level"},
    {"section":"Engine","label":"Steering Fluid"},
    {"section":"Engine","label":"Fuel"},
    {"section":"Engine","label":"Battery (not leaking and secure)"},
    {"section":"Light","label":"Interior"},
    {"section":"Light","label":"Turn"},
    {"section":"Light","label":"Reverse"},
    {"section":"Light","label":"Tail"},
    {"section":"Light","label":"Emergency"},
    {"section":"Accessory","label":"Tape/Radio"},
    {"section":"Control","label":"Horn"},
    {"section":"Control","label":"Engine Start"},
    {"section":"Control","label":"Central Lock"},
    {"section":"Control","label":"Power Window"},
    {"section":"Control","label":"Heater/AC"},
    {"section":"Control","label":"Auto/Manual transmission Operation"},
    {"section":"Control","label":"Brake Operation"},
    {"section":"Control","label":"Wipers/washers"},
    {"section":"Control","label":"Steering Operation"},
    {"section":"Tool","label":"Jack and Wheel Spanner"},
    {"section":"Tool","label":"First Aid Kit"},
    {"section":"Exterior","label":"Mirrors and glass"},
    {"section":"Exterior","label":"Exhaust (doesn’t emit excessive smoke)"},
    {"section":"Exterior","label":"Body work & Doors (any damage)"},
    {"section":"Interior","label":"Seats and seatbelts (secure, operate, no damage)"},
]

class CheckForm(FlaskForm):
    driver_name    = StringField('Driver Name', validators=[DataRequired(), Length(max=80)])
    vehicle_select = StringField('Vehicle Select')
    odometer       = IntegerField('Odometer (miles)', validators=[VOptional(), NumberRange(min=0)])
    safe_to_drive  = BooleanField('Safe to drive')
    defects        = TextAreaField('Defects found (if any)', validators=[VOptional(), Length(max=1000)])
    notes          = TextAreaField('Notes', validators=[VOptional(), Length(max=2000)])
    signature_data = HiddenField('Signature (base64)')

@app.route('/pin', methods=['GET','POST'])
def pin_gate():
    if request.method == 'POST':
        if request.form.get('pin') == DRIVER_PIN:
            resp = redirect(url_for('new_check'))
            resp.set_cookie('driver_ok', '1', max_age=3600*8)
            return resp
        flash('Incorrect PIN')
    return render_template_string(TPL_PIN)

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            resp = redirect(url_for('admin_dashboard'))
            resp.set_cookie('admin_ok', '1', max_age=3600*8)
            return resp
        flash('Incorrect password')
    return render_template_string(TPL_ADMIN_LOGIN)

@app.route('/manifest.webmanifest')
def manifest():
    return jsonify({
        "name": "Driver Vehicle Check",
        "short_name": "Vehicle Check",
        "start_url": "/check",
        "display": "standalone",
        "background_color": "#0b0f14",
        "theme_color": "#0b0f14",
        "icons": [
            {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    })

@app.route('/sw.js')
def service_worker():
    js = """
    const CACHE = 'vehcheck-v3'; // bump version to invalidate old cache
    const ASSETS = [
      '/static/logo.png',
      'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
      'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'
    ];

    self.addEventListener('install', event => {
      event.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
      self.skipWaiting();
    });

    self.addEventListener('activate', event => {
      event.waitUntil(
        caches.keys().then(keys =>
          Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
        )
      );
      self.clients.claim();
    });

    self.addEventListener('fetch', event => {
      const req = event.request;
      if (req.method !== 'GET') return;

      // For navigations (page loads), use network-first; if offline, basic fallback
      if (req.mode === 'navigate') {
        event.respondWith(
          fetch(req).catch(() =>
            new Response('<!doctype html><h1>Offline</h1><p>You appear to be offline.</p>', {
              headers: { 'Content-Type': 'text/html' }
            })
          )
        );
        return;
      }

      // For static assets, cache-first; only cache successful (non-redirect) responses
      const staticDest = ['style','script','image','font'];
      if (staticDest.includes(req.destination)) {
        event.respondWith(
          caches.match(req).then(cached => {
            if (cached) return cached;
            return fetch(req).then(resp => {
              if (resp && resp.ok) {
                const copy = resp.clone();
                caches.open(CACHE).then(c => c.put(req, copy));
              }
              return resp;
            });
          })
        );
        return;
      }

      // Everything else: network passthrough
      event.respondWith(fetch(req));
    });
    """
    return js, 200, {'Content-Type':'application/javascript'}

@app.route('/')
def index():
    return redirect(url_for('new_check'))

@app.route('/check', methods=['GET','POST'])
def new_check():
    if request.cookies.get('driver_ok') != '1':
        return redirect(url_for('pin_gate'))
    form = CheckForm()
    vehicles = Vehicle.query.filter_by(active=True).order_by(Vehicle.reg.asc()).all()
    if request.method == 'POST' and form.validate():
        sel_reg = (request.form.get('vehicle_select') or '').strip().upper()
        vehicle = Vehicle.query.filter_by(reg=sel_reg).first()
        if not vehicle:
            flash('Please select a valid vehicle registration')
            return render_template_string(TPL_FORM, form=form, vehicles=vehicles, CHECK_ITEMS=CHECK_ITEMS)
        c = Check(
            driver_name=form.driver_name.data.strip(),
            vehicle_id=vehicle.id,
            odometer=form.odometer.data,
            notes=form.notes.data,
            defects=form.defects.data,
            safe_to_drive=bool(form.safe_to_drive.data),
        )
        items = []
        for idx, item in enumerate(CHECK_ITEMS):
            status  = request.form.get(f'item_status_{idx}', '')
            comment = (request.form.get(f'item_comment_{idx}', '') or '').strip()
            items.append({'section':item['section'], 'label':item['label'], 'status':status, 'comment':comment})
        c.items_json = json.dumps(items)
        sig_data = form.signature_data.data or ''
        if sig_data.startswith('data:image/png;base64,'):
            img_b64 = sig_data.split(',')[1]
            sig_name = f"sig_{dt.datetime.utcnow():%Y%m%d%H%M%S}_{secrets.token_hex(4)}.png"
            sig_path = os.path.join(app.config['UPLOAD_FOLDER'], sig_name)
            with open(sig_path, 'wb') as f: f.write(base64.b64decode(img_b64))
            c.signature_path = sig_name  # store only the filename
        db.session.add(c)
        db.session.flush()
        # Photos
        files = request.files.getlist('photos')
        for f in files:
            try:
                # skip empty uploads
                if not f or not getattr(f, 'filename', ''):
                    continue

                filename = f.filename

                # derive extension safely (no inline ternary)
                if '.' in filename:
                    ext = filename.rsplit('.', 1)[1].lower()
                else:
                    ext = ''

                if ext not in ALLOWED_EXTENSIONS:
                    continue

                # save to disk
                fname = secure_filename(f"{c.id}_{int(dt.datetime.utcnow().timestamp())}_{filename}")
                fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                try:
                    img = Image.open(f.stream)
                    if img.mode not in ('RGB', 'RGBA'):
                        img = img.convert('RGB')
                    img.thumbnail((2000, 2000))
                    img.save(fpath, optimize=True, quality=85)
                except Exception:
                    # fall back to raw write
                    f.stream.seek(0)
                    with open(fpath, 'wb') as out:
                        out.write(f.read())

                # create DB row (store only the filename)
                photo = Photo(check_id=c.id, path=fname)

                # optional Drive upload
                if GDRIVE_ENABLED and GDRIVE_FOLDER_ID:
                    try:
                        drive_id = upload_to_drive_structured(
                            fpath, vehicle.reg, dt.datetime.utcnow(), os.path.basename(fpath), 'image/jpeg'
                        )
                        photo.drive_file_id = drive_id
                    except Exception:
                        app.logger.warning('Drive upload failed for photo', exc_info=True)

                db.session.add(photo)

            except Exception:
                app.logger.exception('Failed to process uploaded photo')

        # commit once after processing all photos
        db.session.commit()
        try:
            send_submission_email(c, items)
        except Exception:
            app.logger.warning('Submission email failed', exc_info=True)
        flash('Check submitted. Drive safe!')
        return redirect(url_for('success', check_id=c.id))
    return render_template_string(TPL_FORM, form=form, vehicles=vehicles, CHECK_ITEMS=CHECK_ITEMS)

@app.route('/success/<int:check_id>')
def success(check_id):
    check = Check.query.get_or_404(check_id)
    return render_template_string(TPL_SUCCESS, check=check)

@app.route('/admin')
def admin_dashboard():
    if request.cookies.get('admin_ok') != '1':
        return redirect(url_for('admin_login'))
    rows = Check.query.order_by(Check.created_at.desc()).limit(200).all()
    return render_template_string(TPL_ADMIN, rows=rows)

@app.route('/admin/check/<int:check_id>')
def admin_check(check_id):
    if request.cookies.get('admin_ok') != '1':
        return redirect(url_for('admin_login'))
    c = Check.query.get_or_404(check_id)
    items = json.loads(c.items_json or '[]')
    return render_template_string(TPL_DETAIL, c=c, items=items)

@app.route('/admin/export.csv')
def export_csv():
    if request.cookies.get('admin_ok') != '1':
        return redirect(url_for('admin_login'))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['created_at','driver','reg','odometer','safe_to_drive','defects'])
    for c in Check.query.order_by(Check.created_at.desc()).all():
        writer.writerow([c.created_at.isoformat(), c.driver_name, c.vehicle.reg, c.odometer or '', c.safe_to_drive, (c.defects or '').replace('\n',' ')[:500]])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')),
                     mimetype='text/csv', as_attachment=True, download_name='vehicle_checks.csv')

@app.route('/admin/vehicles', methods=['GET','POST'])
def admin_vehicles():
    if request.cookies.get('admin_ok') != '1':
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        reg  = (request.form.get('reg') or '').strip().upper()
        make = (request.form.get('make_model') or '').strip()
        if reg:
            v = Vehicle.query.filter_by(reg=reg).first()
            if v:
                flash('Vehicle already exists')
            else:
                db.session.add(Vehicle(reg=reg, make_model=make, active=True)); db.session.commit()
    vs = Vehicle.query.order_by(Vehicle.active.desc(), Vehicle.reg.asc()).all()
    return render_template_string(TPL_VEHICLES, vehicles=vs)

@app.route('/admin/vehicles/<int:vid>/toggle')
def toggle_vehicle(vid):
    if request.cookies.get('admin_ok') != '1':
        return redirect(url_for('admin_login'))
    v = Vehicle.query.get_or_404(vid)
    v.active = not v.active
    db.session.commit()
    return redirect(url_for('admin_vehicles'))

@app.route('/admin/vehicles/<int:vid>', methods=['GET','POST'])
def edit_vehicle(vid):
    if request.cookies.get('admin_ok') != '1':
        return redirect(url_for('admin_login'))
    v = Vehicle.query.get_or_404(vid)
    if request.method == 'POST':
        new_reg = (request.form.get('reg') or '').strip().upper()
        new_mm  = (request.form.get('make_model') or '').strip()
        if new_reg:
            taken = Vehicle.query.filter(Vehicle.id != v.id, Vehicle.reg == new_reg).first()
            if taken:
                flash('That registration already exists.')
            else:
                v.reg = new_reg
                v.make_model = new_mm
                db.session.commit()
                flash('Vehicle updated.')
                return redirect(url_for('admin_vehicles'))
    return render_template_string(TPL_VEHICLE_EDIT, v=v)

def _month_start_utc(now: Optional[dt.datetime] = None) -> dt.datetime:
    now = now or dt.datetime.utcnow()
    return dt.datetime(now.year, now.month, 1)

def _vehicles_missing_since(since_utc: dt.datetime) -> list[Vehicle]:
    missing = []
    for v in Vehicle.query.filter_by(active=True).all():
        exists = db.session.query(Check.id).filter(Check.vehicle_id==v.id, Check.created_at>=since_utc).first()
        if not exists:
            missing.append(v)
    return missing

def send_text_email(subject: str, body: str) -> bool:
    import smtplib
    from email.message import EmailMessage
    host, port, user, pwd, to = _mail_cfg()
    if not (host and user and pwd and to):
        return False
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = user
    msg['To'] = to
    msg.set_content(body)
    with smtplib.SMTP(host, port) as s:
        s.starttls(); s.login(user, pwd); s.send_message(msg)
    return True

def send_monthly_reminder(stage: str) -> bool:
    stage = stage.lower()
    labels = {'due':'DUE','amber':'OVERDUE (Amber)','red':'FINAL OVERDUE (Red)'}
    if stage not in labels: return False
    start = _month_start_utc()
    missing = _vehicles_missing_since(start)
    if not missing: return False
    lines = [f"- {v.reg}" + (f" — {v.make_model}" if v.make_model else '') for v in missing]
    body = (f"Monthly vehicle checks — {labels[stage]}\n"
            f"Month starting {start.date()} (UTC)\n\n"
            f"Outstanding vehicles ({len(missing)}):\n" + "\n".join(lines) +
            "\n\nPlease complete a check via the Driver PIN page.")
    return send_text_email(f"{labels[stage]}: Monthly vehicle checks — {len(missing)} outstanding", body)

@app.route('/cron/monthly/<stage>')
def cron_monthly(stage):
    token = request.args.get('token','')
    if token != os.getenv('CRON_SECRET',''):
        abort(403)
    ok = send_monthly_reminder(stage)
    return jsonify({'sent': bool(ok), 'stage': stage})

@app.route('/cron/weekly/<stage>')
def cron_weekly(stage):
    return cron_monthly(stage)

import smtplib
from email.message import EmailMessage
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader

def send_submission_email(c: Check, items: list):
    pdf_bytes = build_pdf_for_check(c, items)
    if GDRIVE_ENABLED and GDRIVE_FOLDER_ID:
        try:
            pdf_name = f'check_{c.id}_{c.vehicle.reg}.pdf'
            tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_name)
            with open(tmp_path,'wb') as _f: _f.write(pdf_bytes)
            upload_to_drive_structured(tmp_path, c.vehicle.reg, c.created_at, pdf_name, 'application/pdf')
        except Exception:
            app.logger.warning('Drive upload failed for PDF', exc_info=True)
    host, port, user, pwd, to = _mail_cfg()
    if not (host and user and pwd and to):
        return
    any_fail = any(i.get('status')=='fail' for i in items) or (c.defects and c.defects.strip()) or (not c.safe_to_drive)
    tag = "DEFECT" if any_fail else "Submission"
    msg = EmailMessage()
    msg['Subject'] = f"{tag}: {c.vehicle.reg} by {c.driver_name} — #{c.id}"
    msg['From'] = user
    msg['To'] = to
    msg.set_content(
        f"Time: {c.created_at}\n"
        f"Reg: {c.vehicle.reg}\n"
        f"Driver: {c.driver_name}\n"
        f"Safe to drive: {c.safe_to_drive}\n"
        f"Odometer: {c.odometer}\n"
        f"Defects: {c.defects or '-'}\n"
        f"Notes: {c.notes or '-'}\n"
    )
    msg.add_attachment(pdf_bytes, maintype='application', subtype='pdf', filename=f'check_{c.id}_{c.vehicle.reg}.pdf')
    with smtplib.SMTP(host, port) as s:
        s.starttls(); s.login(user, pwd); s.send_message(msg)

def build_pdf_for_check(c: Check, items: list) -> bytes:
    buf = io.BytesIO()
    p = pdfcanvas.Canvas(buf, pagesize=A4)
    W, H = A4
    y = H - 20*mm
    logo_path = os.path.join('static','logo.png')
    if os.path.exists(logo_path):
        try: p.drawImage(ImageReader(logo_path), 15*mm, H-25*mm, width=30*mm, height=12*mm, preserveAspectRatio=True, mask='auto')
        except Exception: pass
    p.setFont('Helvetica-Bold', 16); p.drawString(50*mm, H-15*mm, 'Daily Vehicle Check Report')
    p.setFont('Helvetica', 10)
    p.drawString(15*mm, y, f"Check ID: {c.id}"); y-=6*mm
    p.drawString(15*mm, y, f"Date/Time (UTC): {c.created_at:%Y-%m-%d %H:%M}"); y-=6*mm
    p.drawString(15*mm, y, f"Vehicle: {c.vehicle.reg}"); y-=6*mm
    p.drawString(15*mm, y, f"Driver: {c.driver_name}"); y-=6*mm
    if c.odometer is not None:
        p.drawString(15*mm, y, f"Odometer: {c.odometer} miles"); y-=8*mm
    else:
        y -= 2*mm
    p.setFont('Helvetica-Bold', 11)
    p.drawString(15*mm, y, f"Safe to drive: {'YES' if c.safe_to_drive else 'NO'}"); y-=8*mm
    p.setFont('Helvetica-Bold', 11); p.drawString(15*mm, y, 'Checklist'); y-=6*mm
    p.setFont('Helvetica', 9)
    for it in items:
        status = it.get('status') or '-'
        if y < 40*mm: p.showPage(); y = H - 20*mm; p.setFont('Helvetica', 9)
        p.drawString(15*mm, y, f"{it.get('section')} — {it.get('label')}")
        p.drawRightString(W-40*mm, y, 'Pass' if status=='pass' else ('Fail' if status=='fail' else '-'))
        comment = (it.get('comment') or '').strip()
        if comment:
            y -= 4*mm; p.setFont('Helvetica-Oblique', 8); p.drawString(20*mm, y, f"Note: {comment[:180]}"); p.setFont('Helvetica', 9)
        y -= 6*mm
    if y < 40*mm: p.showPage(); y = H - 20*mm
    p.setFont('Helvetica-Bold', 11); p.drawString(15*mm, y, 'Defects'); y-=6*mm
    p.setFont('Helvetica', 9); p.drawString(15*mm, y, (c.defects or '-')); y-=8*mm
    p.setFont('Helvetica-Bold', 11); p.drawString(15*mm, y, 'Notes'); y-=6*mm
    p.setFont('Helvetica', 9); p.drawString(15*mm, y, (c.notes or '-')); y-=10*mm
    if c.photos:
        p.setFont('Helvetica-Bold', 11); p.drawString(15*mm, y, 'Photos'); y-=6*mm
        x = 15*mm
        for ph in c.photos[:4]:
            try: p.drawImage(ImageReader(ph.path), x, y-35*mm, width=45*mm, height=30*mm, preserveAspectRatio=True, mask='auto')
            except Exception: pass
            x += 50*mm
            if x > W-60*mm: x = 15*mm; y -= 32*mm
        y -= 36*mm
    if c.signature_path and os.path.exists(c.signature_path):
        p.setFont('Helvetica-Bold', 11); p.drawString(15*mm, y, 'Driver Signature'); y-=6*mm
        try: p.drawImage(ImageReader(c.signature_path), 15*mm, y-20*mm, width=60*mm, height=20*mm, mask='auto')
        except Exception: pass
        y -= 24*mm
    p.showPage(); p.save(); buf.seek(0)
    return buf.getvalue()

def _drive_service():
    if not (GDRIVE_ENABLED and GDRIVE_SA_JSON): return None
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    if os.path.isfile(GDRIVE_SA_JSON):
        creds = service_account.Credentials.from_service_account_file(GDRIVE_SA_JSON, scopes=['https://www.googleapis.com/auth/drive'])
    else:
        creds = service_account.Credentials.from_service_account_info(json.loads(GDRIVE_SA_JSON), scopes=['https://www.googleapis.com/auth/drive'])
    return build('drive','v3',credentials=creds,cache_discovery=False)

def drive_ensure_folder(svc, name: str, parent_id: Optional[str]) -> str:
    if not svc: return ''
    q_name = name.replace("'", "\\'")
    q = f"name='{q_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    if parent_id: q += f" and '{parent_id}' in parents"
    res = svc.files().list(q=q, fields='files(id,name)', pageSize=1).execute()
    files = res.get('files', [])
    if files: return files[0]['id']
    meta = {'name':name,'mimeType':'application/vnd.google-apps.folder'}
    if parent_id: meta['parents']=[parent_id]
    return svc.files().create(body=meta, fields='id').execute()['id']

def drive_upload(svc, local_path: str, name: str, parent_id: str, mimetype: Optional[str]=None) -> str:
    if not svc: return ''
    from googleapiclient.http import MediaFileUpload
    media = MediaFileUpload(local_path, mimetype=mimetype, resumable=False)
    meta = {'name':name,'parents':[parent_id]}
    return svc.files().create(body=meta, media_body=media, fields='id').execute()['id']

def upload_to_drive_structured(local_path: str, reg: str, when: dt.datetime, name: str, mimetype: Optional[str]):
    if not (GDRIVE_ENABLED and GDRIVE_FOLDER_ID): return None
    svc = _drive_service()
    reg_folder = drive_ensure_folder(svc, reg, GDRIVE_FOLDER_ID)
    ym_folder  = drive_ensure_folder(svc, when.strftime('%Y-%m'), reg_folder)
    return drive_upload(svc, local_path, name, ym_folder, mimetype=mimetype)

TPL_BASE = r"""
<!doctype html>
<html lang="en" data-bs-theme="dark">
  <head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Driver Vehicle Check</title>
    <link rel="manifest" href="{{ url_for('manifest') }}">
    <meta name="theme-color" content="#0b0f14">
    <link rel="apple-touch-icon" href="/static/icons/icon-192.png">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body {padding-bottom: 60px;}
      .sig-pad {border:2px dashed #777; border-radius:12px; height:200px;}
      .photo-input {border:1px dashed #666; padding:12px; border-radius:12px;}
      .grid-2 {display:grid; grid-template-columns: 1fr 1fr; gap: 8px;}
      @media (max-width: 640px) {.grid-2 {grid-template-columns: 1fr;}}
      .logo {height: 28px;}
    </style>
  </head>
  <body class="bg-dark text-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-black border-bottom border-secondary sticky-top">
      <div class="container-fluid">
        <a class="navbar-brand d-flex align-items-center gap-2" href="{{ url_for('new_check') }}">
          <img src="/static/logo.png" alt="Logo" class="logo" onerror="this.style.display='none'">
          <span>🚚 Vehicle Check</span>
        </a>
        <div class="d-flex gap-2">
          <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('admin_dashboard') }}">Admin</a>
        </div>
      </div>
    </nav>
    <main class="container mt-3">
      {% with messages = get_flashed_messages() %}
        {% if messages %}<div class="alert alert-info">{{ messages[0] }}</div>{% endif %}
      {% endwith %}
      {% block content %}{% endblock %}
    </main>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
      const enableSW = !['localhost','127.0.0.1'].includes(location.hostname);
      if ('serviceWorker' in navigator && enableSW) {
        window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js'));
      } else if ('serviceWorker' in navigator) {
        // Unregister any old SW from earlier runs
        navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister()));
      }
    </script>
  </body>
</html>
"""

TPL_PIN = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <div class="mx-auto" style="max-width:420px;">
    <h3 class="mb-3">Enter Driver PIN</h3>
    <form method="post" class="card p-3 bg-secondary-subtle">
      <input class="form-control form-control-lg mb-3" type="password" name="pin" placeholder="PIN" autofocus required>
      <button class="btn btn-primary w-100">Continue</button>
    </form>
  </div>
{% endblock %}
"""

TPL_ADMIN_LOGIN = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <div class="mx-auto" style="max-width:420px;">
    <h3 class="mb-3">Admin Login</h3>
    <form method="post" class="card p-3 bg-secondary-subtle">
      <input class="form-control mb-3" type="password" name="password" placeholder="Admin password" required>
      <button class="btn btn-primary w-100">Login</button>
    </form>
  </div>
{% endblock %}
"""

TPL_FORM = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <h2 class="mb-3">Daily Vehicle Check</h2>
  <form method="post" enctype="multipart/form-data" class="card p-3 bg-secondary-subtle">
    {{ form.csrf_token }}
    <div class="grid-2">
      <div>
        <label class="form-label">Driver Name</label>
        {{ form.driver_name(class_='form-control', placeholder='e.g. Alex Smith') }}
      </div>
      <div>
        <label class="form-label">Vehicle Registration</label>
        <select class="form-select text-uppercase" name="vehicle_select" required>
          <option value="" selected disabled>Select registration</option>
          {% for v in vehicles %}
            <option value="{{ v.reg }}" data-mm="{{ v.make_model or '' }}">{{ v.reg }}{% if v.make_model %} — {{ v.make_model }}{% endif %}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    <div class="grid-2 mt-2">
      <div>
        <label class="form-label">Make / Model</label>
        <input id="mm" class="form-control" type="text" placeholder="Auto-filled" readonly>
      </div>
      <div>
        <label class="form-label">Odometer (miles)</label>
        {{ form.odometer(class_='form-control', placeholder='e.g. 41250') }}
      </div>
    </div>
    <div class="form-check mt-3">
      {{ form.safe_to_drive(class_='form-check-input', id='safe') }}
      <label class="form-check-label" for="safe">Safe to drive</label>
    </div>
    <hr>
    <h5 class="mt-2">Checklist</h5>
  {% for item in CHECK_ITEMS %}
  {% if not loop.first and (item.section != CHECK_ITEMS[loop.index0-1].section) %}
    <hr class="my-2">
  {% endif %}
  {% if loop.first or (item.section != CHECK_ITEMS[loop.index0-1].section) %}
    <h6 class="text-info mt-2">{{ item.section }}</h6>
  {% endif %}

  <div class="row align-items-center g-2 mb-2">
    <div class="col-sm-5">{{ item.label }}</div>
    <div class="col-sm-3">
      <div class="d-flex gap-3">
        <div class="form-check">
          <input class="form-check-input" type="radio" name="item_status_{{ loop.index0 }}" id="p{{ loop.index0 }}" value="pass">
          <label class="form-check-label" for="p{{ loop.index0 }}">Pass</label>
        </div>
        <div class="form-check">
          <input class="form-check-input" type="radio" name="item_status_{{ loop.index0 }}" id="f{{ loop.index0 }}" value="fail">
          <label class="form-check-label" for="f{{ loop.index0 }}">Fail</label>
        </div>
      </div>
    </div>
    <div class="col-sm-4">
      <input class="form-control" name="item_comment_{{ loop.index0 }}" placeholder="Comments (optional)">
    </div>
  </div>
{% endfor %}
    <div class="mt-3">
      <label class="form-label">Photos (defects, mileage, etc.)</label>
      <div class="photo-input">
        <input class="form-control" type="file" name="photos" accept="image/*" capture="environment" multiple>
        <small class="text-secondary">You can add multiple images.</small>
      </div>
    </div>
    <div class="mt-3">
      <label class="form-label">Driver Signature</label>
      <div><canvas id="sig" class="w-100 sig-pad"></canvas></div>
      <div class="mt-2 d-flex gap-2">
        <button type="button" class="btn btn-outline-light btn-sm" onclick="sigClear()">Clear</button>
        <button type="button" class="btn btn-outline-info btn-sm" onclick="sigUndo()">Undo</button>
      </div>
      {{ form.signature_data(id='signature_data') }}
    </div>
    <div class="mt-3">
      <label class="form-label">Additional Notes</label>
      {{ form.notes(class_='form-control', rows=3, placeholder='Anything else to record') }}
    </div>
    <div class="mt-4 d-grid">
      <button class="btn btn-primary btn-lg">Submit Check</button>
    </div>
  </form>
  <script>
    const select = document.querySelector('select[name="vehicle_select"]');
    const mmInput = document.getElementById('mm');
    function updateMM(){ const opt = select.selectedOptions[0]; mmInput.value = (opt && opt.dataset.mm) ? opt.dataset.mm : ''; }
    select.addEventListener('change', updateMM); updateMM();
    const canvas = document.getElementById('sig');
    const sigInput = document.getElementById('signature_data');
    const ctx = canvas.getContext('2d');
    let drawing = false; let points=[];
    function resize(){ canvas.width = canvas.clientWidth; canvas.height = 200; redraw(); }
    window.addEventListener('resize', resize); resize();
    function pos(e){ const r=canvas.getBoundingClientRect(); const t=e.touches?e.touches[0]:e; return {x:(t.clientX-r.left), y:(t.clientY-r.top)} }
    function start(e){ drawing=true; points.push([]); add(e); }
    function add(e){ if(!drawing) return; const p=pos(e); points[points.length-1].push(p); redraw(); }
    function end(){ drawing=false; save(); }
    function redraw(){ ctx.clearRect(0,0,canvas.width,canvas.height); ctx.lineWidth=2; ctx.lineCap='round'; ctx.strokeStyle='#fff';
      for(const stroke of points){ if(stroke.length<2) continue; ctx.beginPath(); ctx.moveTo(stroke[0].x, stroke[0].y); for(const p of stroke){ ctx.lineTo(p.x,p.y);} ctx.stroke(); }
      ctx.setLineDash([5,5]); ctx.strokeStyle='#777'; ctx.strokeRect(2,2,canvas.width-4,canvas.height-4); ctx.setLineDash([]);
    }
    function save(){ sigInput.value = canvas.toDataURL('image/png'); }
    function sigClear(){ points=[]; redraw(); save(); }
    function sigUndo(){ points.pop(); redraw(); save(); }
    canvas.addEventListener('mousedown', start); canvas.addEventListener('mousemove', add); window.addEventListener('mouseup', end);
    canvas.addEventListener('touchstart', (e)=>{e.preventDefault(); start(e);}); canvas.addEventListener('touchmove', (e)=>{e.preventDefault(); add(e);}); canvas.addEventListener('touchend', (e)=>{e.preventDefault(); end(e);});
  // Ensure signature is saved at submit time
  document.querySelector('form').addEventListener('submit', function() {
    save(); // write canvas -> hidden field
  });
</script>
{% endblock %}
"""

TPL_SUCCESS = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <div class="text-center py-5">
    <h3 class="mb-3">✅ Check Submitted</h3>
    <p>Reference: <strong>#{{ check.id }}</strong> — {{ check.vehicle.reg }} — {{ check.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</p>
    <a href="{{ url_for('new_check') }}" class="btn btn-outline-light mt-3">Submit another</a>
  </div>
{% endblock %}
"""

TPL_ADMIN = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
    <h3 class="me-auto">Admin — Recent Checks</h3>
    <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('admin_vehicles') }}">Manage Vehicles</a>
    <a class="btn btn-outline-info btn-sm" href="{{ url_for('export_csv') }}">Export CSV</a>
  </div>
  <div class="table-responsive">
    <table class="table table-dark table-striped align-middle">
      <thead><tr><th>ID</th><th>Time (UTC)</th><th>Driver</th><th>Reg</th><th>Odo</th><th>Safe?</th><th>Defects</th><th></th></tr></thead>
      <tbody>
        {% for c in rows %}
          <tr>
            <td>#{{ c.id }}</td>
            <td>{{ c.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
            <td>{{ c.driver_name }}</td>
            <td>{{ c.vehicle.reg }}</td>
            <td>{{ c.odometer or '' }}</td>
            <td>{% if c.safe_to_drive %}<span class="badge bg-success">Yes</span>{% else %}<span class="badge bg-danger">No</span>{% endif %}</td>
            <td class="text-truncate" style="max-width:300px;">{{ (c.defects or '-') }}</td>
            <td><a class="btn btn-sm btn-outline-light" href="{{ url_for('admin_check', check_id=c.id) }}">Open</a></td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% endblock %}
"""

TPL_DETAIL = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <h3>Check #{{ c.id }} — {{ c.vehicle.reg }}</h3>
  <p><strong>Driver:</strong> {{ c.driver_name }} | <strong>Time (UTC):</strong> {{ c.created_at.strftime('%Y-%m-%d %H:%M') }} | <strong>Odo:</strong> {{ c.odometer or '-' }}</p>
  <div class="row g-3">
    <div class="col-md-7">
      <div class="card card-body">
        <h5>Checklist</h5>
        {% if items %}
        <div class="table-responsive">
          <table class="table table-dark table-sm align-middle">
            <thead><tr><th>Section</th><th>Item</th><th>Status</th><th>Comment</th></tr></thead>
            <tbody>
              {% for it in items %}
                <tr>
                  <td class="text-secondary">{{ it.section }}</td>
                  <td>{{ it.label }}</td>
                  <td>{% if it.status=='pass' %}<span class="badge bg-success">Pass</span>{% elif it.status=='fail' %}<span class="badge bg-danger">Fail</span>{% else %}-{% endif %}</td>
                  <td>{{ it.comment }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
          <p class="text-secondary">No checklist captured.</p>
        {% endif %}
      </div>
      <div class="card card-body mt-3">
        <h5>Defects</h5>
        <p class="mb-0">{{ c.defects or '-' }}</p>
      </div>
      <div class="card card-body mt-3">
        <h5>Notes</h5>
        <p class="mb-0">{{ c.notes or '-' }}</p>
      </div>
    </div>
    <div class="col-md-5">
      <div class="card card-body">
        <h5>Photos</h5>
        {% if c.photos %}
          <div class="row row-cols-2 g-2">
            {% for p in c.photos %}
              <div class="col">
                <img class="img-fluid rounded"
                     src="{{ url_for('uploaded_file', filename=p.path.split('/')[-1]) }}"
                     alt="photo">
              </div>
            {% endfor %}
          </div>
        {% else %}
          <p class="text-secondary">No photos</p>
        {% endif %}
      </div>
      <div class="card card-body mt-3">
        <h5>Driver Signature</h5>
        {% if c.signature_path %}
          <img class="img-fluid bg-white rounded"
               src="{{ url_for('uploaded_file', filename=c.signature_path.split('/')[-1]) }}"
               alt="signature">
        {% else %}
          <p class="text-secondary">None</p>
        {% endif %}
      </div>
      <div class="mt-3">
        <a class="btn btn-outline-info" href="{{ url_for('export_csv') }}">Export CSV</a>
      </div>
    </div>
  </div>
{% endblock %}
"""

TPL_VEHICLES = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <div class="d-flex align-items-center mb-2 gap-2">
    <h3 class="me-auto">Manage Vehicles</h3>
    <a class="btn btn-outline-light btn-sm" href="{{ url_for('admin_dashboard') }}">Back</a>
  </div>
  <form method="post" class="card p-3 bg-secondary-subtle mb-3">
    <div class="row g-2">
      <div class="col-md-3"><input class="form-control text-uppercase" name="reg" placeholder="Registration (e.g. AB12CDE)" required></div>
      <div class="col-md-6"><input class="form-control" name="make_model" placeholder="Make / Model (optional)"></div>
      <div class="col-md-3 d-grid"><button class="btn btn-primary">Add Vehicle</button></div>
    </div>
  </form>
  <div class="table-responsive">
    <table class="table table-dark table-striped align-middle">
      <thead><tr><th>Reg</th><th>Make/Model</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>
        {% for v in vehicles %}
        <tr>
          <td>{{ v.reg }}</td>
          <td>{{ v.make_model }}</td>
          <td>{% if v.active %}<span class='badge bg-success'>Active{% else %}<span class='badge bg-secondary'>Inactive{% endif %}</span></td>
          <td class="d-flex gap-2">
            <a class="btn btn-sm btn-outline-light" href="{{ url_for('edit_vehicle', vid=v.id) }}">Edit</a>
            <a class="btn btn-sm btn-outline-info" href="{{ url_for('toggle_vehicle', vid=v.id) }}">Toggle</a>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% endblock %}
"""

TPL_VEHICLE_EDIT = r"""
{% extends 'TPL_BASE' %}
{% block content %}
  <div class="d-flex align-items-center mb-2 gap-2">
    <h3 class="me-auto">Edit Vehicle</h3>
    <a class="btn btn-outline-light btn-sm" href="{{ url_for('admin_vehicles') }}">Back</a>
  </div>
  <form method="post" class="card p-3 bg-secondary-subtle" style="max-width:560px;">
    <div class="mb-3">
      <label class="form-label">Registration</label>
      <input class="form-control text-uppercase" name="reg" value="{{ v.reg }}" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Make / Model</label>
      <input class="form-control" name="make_model" value="{{ v.make_model or '' }}">
    </div>
    <div class="d-flex gap-2">
      <button class="btn btn-primary">Save</button>
      <a class="btn btn-outline-secondary" href="{{ url_for('toggle_vehicle', vid=v.id) }}">
        {% if v.active %}Set Inactive{% else %}Set Active{% endif %}
      </a>
    </div>
  </form>
{% endblock %}
"""

app.jinja_loader = DictLoader({'TPL_BASE': TPL_BASE})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.cli.command('init-db')
def init_db():
    db.create_all()
    if not Vehicle.query.first():
        db.session.add(Vehicle(reg='AB12CDE', make_model='Ford Transit'))
        db.session.add(Vehicle(reg='XY34ZFG', make_model='VW Caddy'))
        db.session.commit()
    print('DB initialised ✅')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.getenv('PORT', '5001'))
    app.run(host='0.0.0.0', port=port, debug=True)
