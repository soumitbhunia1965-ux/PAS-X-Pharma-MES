"""
Pharma MES Enterprise Suite - Site 102 OSD
Compliance-oriented reference implementation.

Designed to support controls commonly expected for:
- 21 CFR Part 11 electronic records/e-signatures
- EU GMP Annex 11 computerized systems
- ALCOA+ data-integrity principles
- 21 CFR Part 211 OSD manufacturing records and controls

IMPORTANT:
This software is NOT by itself a regulatory approval or validated GxP system.
Before GxP production use, perform documented intended-use/risk assessment,
URS/FRS, supplier assessment, IQ/OQ/PQ or equivalent validation, security
assessment, SOP approval, training, backup/restore testing, periodic review,
and site-specific Part 11 / Annex 11 assessment.
"""

import csv, hashlib, io, json, os, re, secrets, sqlite3, subprocess, threading, time, webbrowser
from pathlib import Path
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template_string, flash, session, g,
    Response, abort, has_request_context
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_VERSION = "11.0-OSD-COMPLIANCE-EXECUTION-FLOW"
DB_NAME = os.environ.get("PHARMA_MES_DB", "pharma_mes_site102_v11.db")
SITE_ID = "SITE-102"
SESSION_TIMEOUT_MIN = 15
MAX_FAILED = 5
PASSWORD_MIN_LEN = 8
CLEAN_HOLD_HOURS = 72
BMS_STALE_MIN = 60
BMS_LIMITS = {"temp": (15.0, 25.0), "rh": (30.0, 60.0), "dp_min": 15.0}
LIMS_SPEC = (95.0, 105.0)

app = Flask(__name__)

def _load_secret():
    p = os.environ.get("PHARMA_MES_SECRET_FILE", ".pharma_mes_secret")
    if os.path.exists(p):
        return open(p, "r", encoding="utf-8").read().strip()
    k = secrets.token_hex(32)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(k)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return k

app.secret_key = os.environ.get("PHARMA_MES_SECRET_KEY") or _load_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PHARMA_MES_SECURE_COOKIE", "0") == "1",
)

def now_utc():
    return datetime.now(timezone.utc)

def ts(**delta):
    return (now_utc() + timedelta(**delta)).strftime("%Y-%m-%d %H:%M:%S")

def today(**delta):
    return (now_utc() + timedelta(**delta)).strftime("%Y-%m-%d")

def connect():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def _hash(*parts):
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()

def json_text(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)

# ---------------------------- RBAC / AUTHORITY ----------------------------

ROLE_PERMS = {
    "System Administrator": {"ADMIN_USERS", "ADMIN_MASTER", "ADMIN_SECURITY", "VIEW_ALL"},
    "Master Data Administrator": {"ADMIN_MASTER", "VIEW_ALL"},
    "Manufacturing Operator": {"EXECUTE", "VIEW_EXECUTION"},
    "Dispensing Operator": {"DISPENSE", "VIEW_EXECUTION"},
    "Packaging Operator": {"PACKAGE", "VIEW_EXECUTION"},
    "Supervisor": {"EXECUTE", "DISPENSE", "PACKAGE", "SUPERVISE", "VIEW_ALL"},
    "QA Reviewer": {"QA_REVIEW", "VIEW_ALL"},
    "QA Release": {"QA_REVIEW", "QA_RELEASE", "VIEW_ALL"},
    "QC Analyst": {"QC", "VIEW_ALL"},
    "Engineering": {"ENGINEERING", "VIEW_ALL"},
    "Warehouse": {"WAREHOUSE", "VIEW_ALL"},
    "Auditor": {"AUDIT_READ", "VIEW_ALL"},
}

ALL_ROLES = tuple(ROLE_PERMS)

TRAIN = {
    "SOP-WD-01": "Dispensing, balance use, FEFO and material verification",
    "SOP-MFG-02": "OSD granulation and equipment safety",
    "SOP-TAB-03": "Compression and tooling inspection",
    "SOP-EBR-09": "Electronic batch record execution",
    "SOP-QA-05": "Batch review, deviations and release",
    "SOP-PKG-03": "Packaging line clearance and serialization",
    "GXP-DI-01": "GxP Data Integrity / ALCOA+",
    "GXP-PT11-01": "21 CFR Part 11 / electronic signatures",
}

def current_user():
    return session.get("user")

def has_perm(permission):
    u = current_user()
    return bool(u and permission in ROLE_PERMS.get(u["role"], set()))

def require_perm(permission):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if "user" not in session:
                return redirect(url_for("login"))
            if not (has_perm(permission) or has_perm("VIEW_ALL")):
                flash(f"Access denied: {permission} authority required.", "danger")
                return redirect(url_for("index"))
            return f(*a, **kw)
        return wrapper
    return deco

def _user_row(conn, username):
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def log_audit(conn, username, module, action, details, record_ref=None,
              old=None, new=None, reason=None, severity="INFO"):
    """
    Append-only application audit event.
    Hash chaining is an integrity-detection mechanism; it is not a substitute
    for database/storage access control, backup, review and validation.
    """
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    prev = conn.execute(
        "SELECT record_hash FROM audit_trail ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = prev["record_hash"] if prev else "GENESIS"
    u = _user_row(conn, username) if username else None
    full = u["full_name"] if u else "SYSTEM"
    role = u["role"] if u else "SYSTEM"
    ip = request.remote_addr if has_request_context() else "system"
    t = ts()
    old_s = None if old is None else json_text(old)
    new_s = None if new is None else json_text(new)
    h = _hash(
        prev_hash, t, username or "SYSTEM", full, role, SITE_ID, module, action,
        record_ref, old_s, new_s, reason, details, ip, severity
    )
    conn.execute(
        """INSERT INTO audit_trail
        (timestamp,username,full_name,role,site_id,module,action,record_ref,
         old_value,new_value,reason,details,ip_address,severity,prev_hash,record_hash)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (t, username or "SYSTEM", full, role, SITE_ID, module, action,
         record_ref, old_s, new_s, reason, details, ip, severity, prev_hash, h)
    )

def record_signature(conn, user, meaning, record_type, record_id, snapshot, reason=None):
    """
    Re-authenticated electronic signature record. Signature is linked to the
    exact record snapshot by hash and carries signer identity, role and meaning.
    """
    t = ts()
    snap = json_text(snapshot)
    record_hash = hashlib.sha256(snap.encode()).hexdigest()
    sig_hash = _hash(record_hash, user["username"], user["full_name"],
                     user["role"], meaning, record_type, record_id, t)
    cur = conn.execute(
        """INSERT INTO e_signatures
        (timestamp,username,full_name,role,site_id,meaning,record_type,record_id,
         record_hash,sig_hash,reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (t, user["username"], user["full_name"], user["role"], SITE_ID, meaning,
         record_type, str(record_id), record_hash, sig_hash, reason)
    )
    return cur.lastrowid

def verify_esign(conn, password, allowed_roles=None, qualification=None, permission=None):
    sess = current_user()
    if not sess:
        return None, "Session is not authenticated."
    uname = sess["username"]
    row = _user_row(conn, uname)
    if not row or not row["active"] or row["locked"]:
        return None, "Account is inactive or locked."
    if len(password or "") < PASSWORD_MIN_LEN:
        return None, "Electronic signature authentication requires the current password."
    if not check_password_hash(row["password_hash"], password):
        n = row["failed_attempts"] + 1
        lock = 1 if n >= MAX_FAILED else 0
        conn.execute(
            "UPDATE users SET failed_attempts=?, locked=? WHERE username=?",
            (n, lock, uname)
        )
        log_audit(conn, uname, "SECURITY", "ESIGN_AUTH_FAILED",
                  f"Electronic-signature authentication failed (attempt {n}/{MAX_FAILED}).",
                  severity="SECURITY")
        return None, "Invalid electronic-signature authentication."
    if allowed_roles and row["role"] not in allowed_roles:
        return None, f"Role not authorized ({row['role']})."
    if permission and permission not in ROLE_PERMS.get(row["role"], set()):
        return None, f"Authority not authorized ({permission})."
    if qualification:
        tr = conn.execute(
            """SELECT 1 FROM user_training
               WHERE username=? AND course_code=? AND status='QUALIFIED'
               AND valid_until>=?""",
            (uname, qualification, today())
        ).fetchone()
        if not tr:
            return None, f"Missing current training qualification [{qualification}]."
    conn.execute(
        "UPDATE users SET failed_attempts=0, last_login=? WHERE username=?",
        (ts(), uname)
    )
    return row, "OK"

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def security_gate():
    if request.endpoint == "static":
        return
    if request.method == "POST":
        tok = request.form.get("csrf_token", "")
        if not tok or not secrets.compare_digest(tok, session.get("csrf", "")):
            abort(400, "CSRF token validation failed.")
    u = session.get("user")
    if u and time.time() - session.get("last_active", 0) > SESSION_TIMEOUT_MIN * 60:
        session.clear()
        flash("Session expired due to inactivity.", "warning")
        return redirect(url_for("login"))
    if u:
        session["last_active"] = time.time()

# ---------------------------- DATABASE / MASTER DATA ----------------------------

def init_db():
    conn = connect()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, full_name TEXT NOT NULL, role TEXT NOT NULL,
        site_id TEXT NOT NULL, password_hash TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1, locked INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0, last_login TEXT,
        created_at TEXT NOT NULL, created_by TEXT, changed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS user_training (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        course_code TEXT NOT NULL, course_name TEXT NOT NULL, status TEXT NOT NULL,
        valid_until TEXT NOT NULL, qualified_by TEXT, qualified_at TEXT,
        UNIQUE(username,course_code)
    );
    CREATE TABLE IF NOT EXISTS rooms (
        room_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, room_name TEXT NOT NULL,
        grade TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'QUALIFIED',
        temp_min REAL, temp_max REAL, rh_min REAL, rh_max REAL,
        dp_min REAL, last_sync TEXT, active INTEGER DEFAULT 1,
        created_at TEXT, created_by TEXT
    );
    CREATE TABLE IF NOT EXISTS cleanroom_bms (
        room_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, room_name TEXT,
        grade TEXT, temp_c REAL, rh_pct REAL, diff_press_pa REAL,
        status TEXT, last_sync TEXT
    );
    CREATE TABLE IF NOT EXISTS equipment (
        eq_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, name TEXT NOT NULL,
        area TEXT NOT NULL, status TEXT NOT NULL, last_cleaned TEXT,
        clean_valid_until TEXT, eq_type TEXT, cal_due_date TEXT,
        qualification_status TEXT DEFAULT 'QUALIFIED', active INTEGER DEFAULT 1,
        created_at TEXT, created_by TEXT
    );
    CREATE TABLE IF NOT EXISTS equipment_logbook (
        id INTEGER PRIMARY KEY AUTOINCREMENT, eq_id TEXT NOT NULL, site_id TEXT,
        event_type TEXT NOT NULL, details TEXT NOT NULL, performed_by TEXT,
        timestamp TEXT NOT NULL, reason TEXT
    );
    CREATE TABLE IF NOT EXISTS materials (
        lot_no TEXT PRIMARY KEY, site_id TEXT NOT NULL, mat_code TEXT NOT NULL,
        mat_name TEXT NOT NULL, qty_available REAL NOT NULL, uom TEXT NOT NULL,
        expiry_date TEXT NOT NULL, qc_status TEXT NOT NULL,
        storage_location TEXT, received_at TEXT, released_at TEXT
    );
    CREATE TABLE IF NOT EXISTS inventory_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, lot_no TEXT NOT NULL, batch_id TEXT,
        tx_type TEXT NOT NULL, qty REAL NOT NULL, uom TEXT, balance_after REAL,
        performed_by TEXT NOT NULL, timestamp TEXT NOT NULL, reason TEXT,
        source_ref TEXT
    );
    CREATE TABLE IF NOT EXISTS mbr_headers (
        mbr_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, product_name TEXT NOT NULL,
        batch_size TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL,
        lifecycle_state TEXT NOT NULL DEFAULT 'DRAFT',
        effective_from TEXT, supersedes_mbr TEXT, created_at TEXT, created_by TEXT,
        approved_at TEXT, approved_by TEXT
    );
    CREATE TABLE IF NOT EXISTS mbr_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT, mbr_id TEXT NOT NULL, site_id TEXT,
        step_no INTEGER NOT NULL, phase_type TEXT NOT NULL, phase_name TEXT NOT NULL,
        instruction TEXT NOT NULL, min_val REAL, max_val REAL, uom TEXT,
        req_training TEXT, required INTEGER DEFAULT 1,
        UNIQUE(mbr_id,step_no)
    );
    CREATE TABLE IF NOT EXISTS batches (
        batch_id TEXT PRIMARY KEY, site_id TEXT NOT NULL, sap_order_no TEXT,
        mbr_id TEXT NOT NULL, product_name TEXT NOT NULL, eq_id TEXT,
        packaging_line TEXT, room_id TEXT, status TEXT NOT NULL,
        qa_disposition_by TEXT, created_at TEXT NOT NULL, created_by TEXT,
        started_at TEXT, completed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS batch_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL, site_id TEXT,
        step_no INTEGER NOT NULL, phase_type TEXT, phase_name TEXT, instruction TEXT,
        min_val REAL, max_val REAL, uom TEXT, actual_val REAL,
        status TEXT NOT NULL, performed_by TEXT, verified_by TEXT, capa_ref TEXT,
        timestamp TEXT, req_training TEXT, executed_at TEXT, executed_reason TEXT
    );
    CREATE TABLE IF NOT EXISTS weigh_dispense_records (
        dispense_id TEXT PRIMARY KEY, site_id TEXT, batch_id TEXT NOT NULL,
        lot_no TEXT NOT NULL, mat_name TEXT, target_qty REAL NOT NULL,
        actual_qty REAL NOT NULL, tare_weight REAL NOT NULL, scale_id TEXT,
        room_id TEXT, uom TEXT, performed_by TEXT, verified_by TEXT,
        timestamp TEXT, barcode_label TEXT, status TEXT DEFAULT 'PENDING_VERIFICATION',
        tolerance_min REAL, tolerance_max REAL
    );
    CREATE TABLE IF NOT EXISTS packaging_runs (
        pack_run_id TEXT PRIMARY KEY, site_id TEXT, batch_id TEXT NOT NULL,
        line_id TEXT NOT NULL, line_clearance_by TEXT, target_units INTEGER,
        packed_units INTEGER DEFAULT 0, status TEXT, started_at TEXT,
        completed_at TEXT, units_issued INTEGER DEFAULT 0, units_rejected INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS serialization_units (
        serial_no TEXT PRIMARY KEY, site_id TEXT, batch_id TEXT, pack_run_id TEXT,
        gtin TEXT, aggregation_case_id TEXT, status TEXT DEFAULT 'ACTIVE',
        timestamp TEXT
    );
    CREATE TABLE IF NOT EXISTS samples (
        sample_id TEXT PRIMARY KEY, site_id TEXT, batch_id TEXT NOT NULL,
        sample_point TEXT, test_name TEXT NOT NULL, spec_min REAL, spec_max REAL,
        result_val REAL, status TEXT NOT NULL, analyst TEXT, sampled_at TEXT,
        reviewed_by TEXT, oos_closed INTEGER DEFAULT 0, oos_ref TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_trail (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        username TEXT NOT NULL, full_name TEXT, role TEXT, site_id TEXT,
        module TEXT, action TEXT, record_ref TEXT, old_value TEXT, new_value TEXT,
        reason TEXT, details TEXT, ip_address TEXT, severity TEXT,
        prev_hash TEXT, record_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS e_signatures (
        sig_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        username TEXT NOT NULL, full_name TEXT, role TEXT, site_id TEXT,
        meaning TEXT NOT NULL, record_type TEXT NOT NULL, record_id TEXT NOT NULL,
        record_hash TEXT NOT NULL, sig_hash TEXT NOT NULL, reason TEXT
    );
    CREATE TABLE IF NOT EXISTS genealogy (
        id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT, parent_type TEXT,
        parent_id TEXT, child_type TEXT, child_id TEXT, relation TEXT,
        qty REAL, uom TEXT, timestamp TEXT, performed_by TEXT
    );
    CREATE TABLE IF NOT EXISTS deviations (
        deviation_id TEXT PRIMARY KEY, batch_id TEXT, module TEXT,
        description TEXT NOT NULL, status TEXT NOT NULL, initiated_by TEXT,
        initiated_at TEXT, investigation TEXT, capa TEXT, closed_by TEXT, closed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS change_control (
        change_id TEXT PRIMARY KEY, object_type TEXT, object_id TEXT,
        description TEXT NOT NULL, impact TEXT, status TEXT NOT NULL,
        requested_by TEXT, requested_at TEXT, approved_by TEXT, approved_at TEXT,
        implemented_by TEXT, implemented_at TEXT
    );
    CREATE TABLE IF NOT EXISTS review_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT NOT NULL,
        exception_type TEXT, reference_id TEXT, disposition TEXT,
        reviewed_by TEXT, reviewed_at TEXT, comments TEXT
    );
    CREATE TABLE IF NOT EXISTS backup_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, performed_by TEXT,
        file_path TEXT, sha256 TEXT, result TEXT, details TEXT
    );
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY, value TEXT, changed_at TEXT, changed_by TEXT
    );
    """)
    seed_master_data(conn)
    conn.commit()
    conn.close()

def seed_master_data(conn):
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        seed_users = [
            ("admin_site102", "Site 102 System Administrator", "System Administrator", "0000admin"),
            ("mdm_site102", "Master Data Administrator", "Master Data Administrator", "0000mdm"),
            ("op_john", "John Doe - Manufacturing Operator", "Manufacturing Operator", "0000john"),
            ("disp_mary", "Mary Singh - Dispensing Operator", "Dispensing Operator", "0000disp"),
            ("pack_lisa", "Lisa Wong - Packaging Operator", "Packaging Operator", "0000pack"),
            ("sup_mike", "Mike Ross - Shift Supervisor", "Supervisor", "0000sup"),
            ("qa_sarah", "Sarah Jenkins - QA Release", "QA Release", "0000qa"),
            ("qc_amit", "Amit Rao - QC Analyst", "QC Analyst", "0000qc"),
            ("eng_david", "David Chen - Engineering", "Engineering", "0000eng"),
            ("wh_priya", "Priya Shah - Warehouse", "Warehouse", "0000wh"),
            ("audit_demo", "Compliance Auditor", "Auditor", "0000audit"),
        ]
        for uname, name, role, pwd in seed_users:
            conn.execute(
                """INSERT INTO users
                (username,full_name,role,site_id,password_hash,created_at,created_by,changed_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (uname, name, role, SITE_ID, generate_password_hash(pwd),
                 ts(), "SYSTEM", ts())
            )
            for cc, cname in TRAIN.items():
                conn.execute(
                    """INSERT INTO user_training
                    (username,course_code,course_name,status,valid_until,qualified_by,qualified_at)
                    VALUES (?,?,?,?,?,?,?)""",
                    (uname, cc, cname, "QUALIFIED", today(days=365),
                     "SYSTEM", ts())
                )

    if conn.execute("SELECT COUNT(*) FROM rooms").fetchone()[0] == 0:
        rooms = [
            ("CR-102-DISP", "Downflow Dispensing Booth 1", "Grade C"),
            ("CR-102-GRAN", "High Shear Granulation Suite A", "Grade D"),
            ("CR-102-TAB", "Rotary Compression Suite 2", "Grade D"),
            ("CR-102-COAT", "Perforated Pan Coating Suite 1", "Grade D"),
            ("CR-102-PKG", "Primary Blister Packaging Bay", "CNC"),
        ]
        for rid, name, grade in rooms:
            conn.execute(
                """INSERT INTO rooms
                (room_id,site_id,room_name,grade,status,temp_min,temp_max,rh_min,rh_max,dp_min,
                 last_sync,active,created_at,created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid,SITE_ID,name,grade,"QUALIFIED",15,25,30,60,15,ts(),1,ts(),"SYSTEM")
            )
            conn.execute(
                """INSERT INTO cleanroom_bms
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (rid,SITE_ID,name,grade,21.0,42.0,20.0,"COMPLIANT",ts())
            )

    if conn.execute("SELECT COUNT(*) FROM equipment").fetchone()[0] == 0:
        eq = [
            ("EQ-SCALE-102","Precision Balance","CR-102-DISP","WEIGH"),
            ("EQ-HSM-102","600L High Shear Granulator","CR-102-GRAN","PROC"),
            ("EQ-FBD-102","500kg Fluid Bed Dryer","CR-102-GRAN","PROC"),
            ("EQ-TAB-102","Rotary Tablet Press","CR-102-TAB","PROC"),
            ("EQ-PACK-102","High Speed Blister Line","CR-102-PKG","PACK"),
        ]
        for eid,name,area,typ in eq:
            conn.execute(
                """INSERT INTO equipment
                (eq_id,site_id,name,area,status,last_cleaned,clean_valid_until,eq_type,
                 cal_due_date,qualification_status,active,created_at,created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (eid,SITE_ID,name,area,"CLEAN",ts(),ts(hours=CLEAN_HOLD_HOURS),typ,
                 today(days=180),"QUALIFIED",1,ts(),"SYSTEM")
            )

    if conn.execute("SELECT COUNT(*) FROM materials").fetchone()[0] == 0:
        mats = [
            ("LOT-PARA-26A","RM-1001","Paracetamol Fine Powder API",850,"kg","2028-12-31","RELEASED","RM-A01"),
            ("LOT-MCC-26B","EX-2004","Microcrystalline Cellulose PH102",1500,"kg","2029-06-30","RELEASED","RM-A02"),
            ("LOT-STEAR-26C","EX-3001","Magnesium Stearate Pharma Grade",200,"kg","2028-08-15","RELEASED","RM-A03"),
        ]
        for lot,code,name,qty,uom,exp,qc,loc in mats:
            conn.execute(
                """INSERT INTO materials
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (lot,SITE_ID,code,name,qty,uom,exp,qc,loc,ts(),ts())
            )

    if conn.execute("SELECT COUNT(*) FROM mbr_headers").fetchone()[0] == 0:
        conn.execute(
            """INSERT INTO mbr_headers
            (mbr_id,site_id,product_name,batch_size,version,status,lifecycle_state,
             effective_from,created_at,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("MBR-PARA-500MG",SITE_ID,"Paracetamol 500mg Compression Tablets",
             "500 kg / 1,000,000 tablets","v1.0","APPROVED","EFFECTIVE",
             today(),ts(),"SYSTEM")
        )
        steps = [
            (10,"DISPENSE","Weigh Paracetamol Active API",
             "Tare verified container and dispense target quantity.",49.5,50.5,"kg","SOP-WD-01"),
            (20,"MANUFACTURING","High Shear Granulation Phase",
             "Mix binder and active at validated process settings.",140,160,"RPM","SOP-MFG-02"),
            (30,"MANUFACTURING","Main Compression Force",
             "Maintain validated compression force.",18,22,"kN","SOP-TAB-03"),
            (40,"QUALITY","Tablet Assay Potency Testing",
             "Submit representative sample for assay testing.",95,105,"%","SOP-EBR-09"),
        ]
        for s in steps:
            conn.execute(
                """INSERT INTO mbr_steps
                (mbr_id,site_id,step_no,phase_type,phase_name,instruction,min_val,max_val,uom,req_training)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("MBR-PARA-500MG",SITE_ID,*s)
            )

def require_reason():
    reason = request.form.get("reason","").strip()
    if len(reason) < 5:
        raise ValueError("A meaningful reason/comment is required.")
    return reason

def validate_id(value, label):
    value = (value or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{2,63}", value):
        raise ValueError(f"Invalid {label}. Use 3-64 letters/numbers/_/-/.")
    return value

def recompute_status(conn, batch_id):
    b = conn.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
    if not b:
        return None
    if b["status"] in ("RELEASED_COMMERCIAL","REJECTED_QUARANTINE"):
        return b["status"]
    open_dev = conn.execute(
        "SELECT COUNT(*) FROM deviations WHERE batch_id=? AND status!='CLOSED'",
        (batch_id,)
    ).fetchone()[0]
    open_oos = conn.execute(
        "SELECT COUNT(*) FROM samples WHERE batch_id=? AND status LIKE 'OOS%' AND oos_closed=0",
        (batch_id,)
    ).fetchone()[0]
    pending_verify = conn.execute(
        """SELECT COUNT(*) FROM weigh_dispense_records
           WHERE batch_id=? AND status!='VERIFIED'""", (batch_id,)
    ).fetchone()[0]
    incomplete = conn.execute(
        """SELECT COUNT(*) FROM batch_steps
           WHERE batch_id=? AND status NOT LIKE 'COMPLETED%'""", (batch_id,)
    ).fetchone()[0]
    if open_dev:
        st = "HOLD (DEVIATION)"
    elif open_oos:
        st = "HOLD (LIMS OOS)"
    elif pending_verify:
        st = "HOLD (DISPENSE VERIFICATION)"
    elif incomplete:
        st = "IN PROGRESS"
    else:
        st = "READY FOR QA RELEASE"
    conn.execute("UPDATE batches SET status=? WHERE batch_id=?", (st,batch_id))
    return st

# ---------------------------- LOGIN ----------------------------

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        conn = get_db()
        row = _user_row(conn, username)
        if not row or not row["active"] or row["locked"] or not check_password_hash(row["password_hash"], password):
            if row:
                n = row["failed_attempts"] + 1
                locked = 1 if n >= MAX_FAILED else 0
                conn.execute("UPDATE users SET failed_attempts=?,locked=? WHERE username=?",
                             (n,locked,username))
                log_audit(conn, username, "SECURITY", "LOGIN_FAILED",
                          f"Invalid login attempt {n}/{MAX_FAILED}.", severity="SECURITY")
                conn.commit()
            flash("Invalid credentials or account unavailable.", "danger")
            return redirect(url_for("login"))
        session.clear()
        session["user"] = {
            "username":row["username"], "full_name":row["full_name"],
            "role":row["role"], "site_id":row["site_id"]
        }
        session["last_active"] = time.time()
        conn.execute("UPDATE users SET failed_attempts=0,last_login=? WHERE username=?",(ts(),username))
        log_audit(conn, username, "SECURITY", "LOGIN_SUCCESS", "User authenticated.")
        conn.commit()
        return redirect(url_for("index"))
    return render_template_string(LOGIN_UI)

@app.route("/logout")
def logout():
    u = current_user()
    if u:
        conn=get_db()
        log_audit(conn,u["username"],"SECURITY","LOGOUT","User signed out.")
        conn.commit()
    session.clear()
    return redirect(url_for("login"))

# ---------------------------- NAV / DASHBOARD ----------------------------

NAV = [
    ("process_flow","Process Flow & Execution","bi-diagram-3-fill"),
    ("dashboard","Dashboard","bi-speedometer2"),
    ("master","Master Data","bi-database-gear"),
    ("mbr","MBR / Recipe","bi-journal-code"),
    ("batch","Batch Execution","bi-play-circle"),
    ("dispense","Weigh / Dispense","bi-basket2"),
    ("packaging","Packaging","bi-box-seam"),
    ("inventory","Materials / Inventory","bi-archive"),
    ("quality","Sampling / QC","bi-eyedropper"),
    ("equipment","Equipment / Rooms","bi-sliders"),
    ("training","Personnel / Training","bi-person-badge"),
    ("rbe","Review by Exception","bi-patch-exclamation"),
    ("genealogy","Genealogy / Traceability","bi-diagram-3"),
    ("logbooks","Electronic Logbooks","bi-journal-text"),
    ("deviation","Deviations / CAPA","bi-exclamation-diamond"),
    ("change","Change Control","bi-arrow-repeat"),
    ("audit","Audit / Compliance","bi-shield-lock"),
    ("backup","Backup / Archive","bi-safe"),
]

def build_flow_state(conn, active_batch, steps, mbrs, materials, samples, packaging):
    """Build a live execution-flow state without replacing the detailed EBR table."""
    state = {
        "spec_ims": "completed",
        "spec_mbr": "completed" if mbrs else "pending",
        "sched": "completed" if active_batch else "pending",
        "dispense": "pending", "weighing": "pending", "mat_flow": "pending",
        "ebr": "pending", "equip": "pending", "wh": "completed" if materials else "pending",
        "lims": "pending", "tnt": "pending", "perf": "completed" if active_batch else "pending",
        "granulation": "pending", "tabletting": "pending", "packaging": "pending"
    }
    if not active_batch:
        return state
    bid = active_batch["batch_id"]
    disp = conn.execute("SELECT COUNT(*) c FROM weigh_dispense_records WHERE batch_id=?", (bid,)).fetchone()["c"]
    dispv = conn.execute("SELECT COUNT(*) c FROM weigh_dispense_records WHERE batch_id=? AND status='VERIFIED'", (bid,)).fetchone()["c"]
    if disp:
        state["dispense"] = "completed" if dispv == disp else "active"
        state["weighing"] = state["dispense"]
        state["mat_flow"] = "completed"
    else:
        state["dispense"] = state["weighing"] = state["mat_flow"] = "active"
    eq = conn.execute("SELECT status FROM equipment WHERE eq_id=?", (active_batch["eq_id"],)).fetchone()
    if eq:
        if eq["status"] == "IN USE": state["equip"] = "active"
        elif eq["status"] == "CLEAN": state["equip"] = "completed"
    for s in steps:
        name = (s["phase_name"] or "").lower()
        target = "ebr"
        if "granulation" in name: target = "granulation"
        elif any(x in name for x in ("tabletting", "compression", "tablet")): target = "tabletting"
        elif "packag" in name: target = "packaging"
        if s["status"] == "READY":
            state[target] = "active"; state["ebr"] = "active"
        elif str(s["status"]).startswith("COMPLETED") and state[target] != "active":
            state[target] = "completed"
        elif s["status"] == "DEVIATION":
            state[target] = state["ebr"] = "deviation"
    qs = conn.execute("SELECT status FROM samples WHERE batch_id=?", (bid,)).fetchall()
    if qs:
        if any("OOS" in (r["status"] or "") for r in qs): state["lims"] = "deviation"
        elif any("PASS" in (r["status"] or "") for r in qs): state["lims"] = "completed"
        else: state["lims"] = "active"
    packs = conn.execute("SELECT status FROM packaging_runs WHERE batch_id=?", (bid,)).fetchall()
    if packs:
        if any((r["status"] or "").upper() == "COMPLETED" for r in packs): state["packaging"] = "completed"
        else: state["packaging"] = "active"
    if active_batch["status"] in ("READY FOR QA RELEASE", "RELEASED_COMMERCIAL"):
        state["tnt"] = "completed"
        state["packaging"] = "completed"
    return state

@app.route("/")
@require_perm("VIEW_EXECUTION")
def index():
    tab=request.args.get("tab","process_flow")
    conn=get_db()
    batches=conn.execute("SELECT * FROM batches ORDER BY created_at DESC").fetchall()
    materials=conn.execute("SELECT * FROM materials ORDER BY expiry_date").fetchall()
    equipment=conn.execute("SELECT * FROM equipment ORDER BY eq_id").fetchall()
    rooms=conn.execute("SELECT * FROM rooms ORDER BY room_id").fetchall()
    users=conn.execute("SELECT username,full_name,role,active,locked FROM users ORDER BY username").fetchall()
    mbrs=conn.execute("SELECT * FROM mbr_headers ORDER BY mbr_id").fetchall()
    mbr_steps=conn.execute("SELECT * FROM mbr_steps ORDER BY mbr_id,step_no").fetchall()
    audits=conn.execute("SELECT * FROM audit_trail ORDER BY id DESC LIMIT 100").fetchall()
    training=conn.execute("SELECT * FROM user_training ORDER BY username,course_code").fetchall()
    logs=conn.execute("SELECT * FROM equipment_logbook ORDER BY id DESC LIMIT 50").fetchall()
    samples=conn.execute("SELECT * FROM samples ORDER BY sampled_at DESC LIMIT 50").fetchall()
    deviations=conn.execute("SELECT * FROM deviations ORDER BY initiated_at DESC").fetchall()
    changes=conn.execute("SELECT * FROM change_control ORDER BY requested_at DESC").fetchall()
    active_batch_id=request.args.get("batch_id","")
    if not active_batch_id and batches:
        active_batch_id=batches[0]["batch_id"]
    active_batch=conn.execute("SELECT * FROM batches WHERE batch_id=?",(active_batch_id,)).fetchone() if active_batch_id else None
    steps=conn.execute("SELECT * FROM batch_steps WHERE batch_id=? ORDER BY step_no",(active_batch_id,)).fetchall() if active_batch_id else []
    dispenses=conn.execute("SELECT * FROM weigh_dispense_records WHERE batch_id=? ORDER BY timestamp DESC",(active_batch_id,)).fetchall() if active_batch_id else []
    packaging=conn.execute("SELECT * FROM packaging_runs WHERE batch_id=? ORDER BY started_at DESC",(active_batch_id,)).fetchall() if active_batch_id else []
    flow_state=build_flow_state(conn, active_batch, steps, mbrs, materials, samples, packaging)
    return render_template_string(
        MAIN_UI, tab=tab,user=current_user(),nav=NAV,version=APP_VERSION,now=ts(),
        batches=batches,materials=materials,equipment=equipment,rooms=rooms,users=users,
        mbrs=mbrs,mbr_steps=mbr_steps,audits=audits,training=training,logs=logs,
        samples=samples,deviations=deviations,changes=changes,active_batch=active_batch,
        steps=steps,dispenses=dispenses,packaging=packaging,flow_state=flow_state
    )

# ---------------------------- ADMIN / MASTER DATA ----------------------------

@app.route("/admin/user", methods=["POST"])
@require_perm("ADMIN_USERS")
def admin_user():
    conn=get_db(); f=request.form
    try:
        username=validate_id(f.get("username","").lower(),"username")
        if len(username)>40: raise ValueError("Username too long.")
        name=f.get("full_name","").strip()
        role=f.get("role","")
        password=f.get("password","")
        if not name or role not in ALL_ROLES or len(password)<PASSWORD_MIN_LEN:
            raise ValueError("Full name, approved role and password (minimum 8 characters) are required.")
        reason=require_reason()
        if conn.execute("SELECT 1 FROM users WHERE username=?",(username,)).fetchone():
            raise ValueError("User already exists.")
        actor=current_user()["username"]
        conn.execute(
            """INSERT INTO users
            (username,full_name,role,site_id,password_hash,created_at,created_by,changed_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (username,name,role,SITE_ID,generate_password_hash(password),ts(),actor,ts())
        )
        log_audit(conn,actor,"MASTER_DATA","USER_CREATED",
                  f"Created user {username} with role {role}.",username,reason=reason)
        conn.commit()
        flash(f"User {username} created.", "success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="master"))

@app.route("/admin/user/<username>/role", methods=["POST"])
@require_perm("ADMIN_USERS")
def change_user_role(username):
    conn=get_db(); f=request.form
    try:
        role=f.get("role","")
        if role not in ALL_ROLES: raise ValueError("Invalid role.")
        reason=require_reason()
        row=_user_row(conn,username)
        if not row: raise ValueError("User not found.")
        old={"role":row["role"],"active":row["active"],"locked":row["locked"]}
        conn.execute("UPDATE users SET role=?,changed_at=? WHERE username=?",(role,ts(),username))
        log_audit(conn,current_user()["username"],"MASTER_DATA","USER_ROLE_CHANGED",
                  f"Role changed for {username}.",username,old,{"role":role},reason)
        conn.commit(); flash("User role updated.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="master"))

@app.route("/admin/user/<username>/status", methods=["POST"])
@require_perm("ADMIN_USERS")
def change_user_status(username):
    conn=get_db(); f=request.form
    try:
        active=1 if f.get("active")=="1" else 0
        reason=require_reason()
        if username==current_user()["username"] and not active:
            raise ValueError("Administrator cannot deactivate the current account.")
        row=_user_row(conn,username)
        if not row: raise ValueError("User not found.")
        conn.execute("UPDATE users SET active=?,locked=0,changed_at=? WHERE username=?",
                     (active,ts(),username))
        log_audit(conn,current_user()["username"],"MASTER_DATA","USER_STATUS_CHANGED",
                  f"User {username} active={active}.",username,{"active":row["active"]},{"active":active},reason)
        conn.commit(); flash("User status updated.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="master"))

@app.route("/admin/room", methods=["POST"])
@require_perm("ADMIN_MASTER")
def admin_room():
    conn=get_db(); f=request.form
    try:
        rid=validate_id(f.get("room_id"),"room ID")
        name=f.get("room_name","").strip(); grade=f.get("grade","").strip()
        reason=require_reason()
        if not name or not grade: raise ValueError("Room name and grade are required.")
        conn.execute(
            """INSERT INTO rooms
            (room_id,site_id,room_name,grade,status,temp_min,temp_max,rh_min,rh_max,dp_min,
             last_sync,active,created_at,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid,SITE_ID,name,grade,"QUALIFIED",15,25,30,60,15,ts(),1,ts(),current_user()["username"])
        )
        conn.execute("INSERT INTO cleanroom_bms VALUES (?,?,?,?,?,?,?,?,?)",
                     (rid,SITE_ID,name,grade,21,42,20,"COMPLIANT",ts()))
        log_audit(conn,current_user()["username"],"MASTER_DATA","ROOM_CREATED",
                  f"Created room {rid} ({name}).",rid,reason=reason)
        conn.commit(); flash(f"Room {rid} created.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="master"))

@app.route("/admin/equipment", methods=["POST"])
@require_perm("ADMIN_MASTER")
def admin_equipment():
    conn=get_db(); f=request.form
    try:
        eid=validate_id(f.get("eq_id"),"equipment ID")
        name=f.get("name","").strip(); area=f.get("area","").strip()
        typ=f.get("eq_type","").strip(); cal=f.get("cal_due_date","").strip()
        reason=require_reason()
        if not all([name,area,typ,cal]): raise ValueError("All equipment fields are required.")
        if not conn.execute("SELECT 1 FROM rooms WHERE room_id=? AND active=1",(area,)).fetchone():
            raise ValueError("Equipment area must reference an active qualified room.")
        conn.execute(
            """INSERT INTO equipment
            (eq_id,site_id,name,area,status,last_cleaned,clean_valid_until,eq_type,
             cal_due_date,qualification_status,active,created_at,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (eid,SITE_ID,name,area,"OUT OF SERVICE",None,None,typ,cal,"QUALIFIED",1,ts(),current_user()["username"])
        )
        log_audit(conn,current_user()["username"],"MASTER_DATA","EQUIPMENT_CREATED",
                  f"Created equipment {eid}.",eid,reason=reason)
        conn.commit(); flash(f"Equipment {eid} created and held OUT OF SERVICE pending site release.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="master"))

# ---------------------------- MBR / RECIPE LIFECYCLE ----------------------------

@app.route("/mbr/create", methods=["POST"])
@require_perm("ADMIN_MASTER")
def create_mbr():
    conn=get_db(); f=request.form
    try:
        mid=validate_id(f.get("mbr_id"),"MBR ID")
        product=f.get("product_name","").strip(); size=f.get("batch_size","").strip()
        version=f.get("version","v1.0").strip()
        reason=require_reason()
        if not product or not size: raise ValueError("Product and batch size are required.")
        conn.execute(
            """INSERT INTO mbr_headers
            (mbr_id,site_id,product_name,batch_size,version,status,lifecycle_state,created_at,created_by)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (mid,SITE_ID,product,size,version,"DRAFT","DRAFT",ts(),current_user()["username"])
        )
        log_audit(conn,current_user()["username"],"MBR","MBR_CREATED",
                  f"Draft MBR {mid} created.",mid,reason=reason)
        conn.commit(); flash("MBR created in DRAFT; it cannot be executed until approved.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="mbr"))

@app.route("/mbr/step", methods=["POST"])
@require_perm("ADMIN_MASTER")
def add_mbr_step():
    conn=get_db(); f=request.form
    try:
        mid=validate_id(f.get("mbr_id"),"MBR ID")
        m=conn.execute("SELECT * FROM mbr_headers WHERE mbr_id=?",(mid,)).fetchone()
        if not m or m["lifecycle_state"]!="DRAFT":
            raise ValueError("Only DRAFT MBRs can be edited.")
        reason=require_reason()
        step=int(f.get("step_no")); phase=f.get("phase_type","").strip()
        name=f.get("phase_name","").strip(); instruction=f.get("instruction","").strip()
        minv=float(f.get("min_val")); maxv=float(f.get("max_val")); uom=f.get("uom","").strip()
        training=f.get("req_training","").strip()
        if minv>maxv: raise ValueError("Minimum cannot exceed maximum.")
        conn.execute(
            """INSERT INTO mbr_steps
            (mbr_id,site_id,step_no,phase_type,phase_name,instruction,min_val,max_val,uom,req_training)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (mid,SITE_ID,step,phase,name,instruction,minv,maxv,uom,training)
        )
        log_audit(conn,current_user()["username"],"MBR","MBR_STEP_ADDED",
                  f"Added step {step} to {mid}.",mid,reason=reason)
        conn.commit(); flash("MBR step added.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="mbr"))

@app.route("/mbr/submit", methods=["POST"])
@require_perm("ADMIN_MASTER")
def submit_mbr():
    conn=get_db(); f=request.form
    try:
        mid=f.get("mbr_id"); reason=require_reason()
        m=conn.execute("SELECT * FROM mbr_headers WHERE mbr_id=?",(mid,)).fetchone()
        count=conn.execute("SELECT COUNT(*) FROM mbr_steps WHERE mbr_id=?",(mid,)).fetchone()[0]
        if not m or m["lifecycle_state"]!="DRAFT" or count==0: raise ValueError("Draft MBR must exist and contain steps.")
        conn.execute("UPDATE mbr_headers SET lifecycle_state='PENDING_APPROVAL',status='PENDING_APPROVAL' WHERE mbr_id=?",(mid,))
        log_audit(conn,current_user()["username"],"MBR","MBR_SUBMITTED",
                  f"MBR {mid} submitted for independent approval.",mid,reason=reason)
        conn.commit(); flash("MBR submitted for independent QA approval.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="mbr"))

@app.route("/mbr/approve", methods=["POST"])
@require_perm("QA_REVIEW")
def approve_mbr():
    conn=get_db(); f=request.form
    try:
        mid=f.get("mbr_id"); reason=require_reason()
        pwd=f.get("password","")
        if current_user()["role"] in ("System Administrator","Master Data Administrator"):
            raise ValueError("MBR approval requires an independent QA role.")
        user,err=verify_esign(conn,pwd,allowed_roles=["QA Reviewer","QA Release"],permission="QA_REVIEW")
        if not user: raise ValueError(err)
        m=conn.execute("SELECT * FROM mbr_headers WHERE mbr_id=?",(mid,)).fetchone()
        if not m or m["lifecycle_state"]!="PENDING_APPROVAL": raise ValueError("MBR is not awaiting approval.")
        snap=dict(m); snap["approval"]="APPROVED"
        sig=record_signature(conn,user,"Approved MBR","MBR",mid,snap,reason)
        conn.execute(
            """UPDATE mbr_headers SET lifecycle_state='EFFECTIVE',status='APPROVED',
               effective_from=?,approved_at=?,approved_by=? WHERE mbr_id=?""",
            (today(),ts(),user["username"],mid)
        )
        log_audit(conn,user["username"],"MBR","MBR_APPROVED",
                  f"MBR {mid} approved; e-signature {sig}.",mid,reason=reason)
        conn.commit(); flash("MBR approved and effective.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="mbr"))

# ---------------------------- BATCH DISPATCH / EXECUTION ----------------------------

@app.route("/batch/create", methods=["POST"])
@require_perm("SUPERVISE")
def create_batch():
    conn=get_db(); f=request.form
    try:
        bid=validate_id(f.get("batch_id"),"batch ID")
        mid=validate_id(f.get("mbr_id"),"MBR ID")
        eqid=validate_id(f.get("eq_id"),"equipment ID")
        room=f.get("room_id","").strip()
        reason=require_reason()
        m=conn.execute("SELECT * FROM mbr_headers WHERE mbr_id=?",(mid,)).fetchone()
        eq=conn.execute("SELECT * FROM equipment WHERE eq_id=?",(eqid,)).fetchone()
        rm=conn.execute("SELECT * FROM rooms WHERE room_id=? AND active=1",(room,)).fetchone()
        bms=conn.execute("SELECT * FROM cleanroom_bms WHERE room_id=?",(room,)).fetchone()
        if not m or m["lifecycle_state"]!="EFFECTIVE": raise ValueError("Only an EFFECTIVE approved MBR may be dispatched.")
        if not eq or eq["status"]!="CLEAN" or eq["qualification_status"]!="QUALIFIED": raise ValueError("Equipment must be CLEAN and QUALIFIED.")
        if datetime.strptime(eq["cal_due_date"],"%Y-%m-%d").date() < datetime.utcnow().date(): raise ValueError("Equipment calibration is overdue.")
        if not rm or rm["status"]!="QUALIFIED": raise ValueError("Room is not qualified.")
        if not bms or bms["status"]!="COMPLIANT" or (now_utc()-datetime.strptime(bms["last_sync"],"%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds()>BMS_STALE_MIN*60:
            raise ValueError("Room environmental status is stale or non-compliant.")
        if conn.execute("SELECT 1 FROM batches WHERE batch_id=?",(bid,)).fetchone(): raise ValueError("Batch ID already exists.")
        conn.execute(
            """INSERT INTO batches
            (batch_id,site_id,sap_order_no,mbr_id,product_name,eq_id,packaging_line,room_id,status,created_at,created_by,started_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (bid,SITE_ID,f.get("sap_order_no",""),mid,m["product_name"],eqid,"",room,"IN PROGRESS",ts(),current_user()["username"],ts())
        )
        for i,s in enumerate(conn.execute("SELECT * FROM mbr_steps WHERE mbr_id=? ORDER BY step_no",(mid,)).fetchall()):
            conn.execute(
                """INSERT INTO batch_steps
                (batch_id,site_id,step_no,phase_type,phase_name,instruction,min_val,max_val,uom,status,req_training)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (bid,SITE_ID,s["step_no"],s["phase_type"],s["phase_name"],s["instruction"],
                 s["min_val"],s["max_val"],s["uom"],"READY" if i==0 else "LOCKED",s["req_training"])
            )
        conn.execute("UPDATE equipment SET status='IN USE' WHERE eq_id=?",(eqid,))
        log_audit(conn,current_user()["username"],"BATCH","BATCH_CREATED",
                  f"Batch {bid} dispatched against effective MBR {mid}.",bid,reason=reason)
        conn.commit(); flash(f"Batch {bid} created and released to execution.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="batch",batch_id=f.get("batch_id","")))

@app.route("/batch/step", methods=["POST"])
@require_perm("EXECUTE")
def execute_step():
    conn=get_db(); f=request.form
    try:
        batch_id=f.get("batch_id"); step_id=int(f.get("step_id"))
        step=conn.execute("SELECT * FROM batch_steps WHERE id=? AND batch_id=?",(step_id,batch_id)).fetchone()
        if not step: raise ValueError("Step not found.")
        if step["status"]!="READY": raise ValueError("Only READY steps may be executed.")
        val=float(f.get("actual_val"))
        reason=f.get("reason","").strip()
        if not reason: reason="Normal execution"
        user,err=verify_esign(conn,f.get("password"),qualification=step["req_training"],permission="EXECUTE")
        if not user: raise ValueError(err)
        ok=step["min_val"]<=val<=step["max_val"]
        status="COMPLETED" if ok else "DEVIATION"
        conn.execute(
            """UPDATE batch_steps SET actual_val=?,status=?,performed_by=?,timestamp=?,
               executed_at=?,executed_reason=? WHERE id=?""",
            (val,status,user["username"],ts(),ts(),reason,step_id)
        )
        if ok:
            nxt=conn.execute(
                """SELECT id FROM batch_steps WHERE batch_id=? AND step_no>? AND status='LOCKED'
                   ORDER BY step_no LIMIT 1""",(batch_id,step["step_no"])
            ).fetchone()
            if nxt: conn.execute("UPDATE batch_steps SET status='READY' WHERE id=?",(nxt["id"],))
        else:
            did=f"DEV-{now_utc().strftime('%Y%m%d%H%M%S')}"
            conn.execute(
                """INSERT INTO deviations
                (deviation_id,batch_id,module,description,status,initiated_by,initiated_at)
                VALUES (?,?,?,?,?,?,?)""",
                (did,batch_id,"EBR",f"Step {step['step_no']} out of range: {val} {step['uom']}",
                 "OPEN",user["username"],ts())
            )
        log_audit(conn,user["username"],"EBR","STEP_EXECUTED",
                  f"Step {step['step_no']} recorded as {status}.",batch_id,
                  new={"value":val,"status":status},reason=reason)
        recompute_status(conn,batch_id)
        conn.commit(); flash(f"Step recorded: {status}.","success" if ok else "danger")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="batch",batch_id=f.get("batch_id","")))

# ---------------------------- DISPENSING / INVENTORY ----------------------------

@app.route("/dispense/create", methods=["POST"])
@require_perm("DISPENSE")
def dispense_create():
    conn=get_db(); f=request.form
    try:
        batch_id=f.get("batch_id"); lot=f.get("lot_no"); scale=f.get("scale_id"); room=f.get("room_id")
        target=float(f.get("target_qty")); actual=float(f.get("actual_qty")); tare=float(f.get("tare_weight"))
        tol_min=float(f.get("tol_min")); tol_max=float(f.get("tol_max"))
        reason=require_reason()
        if target<=0 or actual<=0 or tare<0 or tol_min>tol_max: raise ValueError("Invalid quantity/tolerance.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["Dispensing Operator","Supervisor"],qualification="SOP-WD-01",permission="DISPENSE")
        if not user: raise ValueError(err)
        mat=conn.execute("SELECT * FROM materials WHERE lot_no=?",(lot,)).fetchone()
        rm=conn.execute("SELECT * FROM rooms WHERE room_id=? AND active=1",(room,)).fetchone()
        eq=conn.execute("SELECT * FROM equipment WHERE eq_id=?",(scale,)).fetchone()
        if not mat or mat["qc_status"]!="RELEASED": raise ValueError("Material lot is not RELEASED.")
        if datetime.strptime(mat["expiry_date"],"%Y-%m-%d").date() < datetime.utcnow().date(): raise ValueError("Material lot is expired.")
        if not rm or rm["status"]!="QUALIFIED": raise ValueError("Dispensing room is not qualified.")
        if not eq or eq["eq_type"]!="WEIGH" or eq["status"]!="CLEAN": raise ValueError("Balance must be qualified and CLEAN.")
        if datetime.strptime(eq["cal_due_date"],"%Y-%m-%d").date() < datetime.utcnow().date(): raise ValueError("Balance calibration is overdue.")
        if mat["qty_available"] < actual: raise ValueError("Insufficient inventory; negative inventory is prohibited.")
        if not (tol_min <= actual <= tol_max): raise ValueError("Actual quantity outside approved dispense tolerance.")
        did=f"DSP-{now_utc().strftime('%Y%m%d%H%M%S%f')}"
        barcode=f"(01)08901001000010(10){lot}(21){did}"
        balance=round(mat["qty_available"]-actual,6)
        conn.execute(
            """INSERT INTO weigh_dispense_records
            (dispense_id,site_id,batch_id,lot_no,mat_name,target_qty,actual_qty,tare_weight,
             scale_id,room_id,uom,performed_by,timestamp,barcode_label,status,tolerance_min,tolerance_max)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (did,SITE_ID,batch_id,lot,mat["mat_name"],target,actual,tare,scale,room,"kg",
             user["username"],ts(),barcode,"PENDING_VERIFICATION",tol_min,tol_max)
        )
        conn.execute("UPDATE materials SET qty_available=? WHERE lot_no=?",(balance,lot))
        conn.execute(
            """INSERT INTO inventory_transactions
            (lot_no,batch_id,tx_type,qty,uom,balance_after,performed_by,timestamp,reason,source_ref)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (lot,batch_id,"ISSUE",-actual,"kg",balance,user["username"],ts(),reason,did)
        )
        conn.execute(
            """INSERT INTO genealogy
            (site_id,parent_type,parent_id,child_type,child_id,relation,qty,uom,timestamp,performed_by)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (SITE_ID,"MATERIAL_LOT",lot,"BATCH",batch_id,"CONSUMED",actual,"kg",ts(),user["username"])
        )
        log_audit(conn,user["username"],"DISPENSING","DISPENSE_RECORDED",
                  f"Dispensed {actual} kg from {lot}; balance {balance} kg.",did,reason=reason)
        conn.commit(); flash(f"Dispense {did} recorded; second-person verification required.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="dispense",batch_id=f.get("batch_id","")))

@app.route("/dispense/verify", methods=["POST"])
@require_perm("SUPERVISE")
def dispense_verify():
    conn=get_db(); f=request.form
    try:
        did=f.get("dispense_id")
        rec=conn.execute("SELECT * FROM weigh_dispense_records WHERE dispense_id=?",(did,)).fetchone()
        if not rec: raise ValueError("Dispense record not found.")
        if rec["performed_by"]==current_user()["username"]: raise ValueError("Independent verification requires a different user.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["Supervisor","QA Reviewer","QA Release"],permission="SUPERVISE")
        if not user: raise ValueError(err)
        reason=require_reason()
        conn.execute("UPDATE weigh_dispense_records SET verified_by=?,status='VERIFIED' WHERE dispense_id=?",
                     (user["username"],did))
        log_audit(conn,user["username"],"DISPENSING","DISPENSE_VERIFIED",
                  f"Independent verification completed for {did}.",did,reason=reason)
        recompute_status(conn,rec["batch_id"])
        conn.commit(); flash("Dispense independently verified.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="dispense",batch_id=f.get("batch_id","")))

# ---------------------------- PACKAGING ----------------------------

@app.route("/packaging/create", methods=["POST"])
@require_perm("PACKAGE")
def packaging_create():
    conn=get_db(); f=request.form
    try:
        bid=f.get("batch_id"); line=validate_id(f.get("line_id"),"line ID")
        target=int(f.get("target_units")); reason=require_reason()
        if target<=0: raise ValueError("Target units must be positive.")
        user,err=verify_esign(conn,f.get("password"),qualification="SOP-PKG-03",permission="PACKAGE")
        if not user: raise ValueError(err)
        eq=conn.execute("SELECT * FROM equipment WHERE eq_id=? AND eq_type='PACK' AND active=1",(line,)).fetchone()
        if not eq or eq["status"]!="CLEAN": raise ValueError("Packaging line must be CLEAN.")
        pack=f"PKG-{now_utc().strftime('%Y%m%d%H%M%S%f')}"
        conn.execute(
            """INSERT INTO packaging_runs
            (pack_run_id,site_id,batch_id,line_id,line_clearance_by,target_units,status,started_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (pack,SITE_ID,bid,line,user["username"],target,"IN PROGRESS",ts())
        )
        log_audit(conn,user["username"],"PACKAGING","PACK_RUN_STARTED",
                  f"Packaging run {pack} started with line clearance by {user['username']}.",pack,reason=reason)
        conn.commit(); flash(f"Packaging run {pack} started.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="packaging",batch_id=f.get("batch_id","")))

@app.route("/packaging/complete", methods=["POST"])
@require_perm("PACKAGE")
def packaging_complete():
    conn=get_db(); f=request.form
    try:
        pack=f.get("pack_run_id"); packed=int(f.get("packed_units")); rejected=int(f.get("units_rejected",0))
        reason=require_reason()
        row=conn.execute("SELECT * FROM packaging_runs WHERE pack_run_id=?",(pack,)).fetchone()
        if not row: raise ValueError("Packaging run not found.")
        if packed<0 or rejected<0 or packed+rejected>row["target_units"]: raise ValueError("Invalid packaging quantities.")
        user,err=verify_esign(conn,f.get("password"),qualification="SOP-PKG-03",permission="PACKAGE")
        if not user: raise ValueError(err)
        conn.execute(
            """UPDATE packaging_runs SET packed_units=?,units_rejected=?,status='COMPLETED',completed_at=?
               WHERE pack_run_id=?""",
            (packed,rejected,ts(),pack)
        )
        log_audit(conn,user["username"],"PACKAGING","PACK_RUN_COMPLETED",
                  f"Packaging run {pack}: packed={packed}, rejected={rejected}.",pack,reason=reason)
        conn.commit(); flash("Packaging run completed.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="packaging",batch_id=f.get("batch_id","")))

# ---------------------------- QC / SAMPLING ----------------------------

@app.route("/quality/sample", methods=["POST"])
@require_perm("QC")
def record_sample():
    conn=get_db(); f=request.form
    try:
        sid=validate_id(f.get("sample_id"),"sample ID"); bid=f.get("batch_id")
        test=f.get("test_name","").strip(); point=f.get("sample_point","").strip()
        val=float(f.get("result_val")); smin=float(f.get("spec_min")); smax=float(f.get("spec_max"))
        reason=require_reason()
        if not test or smin>smax: raise ValueError("Test and valid specification limits are required.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["QC Analyst","QA Reviewer","QA Release"],permission="QC")
        if not user: raise ValueError(err)
        status="PASSED" if smin<=val<=smax else "OOS (DEVIATION)"
        conn.execute(
            """INSERT INTO samples
            (sample_id,site_id,batch_id,sample_point,test_name,spec_min,spec_max,result_val,status,analyst,sampled_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (sid,SITE_ID,bid,point,test,smin,smax,val,status,user["username"],ts())
        )
        if status.startswith("OOS"):
            dev=f"DEV-{now_utc().strftime('%Y%m%d%H%M%S%f')}"
            conn.execute(
                """INSERT INTO deviations
                (deviation_id,batch_id,module,description,status,initiated_by,initiated_at)
                VALUES (?,?,?,?,?,?,?)""",
                (dev,bid,"QC",f"OOS result for {test}: {val} [{smin}-{smax}]",
                 "OPEN",user["username"],ts())
            )
        log_audit(conn,user["username"],"QC","SAMPLE_RECORDED",
                  f"{sid}: {test}={val}, {status}.",sid,reason=reason)
        recompute_status(conn,bid)
        conn.commit(); flash(f"Sample recorded: {status}.","success" if status=="PASSED" else "danger")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="quality",batch_id=f.get("batch_id","")))

# ---------------------------- EQUIPMENT / ROOMS ----------------------------

@app.route("/equipment/clean", methods=["POST"])
@require_perm("ENGINEERING")
def clean_equipment():
    conn=get_db(); f=request.form
    try:
        eid=f.get("eq_id"); agent=f.get("agent","").strip(); reason=require_reason()
        if not agent: raise ValueError("Cleaning agent/procedure reference is required.")
        eq=conn.execute("SELECT * FROM equipment WHERE eq_id=?",(eid,)).fetchone()
        if not eq: raise ValueError("Equipment not found.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["Engineering","Supervisor","QA Release"],permission="ENGINEERING")
        if not user: raise ValueError(err)
        until=(now_utc()+timedelta(hours=CLEAN_HOLD_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("UPDATE equipment SET status='CLEAN',last_cleaned=?,clean_valid_until=? WHERE eq_id=?",
                     (ts(),until,eid))
        conn.execute(
            """INSERT INTO equipment_logbook
            (eq_id,site_id,event_type,details,performed_by,timestamp,reason)
            VALUES (?,?,?,?,?,?,?)""",
            (eid,SITE_ID,"CLEANING",f"Cleaning completed using {agent}. Valid until {until}.",
             user["username"],ts(),reason)
        )
        log_audit(conn,user["username"],"EQUIPMENT","CLEANING_COMPLETED",
                  f"Equipment {eid} cleaned.",eid,reason=reason)
        conn.commit(); flash("Equipment returned to CLEAN status.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="equipment"))

@app.route("/equipment/status", methods=["POST"])
@require_perm("ENGINEERING")
def equipment_status():
    conn=get_db(); f=request.form
    try:
        eid=f.get("eq_id"); status=f.get("status"); reason=require_reason()
        allowed={"CLEAN","DIRTY","MAINTENANCE","OUT OF SERVICE","IN USE"}
        if status not in allowed: raise ValueError("Invalid equipment status.")
        row=conn.execute("SELECT * FROM equipment WHERE eq_id=?",(eid,)).fetchone()
        if not row: raise ValueError("Equipment not found.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["Engineering","Supervisor"],permission="ENGINEERING")
        if not user: raise ValueError(err)
        conn.execute("UPDATE equipment SET status=? WHERE eq_id=?",(status,eid))
        conn.execute(
            """INSERT INTO equipment_logbook
            (eq_id,site_id,event_type,details,performed_by,timestamp,reason)
            VALUES (?,?,?,?,?,?,?)""",
            (eid,SITE_ID,"STATUS_CHANGE",f"Status {row['status']} -> {status}.",user["username"],ts(),reason)
        )
        log_audit(conn,user["username"],"EQUIPMENT","STATUS_CHANGED",
                  f"{eid}: {row['status']} -> {status}.",eid,
                  old={"status":row["status"]},new={"status":status},reason=reason)
        conn.commit(); flash("Equipment status updated.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="equipment"))

# ---------------------------- PERSONNEL / TRAINING ----------------------------

@app.route("/training/qualify", methods=["POST"])
@require_perm("ADMIN_USERS")
def qualify_training():
    conn=get_db(); f=request.form
    try:
        username=f.get("username"); course=f.get("course_code"); valid=f.get("valid_until")
        reason=require_reason()
        if course not in TRAIN: raise ValueError("Unknown training course.")
        if not _user_row(conn,username): raise ValueError("User not found.")
        datetime.strptime(valid,"%Y-%m-%d")
        conn.execute(
            """INSERT INTO user_training
            (username,course_code,course_name,status,valid_until,qualified_by,qualified_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(username,course_code) DO UPDATE SET
            status=excluded.status,valid_until=excluded.valid_until,
            qualified_by=excluded.qualified_by,qualified_at=excluded.qualified_at""",
            (username,course,TRAIN[course],"QUALIFIED",valid,current_user()["username"],ts())
        )
        log_audit(conn,current_user()["username"],"TRAINING","QUALIFICATION_UPDATED",
                  f"{username} qualified for {course} until {valid}.",username,reason=reason)
        conn.commit(); flash("Training qualification updated.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="training"))

# ---------------------------- REVIEW BY EXCEPTION / RELEASE ----------------------------

@app.route("/qa/review", methods=["POST"])
@require_perm("QA_REVIEW")
def qa_review():
    conn=get_db(); f=request.form
    try:
        bid=f.get("batch_id"); reason=require_reason()
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["QA Reviewer","QA Release"],qualification="SOP-QA-05",permission="QA_REVIEW")
        if not user: raise ValueError(err)
        b=conn.execute("SELECT * FROM batches WHERE batch_id=?",(bid,)).fetchone()
        if not b: raise ValueError("Batch not found.")
        open_dev=conn.execute("SELECT COUNT(*) FROM deviations WHERE batch_id=? AND status!='CLOSED'",(bid,)).fetchone()[0]
        open_oos=conn.execute("SELECT COUNT(*) FROM samples WHERE batch_id=? AND status LIKE 'OOS%' AND oos_closed=0",(bid,)).fetchone()[0]
        pending=conn.execute("SELECT COUNT(*) FROM weigh_dispense_records WHERE batch_id=? AND status!='VERIFIED'",(bid,)).fetchone()[0]
        incomplete=conn.execute("SELECT COUNT(*) FROM batch_steps WHERE batch_id=? AND status NOT LIKE 'COMPLETED%'",(bid,)).fetchone()[0]
        comments=f.get("comments","").strip()
        disposition="ACCEPTED" if not any([open_dev,open_oos,pending,incomplete]) else "EXCEPTION"
        conn.execute(
            """INSERT INTO review_events
            (batch_id,exception_type,reference_id,disposition,reviewed_by,reviewed_at,comments)
            VALUES (?,?,?,?,?,?,?)""",
            (bid,"RBE","BATCH",disposition,user["username"],ts(),comments)
        )
        snap=dict(b); snap["review_disposition"]=disposition
        sig=record_signature(conn,user,"Batch record reviewed by exception","BATCH",bid,snap,reason)
        log_audit(conn,user["username"],"QA_RBE","BATCH_REVIEWED",
                  f"Batch {bid} RbE disposition={disposition}; signature {sig}.",bid,reason=reason)
        conn.commit(); flash(f"Batch review completed: {disposition}.","success" if disposition=="ACCEPTED" else "warning")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="rbe",batch_id=f.get("batch_id","")))

@app.route("/qa/release", methods=["POST"])
@require_perm("QA_RELEASE")
def qa_release():
    conn=get_db(); f=request.form
    try:
        bid=f.get("batch_id"); decision=f.get("decision"); reason=require_reason()
        if decision not in ("RELEASED_COMMERCIAL","REJECTED_QUARANTINE"):
            raise ValueError("Invalid final disposition.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["QA Release"],qualification="SOP-QA-05",permission="QA_RELEASE")
        if not user: raise ValueError(err)
        b=conn.execute("SELECT * FROM batches WHERE batch_id=?",(bid,)).fetchone()
        if not b: raise ValueError("Batch not found.")
        if decision=="RELEASED_COMMERCIAL":
            if recompute_status(conn,bid)!="READY FOR QA RELEASE": raise ValueError("Batch is not eligible for release.")
            review=conn.execute(
                """SELECT 1 FROM review_events WHERE batch_id=? AND disposition='ACCEPTED'
                   ORDER BY id DESC LIMIT 1""",(bid,)
            ).fetchone()
            if not review: raise ValueError("Independent QA review-by-exception must be completed before release.")
        snap=dict(b); snap["decision"]=decision
        sig=record_signature(conn,user,"Final QA batch disposition","BATCH",bid,snap,reason)
        conn.execute("UPDATE batches SET status=?,qa_disposition_by=?,completed_at=? WHERE batch_id=?",
                     (decision,user["username"],ts(),bid))
        if b["eq_id"]:
            conn.execute("UPDATE equipment SET status='DIRTY' WHERE eq_id=?",(b["eq_id"],))
        log_audit(conn,user["username"],"QA_RELEASE","BATCH_DISPOSITION",
                  f"Batch {bid} disposition={decision}; signature {sig}.",bid,reason=reason,severity="IMPORTANT")
        conn.commit(); flash(f"Final batch disposition recorded: {decision}.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="rbe",batch_id=f.get("batch_id","")))

# ---------------------------- DEVIATION / CAPA ----------------------------

@app.route("/deviation/close", methods=["POST"])
@require_perm("QA_REVIEW")
def deviation_close():
    conn=get_db(); f=request.form
    try:
        did=f.get("deviation_id"); capa=f.get("capa","").strip(); investigation=f.get("investigation","").strip()
        reason=require_reason()
        if len(capa)<5 or len(investigation)<5: raise ValueError("Investigation and CAPA are required.")
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["QA Reviewer","QA Release"],qualification="SOP-QA-05",permission="QA_REVIEW")
        if not user: raise ValueError(err)
        row=conn.execute("SELECT * FROM deviations WHERE deviation_id=?",(did,)).fetchone()
        if not row or row["status"]=="CLOSED": raise ValueError("Deviation is not open.")
        conn.execute(
            """UPDATE deviations SET status='CLOSED',investigation=?,capa=?,closed_by=?,closed_at=?
               WHERE deviation_id=?""",
            (investigation,capa,user["username"],ts(),did)
        )
        log_audit(conn,user["username"],"DEVIATION","DEVIATION_CLOSED",
                  f"Deviation {did} closed with documented investigation/CAPA.",did,reason=reason,severity="IMPORTANT")
        if row["batch_id"]: recompute_status(conn,row["batch_id"])
        conn.commit(); flash("Deviation/CAPA closed.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="deviation"))

# ---------------------------- CHANGE CONTROL ----------------------------

@app.route("/change/create", methods=["POST"])
@require_perm("ADMIN_MASTER")
def change_create():
    conn=get_db(); f=request.form
    try:
        cid=validate_id(f.get("change_id"),"change ID")
        obj=f.get("object_type","").strip(); oid=f.get("object_id","").strip()
        desc=f.get("description","").strip(); impact=f.get("impact","").strip()
        reason=require_reason()
        if not desc or not impact: raise ValueError("Description and impact assessment are required.")
        conn.execute(
            """INSERT INTO change_control
            (change_id,object_type,object_id,description,impact,status,requested_by,requested_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (cid,obj,oid,desc,impact,"OPEN",current_user()["username"],ts())
        )
        log_audit(conn,current_user()["username"],"CHANGE_CONTROL","CHANGE_CREATED",
                  f"Change {cid} opened for {obj}/{oid}.",cid,reason=reason)
        conn.commit(); flash("Change control opened.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="change"))

@app.route("/change/approve", methods=["POST"])
@require_perm("QA_REVIEW")
def change_approve():
    conn=get_db(); f=request.form
    try:
        cid=f.get("change_id"); reason=require_reason()
        user,err=verify_esign(conn,f.get("password"),allowed_roles=["QA Reviewer","QA Release"],permission="QA_REVIEW")
        if not user: raise ValueError(err)
        row=conn.execute("SELECT * FROM change_control WHERE change_id=?",(cid,)).fetchone()
        if not row or row["status"]!="OPEN": raise ValueError("Change is not open.")
        conn.execute("UPDATE change_control SET status='APPROVED',approved_by=?,approved_at=? WHERE change_id=?",
                     (user["username"],ts(),cid))
        log_audit(conn,user["username"],"CHANGE_CONTROL","CHANGE_APPROVED",
                  f"Change {cid} approved.",cid,reason=reason,severity="IMPORTANT")
        conn.commit(); flash("Change approved for controlled implementation.","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="change"))

# ---------------------------- GENEALOGY ----------------------------

@app.route("/genealogy/<batch_id>")
@require_perm("VIEW_ALL")
def genealogy(batch_id):
    conn=get_db()
    rows=conn.execute(
        """SELECT * FROM genealogy WHERE parent_id=? OR child_id=? ORDER BY timestamp""",
        (batch_id,batch_id)
    ).fetchall()
    return render_template_string(GENEALOGY_UI,batch_id=batch_id,rows=rows,user=current_user(),version=APP_VERSION)

# ---------------------------- AUDIT INTEGRITY / EXPORT ----------------------------

def verify_audit_chain(conn):
    rows=conn.execute("SELECT * FROM audit_trail ORDER BY id").fetchall()
    prev="GENESIS"; errors=[]
    for r in rows:
        expected=_hash(prev,r["timestamp"],r["username"],r["full_name"],r["role"],r["site_id"],
                       r["module"],r["action"],r["record_ref"],r["old_value"],r["new_value"],
                       r["reason"],r["details"],r["ip_address"],r["severity"])
        if r["prev_hash"]!=prev or r["record_hash"]!=expected:
            errors.append(r["id"])
        prev=r["record_hash"]
    return errors

@app.route("/audit/verify")
@require_perm("AUDIT_READ")
def audit_verify():
    conn=get_db()
    errors=verify_audit_chain(conn)
    u=current_user()
    log_audit(conn,u["username"],"AUDIT","AUDIT_CHAIN_VERIFIED",
              f"Audit chain verification completed; errors={len(errors)}.",
              severity="IMPORTANT" if errors else "INFO")
    conn.commit()
    return Response(
        json.dumps({"status":"PASS" if not errors else "FAIL","invalid_record_ids":errors,
                    "checked_at":ts()},indent=2),
        mimetype="application/json"
    )

@app.route("/audit/export")
@require_perm("AUDIT_READ")
def audit_export():
    conn=get_db()
    rows=conn.execute("SELECT * FROM audit_trail ORDER BY id").fetchall()
    out=io.StringIO()
    w=csv.writer(out)
    w.writerow(rows[0].keys() if rows else ["message"])
    for r in rows: w.writerow([r[k] for k in r.keys()])
    return Response(out.getvalue(),mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=audit_trail.csv"})

# ---------------------------- BACKUP / ARCHIVE ----------------------------

@app.route("/backup", methods=["POST"])
@require_perm("ADMIN_SECURITY")
def backup():
    conn=get_db(); f=request.form
    try:
        reason=require_reason()
        target=f.get("path","").strip() or f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
        # For safety, use SQLite's online backup API rather than copying a live WAL file.
        dest=sqlite3.connect(target)
        conn.backup(dest)
        dest.close()
        digest=hashlib.sha256(Path(target).read_bytes()).hexdigest()
        conn.execute(
            """INSERT INTO backup_events(timestamp,performed_by,file_path,sha256,result,details)
               VALUES (?,?,?,?,?,?)""",
            (ts(),current_user()["username"],os.path.abspath(target),digest,"SUCCESS",
             "SQLite online backup; SHA-256 recorded.")
        )
        log_audit(conn,current_user()["username"],"BACKUP","BACKUP_CREATED",
                  f"Backup created: {os.path.abspath(target)} SHA256={digest}.",
                  reason=reason,severity="IMPORTANT")
        conn.commit(); flash(f"Backup created: {target}","success")
    except Exception as e:
        conn.rollback(); flash(str(e),"danger")
    return redirect(url_for("index",tab="backup"))

# ---------------------------- UI ----------------------------

MAIN_UI = r"""
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pharma MES {{ version }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<style>
body{background:#f4f6f9;font-size:.88rem}.top{background:#002b5c;color:#fff;padding:12px 20px}
.nav-link{margin:2px;background:#e9eef5;border-radius:5px;font-weight:600}.nav-link.active{background:#002b5c;color:#fff}
.card{border:0;box-shadow:0 1px 5px rgba(0,0,0,.08)}.smallx{font-size:.78rem}.mono{font-family:Consolas,monospace}
.badge-soft{background:#eef2f7;color:#243447}.sticky{position:sticky;top:10px}

 .pasx-cross-grid{display:grid;grid-template-columns:90px repeat(7,minmax(110px,1fr));gap:8px;align-items:stretch;overflow-x:auto}
 .pasx-axis-lbl{display:flex;align-items:center;justify-content:flex-end;padding-right:8px;font-weight:700;color:#516173}
 .pasx-box{min-height:82px;border-radius:8px;border:2px solid #9aa8b6;background:#e9eef5;color:#17324d;text-decoration:none;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;font-weight:700;padding:8px;transition:.15s}
 .pasx-box:hover{transform:translateY(-1px);box-shadow:0 3px 10px rgba(0,0,0,.12)}
 .state-pending{background:#eef2f7!important;border-color:#aab6c2!important;color:#516173!important}
 .state-active{background:#fff3cd!important;border-color:#ff9900!important;color:#856404!important;box-shadow:0 0 10px rgba(255,153,0,.25)}
 .state-completed{background:#d1e7dd!important;border-color:#198754!important;color:#0f5132!important}
 .state-deviation{background:#f8d7da!important;border-color:#dc3545!important;color:#842029!important}
 .execution-current{border-left:5px solid #ff9900!important;background:#fff8e1!important}
 .execution-done{background:#f1f8f4!important}
 .execution-deviation{background:#fff0f0!important}
</style></head><body>
<header class="top d-flex justify-content-between align-items-center flex-wrap gap-2">
 <div><b><i class="bi bi-cpu"></i> Pharma MES Enterprise Suite</b>
 <span class="badge bg-warning text-dark ms-2">SITE 102 • OSD</span>
 <span class="badge bg-info text-dark ms-1">Compliance Controls v11 • Execution Flow</span></div>
 <div>{{ user.full_name }} <b>({{ user.role }})</b> • {{ now }} UTC
 <a class="btn btn-sm btn-danger ms-2" href="/logout">Sign out</a></div>
</header>
<div class="container-fluid p-3">
{% with messages=get_flashed_messages(with_categories=true) %}{% for cat,msg in messages %}
<div class="alert alert-{{cat}} py-2">{{msg}}</div>{% endfor %}{% endwith %}
<ul class="nav nav-pills flex-wrap mb-3">
{% for key,label,icon in nav %}<li class="nav-item"><a class="nav-link {{'active' if tab==key else ''}}" href="/?tab={{key}}"><i class="bi {{icon}}"></i> {{label}}</a></li>{% endfor %}
</ul>

{% if tab=='process_flow' %}
<div class="card p-3 mb-3">
 <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">
  <h5 class="mb-0"><i class="bi bi-grid-3x3-gap-fill"></i> Functional Architecture & Process Flow</h5>
  <div class="small"><span class="badge bg-warning text-dark">In Execution</span> <span class="badge bg-success">Completed</span> <span class="badge bg-danger">Deviation / OOS</span> <span class="badge bg-secondary">Standby</span></div>
 </div>
 <div class="pasx-cross-grid">
  <div class="pasx-axis-lbl" style="grid-column:1;grid-row:1">Specification</div>
  <a href="/?tab=mbr" class="pasx-box state-{{flow_state['spec_ims']}}" style="grid-column:4;grid-row:1">Process Development<br>IMS Manufacturing</a>
  <a href="/?tab=mbr" class="pasx-box state-{{flow_state['spec_mbr']}}" style="grid-column:5;grid-row:1">Master Batch<br>Record</a>
  <div class="pasx-axis-lbl" style="grid-column:1;grid-row:2">Execution</div>
  <a href="/?tab=batch{% if active_batch %}&batch_id={{active_batch.batch_id}}{% endif %}" class="pasx-box state-{{flow_state['sched']}}" style="grid-column:2;grid-row:2">Finite<br>Scheduling<br><span class="badge bg-success mt-1">DISPATCH</span></a>
  <a href="/?tab=dispense{% if active_batch %}&batch_id={{active_batch.batch_id}}{% endif %}" class="pasx-box state-{{flow_state['dispense']}}" style="grid-column:3;grid-row:2">Weighing &amp;<br>Dispensing</a>
  <a href="/?tab=batch{% if active_batch %}&batch_id={{active_batch.batch_id}}{% endif %}" class="pasx-box state-{{flow_state['ebr']}}" style="grid-column:4;grid-row:2">Electronic Batch<br>Recording</a>
  <a href="/?tab=equipment" class="pasx-box state-{{flow_state['equip']}}" style="grid-column:5;grid-row:2">Equipment<br>Management</a>
  <a href="/?tab=inventory" class="pasx-box state-{{flow_state['mat_flow']}}" style="grid-column:6;grid-row:2">Material Flow<br>&amp; Inventory</a>
  <a href="/?tab=inventory" class="pasx-box state-{{flow_state['wh']}}" style="grid-column:7;grid-row:2">Warehouse<br>Management</a>
  <div class="pasx-axis-lbl" style="grid-column:1;grid-row:3">Compliance</div>
  <a href="/?tab=quality{% if active_batch %}&batch_id={{active_batch.batch_id}}{% endif %}" class="pasx-box state-{{flow_state['lims']}}" style="grid-column:4;grid-row:3">Process Quality<br>Control / QC</a>
  <a href="/?tab=packaging{% if active_batch %}&batch_id={{active_batch.batch_id}}{% endif %}" class="pasx-box state-{{flow_state['packaging']}}" style="grid-column:5;grid-row:3">Packaging &amp;<br>Track &amp; Trace</a>
  <a href="/?tab=rbe{% if active_batch %}&batch_id={{active_batch.batch_id}}{% endif %}" class="pasx-box state-{{flow_state['tnt']}}" style="grid-column:6;grid-row:3">Review by<br>Exception</a>
  <div class="pasx-axis-lbl" style="grid-column:1;grid-row:4">Performance</div>
  <a href="/?tab=dashboard" class="pasx-box state-{{flow_state['perf']}}" style="grid-column:5;grid-row:4">Manufacturing<br>Intelligence</a>
 </div>
</div>
<div class="card p-3 mb-3">
 <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
  <h5 class="mb-0">Step-by-Step OSD Execution</h5>
  {% if active_batch %}<span class="badge bg-primary">Active Batch: {{active_batch.batch_id}}</span>{% else %}<span class="badge bg-secondary">No batch selected</span>{% endif %}
 </div>
 <p class="text-muted small mb-2">The execution sequence below is generated from the selected effective MBR. Future steps remain locked until the preceding step is completed.</p>
 {% if active_batch %}
 <div class="table-responsive"><table class="table table-sm table-bordered align-middle mb-0">
  <thead class="table-light"><tr><th>Step</th><th>Phase / Unit Operation</th><th>Controlled Instruction</th><th>Limit / Target</th><th>Actual</th><th>Status</th><th>Performed By</th><th>Executed At</th><th>E-Sign</th></tr></thead>
  <tbody>
  {% for s in steps %}
  <tr class="{% if s.status=='READY' %}execution-current{% elif s.status=='DEVIATION' %}execution-deviation{% elif s.status.startswith('COMPLETED') %}execution-done{% endif %}">
   <td class="fw-bold">{{s.step_no}}</td><td>{{s.phase_name}}<br><small class="text-muted">{{s.phase_type}}</small></td><td>{{s.instruction}}</td><td>{{s.min_val}} – {{s.max_val}} {{s.uom}}</td><td>{{s.actual_val if s.actual_val is not none else '—'}}</td><td><span class="badge {% if s.status=='READY' %}bg-warning text-dark{% elif s.status=='DEVIATION' %}bg-danger{% elif s.status.startswith('COMPLETED') %}bg-success{% else %}bg-secondary{% endif %}">{{s.status}}</span></td><td>{{s.performed_by or '—'}}</td><td>{{s.executed_at or s.timestamp or '—'}}</td><td>{% if s.status.startswith('COMPLETED') %}<span class="text-success fw-bold">✓ Signed</span>{% elif s.status=='READY' %}<span class="text-warning fw-bold">Pending</span>{% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
 </table></div>
 {% else %}<div class="alert alert-info mb-0">Select or create a batch from <b>Batch Execution</b> to display the complete controlled execution table.</div>{% endif %}
</div>
{% endif %}

{% if tab=='dashboard' %}
<div class="row g-3">
 <div class="col-md-3"><div class="card p-3"><div class="text-muted">Users</div><h3>{{users|length}}</h3></div></div>
 <div class="col-md-3"><div class="card p-3"><div class="text-muted">Batches</div><h3>{{batches|length}}</h3></div></div>
 <div class="col-md-3"><div class="card p-3"><div class="text-muted">Open deviations</div><h3>{{deviations|selectattr('status','equalto','OPEN')|list|length}}</h3></div></div>
 <div class="col-md-3"><div class="card p-3"><div class="text-muted">Effective MBRs</div><h3>{{mbrs|selectattr('lifecycle_state','equalto','EFFECTIVE')|list|length}}</h3></div></div>
</div>
<div class="card p-3 mt-3"><h5>Compliance control set</h5>
<ul class="mb-0">
<li>Individual user accounts, lockout and role-based authority.</li>
<li>Re-authenticated electronic signatures with signer, meaning, record hash and timestamp.</li>
<li>Append-only application audit events with chained hashes and verification endpoint.</li>
<li>Controlled MBR lifecycle: Draft → Pending Approval → Effective.</li>
<li>Independent QA review and release gates; no direct self-approval.</li>
<li>Training qualification checks, equipment/room status and calibration gates.</li>
<li>Material lot status, expiry and non-negative inventory controls.</li>
<li>Deviation/CAPA, change control, genealogy, backup and export controls.</li>
</ul></div>
{% endif %}

{% if tab=='master' %}
<div class="row g-3">
<div class="col-lg-6"><div class="card p-3"><h5>Admin — Add User</h5>
<form method="post" action="/admin/user"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<input class="form-control mb-2" name="username" placeholder="User ID" required>
<input class="form-control mb-2" name="full_name" placeholder="Full name" required>
<select class="form-select mb-2" name="role">{% for r in ['System Administrator','Master Data Administrator','Manufacturing Operator','Dispensing Operator','Packaging Operator','Supervisor','QA Reviewer','QA Release','QC Analyst','Engineering','Warehouse','Auditor'] %}<option>{{r}}</option>{% endfor %}</select>
<input class="form-control mb-2" type="password" name="password" placeholder="Initial password (min 8 chars)" required>
<input class="form-control mb-2" name="reason" placeholder="Reason / authorization reference" required>
<button class="btn btn-primary">Create user</button></form></div></div>
<div class="col-lg-6"><div class="card p-3"><h5>Admin — Add Room</h5>
<form method="post" action="/admin/room"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<div class="row g-2"><div class="col"><input class="form-control" name="room_id" placeholder="Room ID" required></div><div class="col"><input class="form-control" name="room_name" placeholder="Room name" required></div></div>
<input class="form-control my-2" name="grade" placeholder="Grade / classification" required>
<input class="form-control mb-2" name="reason" placeholder="Reason / qualification reference" required>
<button class="btn btn-primary">Create room</button></form></div>
<div class="card p-3 mt-3"><h5>Admin — Add Equipment</h5>
<form method="post" action="/admin/equipment"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<div class="row g-2"><div class="col"><input class="form-control" name="eq_id" placeholder="Equipment ID" required></div><div class="col"><input class="form-control" name="name" placeholder="Name" required></div></div>
<div class="row g-2 my-2"><div class="col"><input class="form-control" name="area" placeholder="Qualified room ID" required></div><div class="col"><input class="form-control" name="eq_type" placeholder="WEIGH / PROC / PACK" required></div></div>
<input class="form-control mb-2" type="date" name="cal_due_date" required><input class="form-control mb-2" name="reason" placeholder="Reason / qualification reference" required>
<button class="btn btn-primary">Create equipment</button></form></div></div></div>
<div class="card p-3 mt-3"><h5>Current Users</h5><table class="table table-sm"><tr><th>User</th><th>Name</th><th>Role</th><th>State</th></tr>{% for u in users %}<tr><td>{{u.username}}</td><td>{{u.full_name}}</td><td>{{u.role}}</td><td>{{'ACTIVE' if u.active else 'INACTIVE'}} / {{'LOCKED' if u.locked else 'UNLOCKED'}}</td></tr>{% endfor %}</table></div>
{% endif %}

{% if tab=='mbr' %}
<div class="row g-3"><div class="col-lg-5">
<div class="card p-3"><h5>Create Draft MBR</h5><form method="post" action="/mbr/create"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<input class="form-control mb-2" name="mbr_id" placeholder="MBR ID" required><input class="form-control mb-2" name="product_name" placeholder="Product" required>
<input class="form-control mb-2" name="batch_size" placeholder="Batch size" required><input class="form-control mb-2" name="version" value="v1.0">
<input class="form-control mb-2" name="reason" placeholder="Reason / change reference" required><button class="btn btn-primary">Create Draft</button></form></div>
<div class="card p-3 mt-3"><h5>Add MBR Step</h5><form method="post" action="/mbr/step"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<select class="form-select mb-2" name="mbr_id">{% for m in mbrs if m.lifecycle_state=='DRAFT' %}<option>{{m.mbr_id}}</option>{% endfor %}</select>
<input class="form-control mb-2" name="step_no" type="number" placeholder="Step" required><input class="form-control mb-2" name="phase_type" placeholder="DISPENSE / MANUFACTURING / QUALITY" required>
<input class="form-control mb-2" name="phase_name" placeholder="Phase name" required><textarea class="form-control mb-2" name="instruction" placeholder="Controlled instruction" required></textarea>
<div class="row g-2"><input class="col form-control" name="min_val" type="number" step="0.01" placeholder="Min" required><input class="col form-control" name="max_val" type="number" step="0.01" placeholder="Max" required><input class="col form-control" name="uom" placeholder="UOM" required></div>
<input class="form-control my-2" name="req_training" placeholder="Training code" required><input class="form-control mb-2" name="reason" placeholder="Reason" required>
<button class="btn btn-success">Add step</button></form></div></div>
<div class="col-lg-7"><div class="card p-3"><h5>MBR Lifecycle</h5><table class="table table-sm"><tr><th>ID</th><th>Product</th><th>Version</th><th>Lifecycle</th><th>Control</th></tr>
{% for m in mbrs %}<tr><td>{{m.mbr_id}}</td><td>{{m.product_name}}</td><td>{{m.version}}</td><td>{{m.lifecycle_state}}</td><td>
{% if m.lifecycle_state=='DRAFT' %}<form method="post" action="/mbr/submit" class="d-inline"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="mbr_id" value="{{m.mbr_id}}"><input type="hidden" name="reason" value="Submitted for independent approval"><button class="btn btn-sm btn-warning">Submit</button></form>{% endif %}
{% if m.lifecycle_state=='PENDING_APPROVAL' %}<form method="post" action="/mbr/approve"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="mbr_id" value="{{m.mbr_id}}"><input class="form-control form-control-sm mb-1" name="password" type="password" placeholder="QA password" required><input class="form-control form-control-sm mb-1" name="reason" placeholder="Approval reason" required><button class="btn btn-sm btn-success">QA Approve + eSign</button></form>{% endif %}</td></tr>{% endfor %}</table>
<h6>Effective MBR steps</h6><table class="table table-sm"><tr><th>MBR</th><th>Step</th><th>Phase</th><th>Range</th><th>Training</th></tr>{% for s in mbr_steps %}<tr><td>{{s.mbr_id}}</td><td>{{s.step_no}}</td><td>{{s.phase_name}}</td><td>{{s.min_val}}–{{s.max_val}} {{s.uom}}</td><td>{{s.req_training}}</td></tr>{% endfor %}</table></div></div></div>
{% endif %}

{% if tab=='batch' %}
<div class="row g-3">
 <div class="col-lg-4">
  <div class="card p-3"><h5>Dispatch Batch</h5>
   <form method="post" action="/batch/create"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
    <input class="form-control mb-2" name="batch_id" placeholder="Batch ID" required>
    <input class="form-control mb-2" name="sap_order_no" placeholder="ERP / SAP order reference">
    <select class="form-select mb-2" name="mbr_id">{% for m in mbrs if m.lifecycle_state=='EFFECTIVE' %}<option value="{{m.mbr_id}}">{{m.mbr_id}} — {{m.product_name}} / {{m.version}}</option>{% endfor %}</select>
    <select class="form-select mb-2" name="eq_id">{% for e in equipment if e.eq_type!='PACK' %}<option value="{{e.eq_id}}">{{e.eq_id}} — {{e.name}} [{{e.status}}]</option>{% endfor %}</select>
    <select class="form-select mb-2" name="room_id">{% for r in rooms %}<option value="{{r.room_id}}">{{r.room_id}} — {{r.room_name}} [{{r.status}}]</option>{% endfor %}</select>
    <input class="form-control mb-2" name="reason" placeholder="Dispatch authorization / reason" required>
    <button class="btn btn-primary w-100">Create / Dispatch Batch</button>
   </form>
  </div>
  <div class="card p-3 mt-3"><h6>Batch List</h6>{% for b in batches %}<div class="border rounded p-2 mb-1"><a href="/?tab=batch&batch_id={{b.batch_id}}"><b>{{b.batch_id}}</b></a><br><small>{{b.product_name}}</small> <span class="badge bg-secondary">{{b.status}}</span></div>{% endfor %}</div>
 </div>
 <div class="col-lg-8">
  {% if active_batch %}
  <div class="card p-3">
   <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2"><h5 class="mb-0">Electronic Batch Record — {{active_batch.batch_id}}</h5><span class="badge bg-primary">{{active_batch.status}}</span></div>
   <div class="row small mb-3"><div class="col-md-4"><b>Product:</b> {{active_batch.product_name}}</div><div class="col-md-4"><b>MBR:</b> {{active_batch.mbr_id}}</div><div class="col-md-4"><b>Room:</b> {{active_batch.room_id}}</div></div>
   <div class="table-responsive"><table class="table table-sm table-bordered align-middle">
    <thead class="table-light"><tr><th>Step</th><th>Phase / Unit Operation</th><th>Controlled Instruction</th><th>Bounds</th><th>Actual</th><th>Status</th><th>Performed By</th><th>Timestamp</th><th>Execution / E-Signature</th></tr></thead>
    <tbody>{% for s in steps %}
     <tr class="{% if s.status=='READY' %}execution-current{% elif s.status=='DEVIATION' %}execution-deviation{% elif s.status.startswith('COMPLETED') %}execution-done{% endif %}">
      <td class="fw-bold">{{s.step_no}}</td><td><b>{{s.phase_name}}</b><br><small>{{s.phase_type}}</small></td><td style="min-width:220px">{{s.instruction}}</td><td>{{s.min_val}} – {{s.max_val}} {{s.uom}}</td><td>{{s.actual_val if s.actual_val is not none else '—'}}</td><td><span class="badge {% if s.status=='READY' %}bg-warning text-dark{% elif s.status=='DEVIATION' %}bg-danger{% elif s.status.startswith('COMPLETED') %}bg-success{% else %}bg-secondary{% endif %}">{{s.status}}</span></td><td>{{s.performed_by or '—'}}</td><td>{{s.executed_at or s.timestamp or '—'}}</td>
      <td style="min-width:260px">{% if s.status=='READY' and active_batch.status=='IN PROGRESS' %}<form method="post" action="/batch/step"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="batch_id" value="{{active_batch.batch_id}}"><input type="hidden" name="step_id" value="{{s.id}}"><input class="form-control form-control-sm mb-1" name="actual_val" type="number" step="0.01" placeholder="Actual value" required><input class="form-control form-control-sm mb-1" name="password" type="password" placeholder="e-sign password" required><input class="form-control form-control-sm mb-1" name="reason" placeholder="Execution comment / reason" required><button class="btn btn-sm btn-success w-100">Execute Step + eSign</button></form>{% elif s.status.startswith('COMPLETED') %}<span class="text-success fw-bold">✓ Executed and electronically signed</span>{% elif s.status=='DEVIATION' %}<span class="text-danger fw-bold">Deviation / investigation required</span>{% else %}<span class="text-muted">LOCKED — previous step must be completed</span>{% endif %}</td>
     </tr>
    {% endfor %}</tbody>
  </table></div>
  </div>
  {% else %}<div class="card p-4"><h5>No batch selected</h5><p class="text-muted mb-0">Create or select a batch to open the full step-by-step electronic batch record.</p></div>{% endif %}
 </div>
</div>
{% endif %}

{% if tab=='dispense' %}
<div class="row g-3"><div class="col-lg-5"><div class="card p-3"><h5>Controlled Weigh / Dispense</h5><form method="post" action="/dispense/create"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<select class="form-select mb-2" name="batch_id">{% for b in batches %}<option>{{b.batch_id}}</option>{% endfor %}</select><select class="form-select mb-2" name="lot_no">{% for m in materials %}<option>{{m.lot_no}}</option>{% endfor %}</select>
<select class="form-select mb-2" name="scale_id">{% for e in equipment if e.eq_type=='WEIGH' %}<option>{{e.eq_id}}</option>{% endfor %}</select><select class="form-select mb-2" name="room_id">{% for r in rooms %}<option>{{r.room_id}}</option>{% endfor %}</select>
<div class="row g-2"><input class="col form-control" name="target_qty" type="number" step="0.001" placeholder="Target" required><input class="col form-control" name="actual_qty" type="number" step="0.001" placeholder="Actual" required></div>
<div class="row g-2 my-2"><input class="col form-control" name="tol_min" type="number" step="0.001" placeholder="Tolerance min" required><input class="col form-control" name="tol_max" type="number" step="0.001" placeholder="Tolerance max" required></div>
<input class="form-control mb-2" name="tare_weight" type="number" step="0.001" placeholder="Tare" required><input class="form-control mb-2" name="password" type="password" placeholder="Operator e-sign password" required><input class="form-control mb-2" name="reason" placeholder="Reason / dispense reference" required>
<button class="btn btn-primary">Record Dispense</button></form></div></div>
<div class="col-lg-7"><div class="card p-3"><h5>Dispensing Records</h5><table class="table table-sm"><tr><th>ID</th><th>Lot</th><th>Actual</th><th>Status</th><th>Verify</th></tr>{% for d in dispenses %}<tr><td>{{d.dispense_id}}</td><td>{{d.lot_no}}</td><td>{{d.actual_qty}} {{d.uom}}</td><td>{{d.status}}</td><td>{% if d.status!='VERIFIED' %}<form method="post" action="/dispense/verify"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="dispense_id" value="{{d.dispense_id}}"><input type="hidden" name="batch_id" value="{{d.batch_id}}"><input class="form-control form-control-sm mb-1" name="password" type="password" placeholder="Verifier password" required><input class="form-control form-control-sm mb-1" name="reason" placeholder="Verification reason" required><button class="btn btn-sm btn-warning">Verify</button></form>{% else %}{{d.verified_by}}{% endif %}</td></tr>{% endfor %}</table></div></div></div>
{% endif %}

{% if tab=='packaging' %}
<div class="row g-3"><div class="col-lg-5"><div class="card p-3"><h5>Start Packaging</h5><form method="post" action="/packaging/create"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<select class="form-select mb-2" name="batch_id">{% for b in batches %}<option>{{b.batch_id}}</option>{% endfor %}</select><select class="form-select mb-2" name="line_id">{% for e in equipment if e.eq_type=='PACK' %}<option>{{e.eq_id}}</option>{% endfor %}</select>
<input class="form-control mb-2" name="target_units" type="number" placeholder="Target units" required><input class="form-control mb-2" name="password" type="password" placeholder="Operator password" required><input class="form-control mb-2" name="reason" placeholder="Line clearance / packaging reason" required><button class="btn btn-primary">Start</button></form></div></div>
<div class="col-lg-7"><div class="card p-3"><h5>Packaging Runs</h5>{% for p in packaging %}<form class="border rounded p-2 mb-2" method="post" action="/packaging/complete"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="pack_run_id" value="{{p.pack_run_id}}"><input type="hidden" name="batch_id" value="{{p.batch_id}}"><b>{{p.pack_run_id}}</b> • {{p.status}} • target {{p.target_units}}<div class="row g-2 my-1"><input class="col form-control" name="packed_units" type="number" placeholder="Packed" required><input class="col form-control" name="units_rejected" type="number" placeholder="Rejected" value="0"></div><input class="form-control mb-1" name="password" type="password" placeholder="Password" required><input class="form-control mb-1" name="reason" placeholder="Completion reason" required><button class="btn btn-sm btn-success">Complete</button></form>{% endfor %}</div></div></div>
{% endif %}

{% if tab=='inventory' %}
<div class="card p-3"><h5>Material / Inventory</h5><table class="table table-sm"><tr><th>Lot</th><th>Material</th><th>Qty</th><th>Expiry</th><th>QC</th><th>Location</th></tr>{% for m in materials %}<tr><td>{{m.lot_no}}</td><td>{{m.mat_name}}</td><td>{{m.qty_available}} {{m.uom}}</td><td>{{m.expiry_date}}</td><td>{{m.qc_status}}</td><td>{{m.storage_location}}</td></tr>{% endfor %}</table></div>
{% endif %}

{% if tab=='quality' %}
<div class="row g-3"><div class="col-lg-5"><div class="card p-3"><h5>Sampling / QC Result</h5><form method="post" action="/quality/sample"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">
<select class="form-select mb-2" name="batch_id">{% for b in batches %}<option>{{b.batch_id}}</option>{% endfor %}</select><input class="form-control mb-2" name="sample_id" placeholder="Sample ID" required><input class="form-control mb-2" name="sample_point" placeholder="Sample point" required><input class="form-control mb-2" name="test_name" placeholder="Test" required>
<div class="row g-2"><input class="col form-control" name="spec_min" type="number" step="0.01" placeholder="Spec min" required><input class="col form-control" name="spec_max" type="number" step="0.01" placeholder="Spec max" required><input class="col form-control" name="result_val" type="number" step="0.01" placeholder="Result" required></div>
<input class="form-control my-2" name="password" type="password" placeholder="QC e-sign password" required><input class="form-control mb-2" name="reason" placeholder="Sampling/result reason" required><button class="btn btn-primary">Record Result</button></form></div></div>
<div class="col-lg-7"><div class="card p-3"><h5>QC Results</h5><table class="table table-sm"><tr><th>Sample</th><th>Batch</th><th>Test</th><th>Result</th><th>Status</th><th>Analyst</th></tr>{% for s in samples %}<tr><td>{{s.sample_id}}</td><td>{{s.batch_id}}</td><td>{{s.test_name}}</td><td>{{s.result_val}}</td><td>{{s.status}}</td><td>{{s.analyst}}</td></tr>{% endfor %}</table></div></div></div>
{% endif %}

{% if tab=='equipment' %}
<div class="card p-3"><h5>Equipment / Cleaning / Calibration</h5><table class="table table-sm"><tr><th>ID</th><th>Name</th><th>Area</th><th>Status</th><th>Clean valid</th><th>Calibration due</th></tr>{% for e in equipment %}<tr><td>{{e.eq_id}}</td><td>{{e.name}}</td><td>{{e.area}}</td><td>{{e.status}}</td><td>{{e.clean_valid_until or '-'}}</td><td>{{e.cal_due_date}}</td></tr>{% endfor %}</table>
{% for e in equipment %}<details class="mb-2"><summary>{{e.eq_id}} — status/cleaning action</summary><div class="row mt-2"><div class="col-md-6"><form method="post" action="/equipment/clean"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="eq_id" value="{{e.eq_id}}"><input class="form-control mb-1" name="agent" placeholder="Cleaning procedure / agent" required><input class="form-control mb-1" name="password" type="password" placeholder="Engineering password" required><input class="form-control mb-1" name="reason" placeholder="Cleaning reason" required><button class="btn btn-sm btn-success">Record Cleaning</button></form></div><div class="col-md-6"><form method="post" action="/equipment/status"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="eq_id" value="{{e.eq_id}}"><select class="form-select mb-1" name="status"><option>CLEAN</option><option>DIRTY</option><option>MAINTENANCE</option><option>OUT OF SERVICE</option><option>IN USE</option></select><input class="form-control mb-1" name="password" type="password" placeholder="Engineering password" required><input class="form-control mb-1" name="reason" placeholder="Status change reason" required><button class="btn btn-sm btn-warning">Change Status</button></form></div></div></details>{% endfor %}</div>
{% endif %}

{% if tab=='training' %}
<div class="card p-3"><h5>Personnel / Training</h5><form method="post" action="/training/qualify" class="row g-2 mb-3"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><select class="col form-select" name="username">{% for u in users %}<option>{{u.username}}</option>{% endfor %}</select><select class="col form-select" name="course_code">{% for k in ['SOP-WD-01','SOP-MFG-02','SOP-TAB-03','SOP-EBR-09','SOP-QA-05','SOP-PKG-03','GXP-DI-01','GXP-PT11-01'] %}<option>{{k}}</option>{% endfor %}</select><input class="col form-control" type="date" name="valid_until" required><input class="col form-control" name="reason" placeholder="Training evidence/reference" required><button class="col btn btn-primary">Qualify</button></form>
<table class="table table-sm"><tr><th>User</th><th>Course</th><th>Status</th><th>Valid until</th><th>Qualified by</th></tr>{% for t in training %}<tr><td>{{t.username}}</td><td>{{t.course_code}}</td><td>{{t.status}}</td><td>{{t.valid_until}}</td><td>{{t.qualified_by}}</td></tr>{% endfor %}</table></div>
{% endif %}

{% if tab=='rbe' %}
<div class="card p-3"><h5>Review by Exception / Final QA Disposition</h5>{% for b in batches %}<div class="border rounded p-2 mb-2"><b>{{b.batch_id}}</b> — {{b.status}} — {{b.product_name}}
<form method="post" action="/qa/review" class="mt-2"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="batch_id" value="{{b.batch_id}}"><input class="form-control mb-1" name="password" type="password" placeholder="QA password" required><input class="form-control mb-1" name="comments" placeholder="Review comments / exceptions"><input class="form-control mb-1" name="reason" placeholder="Review reason" required><button class="btn btn-sm btn-warning">Perform RbE Review + eSign</button></form>
{% if b.status=='READY FOR QA RELEASE' %}<form method="post" action="/qa/release" class="mt-2"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="batch_id" value="{{b.batch_id}}"><select class="form-select mb-1" name="decision"><option value="RELEASED_COMMERCIAL">RELEASED_COMMERCIAL</option><option value="REJECTED_QUARANTINE">REJECTED_QUARANTINE</option></select><input class="form-control mb-1" name="password" type="password" placeholder="QA Release password" required><input class="form-control mb-1" name="reason" placeholder="Final disposition reason" required><button class="btn btn-sm btn-success">Final QA Disposition + eSign</button></form>{% endif %}</div>{% endfor %}</div>
{% endif %}

{% if tab=='genealogy' %}
<div class="card p-3"><h5>Genealogy / Traceability</h5>{% for b in batches %}<a class="btn btn-sm btn-outline-primary me-1 mb-1" href="/genealogy/{{b.batch_id}}">{{b.batch_id}}</a>{% endfor %}<p class="text-muted mt-2">Traceability records link material lots to batches and controlled execution events.</p></div>
{% endif %}

{% if tab=='logbooks' %}
<div class="card p-3"><h5>Electronic Equipment Logbook</h5><table class="table table-sm"><tr><th>Time</th><th>Equipment</th><th>Event</th><th>Details</th><th>Performed by</th><th>Reason</th></tr>{% for l in logs %}<tr><td>{{l.timestamp}}</td><td>{{l.eq_id}}</td><td>{{l.event_type}}</td><td>{{l.details}}</td><td>{{l.performed_by}}</td><td>{{l.reason}}</td></tr>{% endfor %}</table></div>
{% endif %}

{% if tab=='deviation' %}
<div class="card p-3"><h5>Deviations / CAPA</h5>{% for d in deviations %}<div class="border rounded p-2 mb-2"><b>{{d.deviation_id}}</b> — {{d.status}} — {{d.description}}{% if d.status!='CLOSED' %}<form method="post" action="/deviation/close" class="mt-2"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="deviation_id" value="{{d.deviation_id}}"><textarea class="form-control mb-1" name="investigation" placeholder="Investigation" required></textarea><textarea class="form-control mb-1" name="capa" placeholder="CAPA" required></textarea><input class="form-control mb-1" name="password" type="password" placeholder="QA password" required><input class="form-control mb-1" name="reason" placeholder="Closure reason" required><button class="btn btn-sm btn-success">Close CAPA</button></form>{% endif %}</div>{% endfor %}</div>
{% endif %}

{% if tab=='change' %}
<div class="row g-3"><div class="col-lg-5"><div class="card p-3"><h5>Open Change Control</h5><form method="post" action="/change/create"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input class="form-control mb-2" name="change_id" placeholder="Change ID" required><input class="form-control mb-2" name="object_type" placeholder="Object type" required><input class="form-control mb-2" name="object_id" placeholder="Object ID" required><textarea class="form-control mb-2" name="description" placeholder="Change description" required></textarea><textarea class="form-control mb-2" name="impact" placeholder="Documented quality/data-integrity impact assessment" required></textarea><input class="form-control mb-2" name="reason" placeholder="Change reason" required><button class="btn btn-primary">Open Change</button></form></div></div><div class="col-lg-7"><div class="card p-3"><h5>Change Controls</h5>{% for c in changes %}<div class="border rounded p-2 mb-2"><b>{{c.change_id}}</b> — {{c.status}} — {{c.description}}{% if c.status=='OPEN' %}<form method="post" action="/change/approve" class="mt-2"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="change_id" value="{{c.change_id}}"><input class="form-control mb-1" name="password" type="password" placeholder="QA password" required><input class="form-control mb-1" name="reason" placeholder="Approval reason" required><button class="btn btn-sm btn-success">Approve</button></form>{% endif %}</div>{% endfor %}</div></div></div>
{% endif %}

{% if tab=='audit' %}
<div class="card p-3"><h5>Audit Trail / Data Integrity</h5><p>Application audit events are hash chained. Verify before relying on integrity.</p><a class="btn btn-sm btn-primary" href="/audit/verify">Verify chain (JSON)</a> <a class="btn btn-sm btn-secondary" href="/audit/export">Export CSV</a>
<table class="table table-sm mt-3"><tr><th>#</th><th>Time UTC</th><th>User</th><th>Role</th><th>Module</th><th>Action</th><th>Record</th><th>Reason</th><th>Hash</th></tr>{% for a in audits %}<tr><td>{{a.id}}</td><td>{{a.timestamp}}</td><td>{{a.username}}</td><td>{{a.role}}</td><td>{{a.module}}</td><td>{{a.action}}</td><td>{{a.record_ref}}</td><td>{{a.reason}}</td><td class="mono">{{a.record_hash[:12]}}</td></tr>{% endfor %}</table></div>
{% endif %}

{% if tab=='backup' %}
<div class="card p-3"><h5>Backup / Archive</h5><p>Use a controlled backup destination and validate restoration separately.</p><form method="post" action="/backup"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input class="form-control mb-2" name="path" placeholder="Optional backup file path"><input class="form-control mb-2" name="reason" placeholder="Backup reason / schedule reference" required><button class="btn btn-primary">Create SQLite Online Backup</button></form></div>
{% endif %}
</div></body></html>
"""

LOGIN_UI = r"""
<!doctype html><html><head><meta charset="utf-8"><title>Pharma MES Sign In</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#002b5c;min-height:100vh;display:flex;align-items:center;justify-content:center}.box{width:460px;background:white;border-radius:10px;box-shadow:0 12px 35px #0008}.head{background:#001f3f;color:white;padding:20px;border-radius:10px 10px 0 0}</style></head>
<body><div class="box"><div class="head"><h4>Pharma MES</h4><div>Site 102 • OSD • Compliance Controls v11 • Execution Flow</div></div><div class="p-4">
{% with messages=get_flashed_messages(with_categories=true) %}{% for c,m in messages %}<div class="alert alert-{{c}} py-2">{{m}}</div>{% endfor %}{% endwith %}
<form method="post"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><label>User ID</label><input class="form-control mb-3" name="username" autocomplete="username" required><label>Password</label><input class="form-control mb-3" type="password" name="password" autocomplete="current-password" required><button class="btn btn-primary w-100">Sign in</button></form>
<hr><small class="text-muted">Demo seed accounts are provided for development/testing only. Replace them before any controlled use.</small></div></div></body></html>
"""

GENEALOGY_UI = r"""
<!doctype html><html><head><meta charset="utf-8"><title>Genealogy {{batch_id}}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-light"><div class="container py-4"><a href="/">← MES</a><h3>Genealogy / Traceability — {{batch_id}}</h3>
<table class="table table-sm table-bordered bg-white"><tr><th>Time</th><th>Parent</th><th>Relation</th><th>Child</th><th>Qty</th><th>User</th></tr>
{% for r in rows %}<tr><td>{{r.timestamp}}</td><td>{{r.parent_type}}: {{r.parent_id}}</td><td>{{r.relation}}</td><td>{{r.child_type}}: {{r.child_id}}</td><td>{{r.qty}} {{r.uom}}</td><td>{{r.performed_by}}</td></tr>{% endfor %}
</table></div></body></html>
"""

def launch_browser():
    url="http://127.0.0.1:5000"
    for path in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if os.path.exists(path):
            subprocess.Popen([path,f"--app={url}","--window-size=1520,980"])
            return
    webbrowser.open(url)

if __name__=="__main__":
    init_db()
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        threading.Timer(1.2,launch_browser).start()
    app.run(host="127.0.0.1",port=5000,debug=False)
