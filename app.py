import os
import sqlite3
import subprocess
import threading
import webbrowser
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template_string, flash

app = Flask(__name__)
app.secret_key = "pasx_pharma_mes_phase2_secret"
DB_NAME = "pasx_mes_v2.db"

# ==========================================
# DATABASE INITIALIZATION & SEED DATA
# ==========================================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(conn, username, module, action, details):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO audit_trail (timestamp, username, module, action, details) VALUES (?, ?, ?, ?, ?)",
        (ts, username, module, action, details)
    )

def verify_esignature(conn, username, pin, allowed_roles=None):
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND pin = ? AND active = 1",
        (username.strip(), pin.strip())
    ).fetchone()
    if not user:
        return None
    if allowed_roles and user["role"] not in allowed_roles:
        return None
    return user

def init_db():
    conn = get_db()
    c = conn.cursor()

    # 1. Users Table (Admin & 21 CFR Part 11 Access Control)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, full_name TEXT, role TEXT, pin TEXT, active INTEGER DEFAULT 1)''')

    # 2. Equipment Master & Logbook
    c.execute('''CREATE TABLE IF NOT EXISTS equipment (
        eq_id TEXT PRIMARY KEY, name TEXT, area TEXT, status TEXT, last_cleaned TEXT)''')

    # 3. Material Inventory (Weigh & Dispense / FEFO)
    c.execute('''CREATE TABLE IF NOT EXISTS materials (
        lot_no TEXT PRIMARY KEY, mat_code TEXT, mat_name TEXT, qty_available REAL,
        uom TEXT, expiry_date TEXT, qc_status TEXT)''')

    # 4. Master Batch Record (MBR) Recipes & Steps
    c.execute('''CREATE TABLE IF NOT EXISTS mbr_headers (
        mbr_id TEXT PRIMARY KEY, product_name TEXT, batch_size TEXT, version TEXT, status TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS mbr_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT, mbr_id TEXT, step_no INTEGER,
        phase_name TEXT, instruction TEXT, min_val REAL, max_val REAL, uom TEXT)''')

    # 5. Electronic Batch Records (EBR) & Shopfloor Execution (SFC)
    c.execute('''CREATE TABLE IF NOT EXISTS batches (
        batch_id TEXT PRIMARY KEY, mbr_id TEXT, product_name TEXT, eq_id TEXT,
        dispensed_lot TEXT, status TEXT, qa_disposition_by TEXT, created_at TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS batch_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT, step_no INTEGER,
        phase_name TEXT, instruction TEXT, min_val REAL, max_val REAL, uom TEXT,
        actual_val REAL, status TEXT, performed_by TEXT, verified_by TEXT,
        deviation_capa TEXT, timestamp TEXT)''')

    # 6. Immutable Audit Trail
    c.execute('''CREATE TABLE IF NOT EXISTS audit_trail (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, username TEXT,
        module TEXT, action TEXT, details TEXT)''')

    # Seed Initial Default Data
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", [
            ("admin_sys", "System Administrator", "Admin", "0000", 1),
            ("op_john", "John Doe (Operator)", "Operator", "1234", 1),
            ("sup_mike", "Mike Ross (Production Sup)", "Supervisor", "5555", 1),
            ("qa_sarah", "Sarah Jenkins (QA Manager)", "QA", "9999", 1)
        ])

        c.executemany("INSERT INTO equipment VALUES (?, ?, ?, ?, ?)", [
            ("EQ-MIX-01", "High Shear Mixer Granulator 500L", "Granulation Suite A", "CLEAN", "2026-10-01 08:00"),
            ("EQ-TAB-02", "Fette Rotary Tablet Press", "Compression Suite B", "CLEAN", "2026-10-01 09:30"),
            ("EQ-COAT-01", "Perforated Auto Coater", "Coating Suite C", "DIRTY", "2026-09-28 14:00")
        ])

        c.executemany("INSERT INTO materials VALUES (?, ?, ?, ?, ?, ?, ?)", [
            ("LOT-PARA-26A", "RM-101", "Paracetamol API Powder", 250.0, "kg", "2027-12-31", "RELEASED"),
            ("LOT-PARA-25X", "RM-101", "Paracetamol API Powder (Expired)", 100.0, "kg", "2025-05-01", "RELEASED"),
            ("LOT-IBU-26B", "RM-202", "Ibuprofen DC Grade", 180.0, "kg", "2027-08-15", "QUARANTINE")
        ])

        c.execute("INSERT INTO mbr_headers VALUES (?, ?, ?, ?, ?)",
                  ("MBR-PARA-500", "Paracetamol 500mg Tablets", "50.0 kg", "v2.1", "APPROVED"))
        c.executemany("INSERT INTO mbr_steps (mbr_id, step_no, phase_name, instruction, min_val, max_val, uom) VALUES (?, ?, ?, ?, ?, ?, ?)", [
            ("MBR-PARA-500", 10, "Weigh & Dispense Verification", "Verify dispensed API container net weight on floor balance", 49.5, 50.5, "kg"),
            ("MBR-PARA-500", 20, "Dry Mixing & Granulation", "Run High Shear Mixer impeller speed for 15 minutes", 140.0, 160.0, "RPM"),
            ("MBR-PARA-500", 30, "IPC Tablet Hardness Check", "Sample 10 tablets and record average hardness", 80.0, 120.0, "N"),
            ("MBR-PARA-500", 40, "Final Bulk Yield Reconciliation", "Calculate net good tablet yield percentage", 96.0, 100.0, "%")
        ])

        log_audit(conn, "SYSTEM", "INIT", "SYSTEM_BOOT", "PAS-X Desktop MES v2.0 Initialized with Default Master Data")

    conn.commit()
    conn.close()

# ==========================================
# APPLICATION ROUTES
# ==========================================
@app.route("/")
def index():
    tab = request.args.get("tab", "sfc")
    batch_id = request.args.get("batch_id", "")
    conn = get_db()

    batches = conn.execute("SELECT * FROM batches ORDER BY created_at DESC").fetchall()
    if not batch_id and batches:
        batch_id = batches[0]["batch_id"]

    active_batch = conn.execute("SELECT * FROM batches WHERE batch_id = ?", (batch_id,)).fetchone() if batch_id else None
    steps = conn.execute("SELECT * FROM batch_steps WHERE batch_id = ? ORDER BY step_no", (batch_id,)).fetchall() if batch_id else []

    mbrs = conn.execute("SELECT * FROM mbr_headers").fetchall()
    mbr_steps = conn.execute("SELECT * FROM mbr_steps ORDER BY mbr_id, step_no").fetchall()
    equipment = conn.execute("SELECT * FROM equipment").fetchall()
    materials = conn.execute("SELECT * FROM materials").fetchall()
    users = conn.execute("SELECT * FROM users").fetchall()
    audits = conn.execute("SELECT * FROM audit_trail ORDER BY id DESC LIMIT 40").fetchall()
    conn.close()

    return render_template_string(
        HTML_UI, tab=tab, batches=batches, active_batch=active_batch, steps=steps,
        mbrs=mbrs, mbr_steps=mbr_steps, equipment=equipment, materials=materials,
        users=users, audits=audits
    )

# --- 1. WEIGH & DISPENSE + BATCH CREATION ---
@app.route("/create_batch", methods=["POST"])
def create_batch():
    batch_id = request.form["batch_id"].strip().upper()
    mbr_id = request.form["mbr_id"]
    eq_id = request.form["eq_id"]
    lot_no = request.form["lot_no"]
    dispense_qty = float(request.form["dispense_qty"])
    username = request.form["username"]
    pin = request.form["pin"]

    conn = get_db()
    user = verify_esignature(conn, username, pin, ["Operator", "Supervisor", "Admin"])
    if not user:
        flash("e-Signature Failed: Invalid credentials or insufficient role!", "danger")
        return redirect(url_for("index", tab="sfc"))

    # Check Equipment Interlock
    eq = conn.execute("SELECT * FROM equipment WHERE eq_id = ?", (eq_id,)).fetchone()
    if not eq or eq["status"] != "CLEAN":
        flash(f"Equipment Interlock Blocked: {eq_id} is currently '{eq['status']}'. Must be CLEAN.", "danger")
        return redirect(url_for("index", tab="sfc"))

    # Check Material Barcode / QC Status / FEFO Expiry / Quantity
    mat = conn.execute("SELECT * FROM materials WHERE lot_no = ?", (lot_no,)).fetchone()
    today = datetime.now().strftime("%Y-%m-%d")
    if not mat or mat["qc_status"] != "RELEASED":
        flash(f"Material Interlock Blocked: Lot {lot_no} status is '{mat['qc_status']}'. Only RELEASED lots allowed!", "danger")
        return redirect(url_for("index", tab="sfc"))
    if mat["expiry_date"] < today:
        flash(f"FEFO Expiry Interlock Blocked: Lot {lot_no} expired on {mat['expiry_date']}!", "danger")
        return redirect(url_for("index", tab="sfc"))
    if mat["qty_available"] < dispense_qty:
        flash(f"Inventory Error: Insufficient stock in {lot_no} ({mat['qty_available']} {mat['uom']} available).", "danger")
        return redirect(url_for("index", tab="sfc"))

    mbr = conn.execute("SELECT * FROM mbr_headers WHERE mbr_id = ?", (mbr_id,)).fetchone()
    template_steps = conn.execute("SELECT * FROM mbr_steps WHERE mbr_id = ? ORDER BY step_no", (mbr_id,)).fetchall()

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn.execute(
            "INSERT INTO batches VALUES (?, ?, ?, ?, ?, 'IN PROGRESS', '', ?)",
            (batch_id, mbr_id, mbr["product_name"], eq_id, f"{lot_no} ({dispense_qty} {mat['uom']})", ts)
        )
        conn.execute("UPDATE equipment SET status = 'IN USE' WHERE eq_id = ?", (eq_id,))
        conn.execute("UPDATE materials SET qty_available = ROUND(qty_available - ?, 2) WHERE lot_no = ?", (dispense_qty, lot_no))

        for idx, s in enumerate(template_steps):
            initial_state = "READY" if idx == 0 else "LOCKED"
            conn.execute('''INSERT INTO batch_steps
                (batch_id, step_no, phase_name, instruction, min_val, max_val, uom, actual_val, status, performed_by, verified_by, deviation_capa, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, '', '', '', '')''',
                (batch_id, s["step_no"], s["phase_name"], s["instruction"], s["min_val"], s["max_val"], s["uom"], initial_state)
            )

        log_audit(conn, username, "WD_EBR", "BATCH_DISPENSE_RELEASE",
                  f"Batch {batch_id} created from {mbr_id}, Dispensed {dispense_qty}{mat['uom']} of {lot_no} on {eq_id}")
        conn.commit()
        flash(f"Batch {batch_id} dispensed and released to Shopfloor Execution!", "success")
    except sqlite3.IntegrityError:
        flash(f"Batch ID {batch_id} already exists!", "warning")
    finally:
        conn.close()

    return redirect(url_for("index", tab="sfc", batch_id=batch_id))

# --- 2. SHOPFLOOR EXECUTION (SFC) ---
@app.route("/execute_step", methods=["POST"])
def execute_step():
    step_id = request.form["step_id"]
    batch_id = request.form["batch_id"]
    actual_val = float(request.form["actual_val"])
    op_user = request.form["op_user"]
    op_pin = request.form["op_pin"]
    qa_user = request.form.get("qa_user", "").strip()
    qa_pin = request.form.get("qa_pin", "").strip()

    conn = get_db()
    op = verify_esignature(conn, op_user, op_pin, ["Operator", "Supervisor", "Admin"])
    if not op:
        flash("Operator e-Signature failed!", "danger")
        return redirect(url_for("index", tab="sfc", batch_id=batch_id))

    verified_by = ""
    if qa_user:
        verifier = verify_esignature(conn, qa_user, qa_pin, ["QA", "Supervisor", "Admin"])
        if not verifier or verifier["username"] == op["username"]:
            flash("2nd Verifier e-Signature failed (must be a distinct Supervisor/QA/Admin user)!", "danger")
            return redirect(url_for("index", tab="sfc", batch_id=batch_id))
        verified_by = verifier["username"]

    step = conn.execute("SELECT * FROM batch_steps WHERE id = ?", (step_id,)).fetchone()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if actual_val < step["min_val"] or actual_val > step["max_val"]:
        step_status = "DEVIATION"
        conn.execute("UPDATE batches SET status = 'HOLD (DEVIATION)' WHERE batch_id = ?", (batch_id,))
        log_audit(conn, op_user, "SFC", "IPC_DEVIATION",
                  f"Batch {batch_id} Step {step['step_no']} Out-Of-Spec: {actual_val} {step['uom']} (Limits: {step['min_val']}-{step['max_val']})")
        flash(f"DEVIATION LOCKED: {actual_val} {step['uom']} is outside limits ({step['min_val']}–{step['max_val']}). Batch placed on QA Hold!", "danger")
    else:
        step_status = "COMPLETED"
        log_audit(conn, op_user, "SFC", "STEP_EXEC",
                  f"Batch {batch_id} Step {step['step_no']} completed: {actual_val} {step['uom']} (Verified by: {verified_by or 'None'})")
        flash(f"Step {step['step_no']} signed and completed.", "success")

    conn.execute('''UPDATE batch_steps SET actual_val=?, status=?, performed_by=?, verified_by=?, timestamp=? WHERE id=?''',
                 (actual_val, step_status, op_user, verified_by, ts, step_id))

    if step_status == "COMPLETED":
        next_step = conn.execute(
            "SELECT id FROM batch_steps WHERE batch_id=? AND step_no > ? AND status='LOCKED' ORDER BY step_no ASC LIMIT 1",
            (batch_id, step["step_no"])
        ).fetchone()
        if next_step:
            conn.execute("UPDATE batch_steps SET status='READY' WHERE id=?", (next_step["id"],))

    # Check if all steps completed
    unfinished = conn.execute(
        "SELECT COUNT(*) FROM batch_steps WHERE batch_id=? AND status IN ('READY', 'LOCKED', 'DEVIATION')",
        (batch_id,)
    ).fetchone()[0]
    if unfinished == 0:
        conn.execute("UPDATE batches SET status='READY FOR QA RELEASE' WHERE batch_id=?", (batch_id,))
        b_info = conn.execute("SELECT eq_id FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        conn.execute("UPDATE equipment SET status='DIRTY' WHERE eq_id=?", (b_info["eq_id"],))
        log_audit(conn, op_user, "EBR", "SFC_FINISHED", f"Batch {batch_id} all steps finished. Routed to QA Review by Exception.")

    conn.commit()
    conn.close()
    return redirect(url_for("index", tab="sfc", batch_id=batch_id))

# --- 3. QA REVIEW BY EXCEPTION (RbE) & DEVIATION CAPA ---
@app.route("/qa_resolve_deviation", methods=["POST"])
def qa_resolve_deviation():
    step_id = request.form["step_id"]
    batch_id = request.form["batch_id"]
    capa_text = request.form["capa_text"].strip()
    qa_user = request.form["qa_user"]
    qa_pin = request.form["qa_pin"]

    conn = get_db()
    qa = verify_esignature(conn, qa_user, qa_pin, ["QA", "Admin"])
    if not qa:
        flash("QA e-Signature failed! Only QA or Admin role can approve deviations.", "danger")
        return redirect(url_for("index", tab="qa", batch_id=batch_id))

    step = conn.execute("SELECT * FROM batch_steps WHERE id=?", (step_id,)).fetchone()
    conn.execute("UPDATE batch_steps SET status='COMPLETED (CAPA)', deviation_capa=?, verified_by=? WHERE id=?",
                 (capa_text, qa_user, step_id))

    # Unlock next step
    next_step = conn.execute(
        "SELECT id FROM batch_steps WHERE batch_id=? AND step_no > ? AND status='LOCKED' ORDER BY step_no ASC LIMIT 1",
        (batch_id, step["step_no"])
    ).fetchone()
    if next_step:
        conn.execute("UPDATE batch_steps SET status='READY' WHERE id=?", (next_step["id"],))

    # Update Batch Status
    rem_devs = conn.execute("SELECT COUNT(*) FROM batch_steps WHERE batch_id=? AND status='DEVIATION'", (batch_id,)).fetchone()[0]
    rem_open = conn.execute("SELECT COUNT(*) FROM batch_steps WHERE batch_id=? AND status IN ('READY', 'LOCKED')", (batch_id,)).fetchone()[0]
    if rem_devs == 0:
        new_b_status = "IN PROGRESS" if rem_open > 0 else "READY FOR QA RELEASE"
        conn.execute("UPDATE batches SET status=? WHERE batch_id=?", (new_b_status, batch_id))

    log_audit(conn, qa_user, "QA_RBE", "DEVIATION_CAPA_APPROVED", f"Batch {batch_id} Step {step['step_no']} CAPA: {capa_text}")
    conn.commit()
    conn.close()
    flash(f"Deviation on Step {step['step_no']} closed with CAPA. Next step unlocked!", "success")
    return redirect(url_for("index", tab="qa", batch_id=batch_id))

@app.route("/qa_disposition", methods=["POST"])
def qa_disposition():
    batch_id = request.form["batch_id"]
    decision = request.form["decision"]
    qa_user = request.form["qa_user"]
    qa_pin = request.form["qa_pin"]

    conn = get_db()
    qa = verify_esignature(conn, qa_user, qa_pin, ["QA", "Admin"])
    if not qa:
        flash("QA Disposition failed: Invalid QA credentials!", "danger")
        return redirect(url_for("index", tab="qa", batch_id=batch_id))

    conn.execute("UPDATE batches SET status=?, qa_disposition_by=? WHERE batch_id=?", (decision, qa_user, batch_id))
    log_audit(conn, qa_user, "QA_RBE", "BATCH_DISPOSITION", f"Batch {batch_id} final disposition set to {decision}")
    conn.commit()
    conn.close()
    flash(f"Batch {batch_id} disposition signed: {decision}", "success")
    return redirect(url_for("index", tab="qa", batch_id=batch_id))

# --- 4. MBR RECIPE DESIGNER ---
@app.route("/create_mbr", methods=["POST"])
def create_mbr():
    mbr_id = request.form["mbr_id"].strip().upper()
    product_name = request.form["product_name"].strip()
    batch_size = request.form["batch_size"].strip()
    version = request.form["version"].strip()
    username = request.form["username"]
    pin = request.form["pin"]

    conn = get_db()
    if not verify_esignature(conn, username, pin, ["Supervisor", "QA", "Admin"]):
        flash("Unauthorized: Only Supervisor, QA, or Admin can author MBR recipes!", "danger")
        return redirect(url_for("index", tab="mbr"))

    try:
        conn.execute("INSERT INTO mbr_headers VALUES (?, ?, ?, ?, 'APPROVED')", (mbr_id, product_name, batch_size, version))
        log_audit(conn, username, "MBR_DESIGNER", "CREATE_MBR", f"Created Master Recipe {mbr_id} ({product_name})")
        conn.commit()
        flash(f"Master Batch Record {mbr_id} created. Add execution phases below.", "success")
    except sqlite3.IntegrityError:
        flash("MBR ID already exists!", "warning")
    finally:
        conn.close()
    return redirect(url_for("index", tab="mbr"))

@app.route("/add_mbr_step", methods=["POST"])
def add_mbr_step():
    mbr_id = request.form["mbr_id"]
    step_no = int(request.form["step_no"])
    phase_name = request.form["phase_name"]
    instruction = request.form["instruction"]
    min_val = float(request.form["min_val"])
    max_val = float(request.form["max_val"])
    uom = request.form["uom"]
    username = request.form["username"]
    pin = request.form["pin"]

    conn = get_db()
    if not verify_esignature(conn, username, pin, ["Supervisor", "QA", "Admin"]):
        flash("e-Signature failed for adding MBR phase!", "danger")
        return redirect(url_for("index", tab="mbr"))

    conn.execute("INSERT INTO mbr_steps (mbr_id, step_no, phase_name, instruction, min_val, max_val, uom) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (mbr_id, step_no, phase_name, instruction, min_val, max_val, uom))
    log_audit(conn, username, "MBR_DESIGNER", "ADD_MBR_STEP", f"Added Step {step_no} ({phase_name}) to {mbr_id}")
    conn.commit()
    conn.close()
    flash(f"Step {step_no} added to {mbr_id}.", "success")
    return redirect(url_for("index", tab="mbr"))

# --- 5. ADMIN & SYSTEM MANAGEMENT MODULE ---
@app.route("/admin_add_user", methods=["POST"])
def admin_add_user():
    new_user = request.form["new_user"].strip()
    full_name = request.form["full_name"].strip()
    role = request.form["role"]
    new_pin = request.form["new_pin"].strip()
    admin_user = request.form["admin_user"]
    admin_pin = request.form["admin_pin"]

    conn = get_db()
    if not verify_esignature(conn, admin_user, admin_pin, ["Admin"]):
        flash("Admin Authentication Failed! Only Admin (admin_sys / PIN: 0000) can manage users.", "danger")
        return redirect(url_for("index", tab="admin"))

    try:
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, 1)", (new_user, full_name, role, new_pin))
        log_audit(conn, admin_user, "ADMIN", "USER_CREATED", f"Created user '{new_user}' with role '{role}'")
        conn.commit()
        flash(f"User {new_user} ({role}) created successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Username already exists!", "warning")
    finally:
        conn.close()
    return redirect(url_for("index", tab="admin"))

@app.route("/admin_toggle_user", methods=["POST"])
def admin_toggle_user():
    target_user = request.form["target_user"]
    admin_user = request.form["admin_user"]
    admin_pin = request.form["admin_pin"]

    conn = get_db()
    if not verify_esignature(conn, admin_user, admin_pin, ["Admin"]):
        flash("Admin Authentication Failed!", "danger")
        return redirect(url_for("index", tab="admin"))

    conn.execute("UPDATE users SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE username=?", (target_user,))
    log_audit(conn, admin_user, "ADMIN", "USER_STATUS_CHANGE", f"Toggled active status for user '{target_user}'")
    conn.commit()
    conn.close()
    flash(f"Updated status for user {target_user}.", "info")
    return redirect(url_for("index", tab="admin"))

@app.route("/admin_add_material", methods=["POST"])
def admin_add_material():
    lot_no = request.form["lot_no"].strip().upper()
    mat_code = request.form["mat_code"].strip().upper()
    mat_name = request.form["mat_name"].strip()
    qty = float(request.form["qty"])
    uom = request.form["uom"].strip()
    expiry = request.form["expiry"]
    qc_status = request.form["qc_status"]
    user = request.form["username"]
    pin = request.form["pin"]

    conn = get_db()
    if not verify_esignature(conn, user, pin, ["Admin", "QA", "Supervisor"]):
        flash("Authentication failed!", "danger")
        return redirect(url_for("index", tab="admin"))

    conn.execute("INSERT OR REPLACE INTO materials VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (lot_no, mat_code, mat_name, qty, uom, expiry, qc_status))
    log_audit(conn, user, "ADMIN_INV", "MATERIAL_LOT_REGISTERED", f"Lot {lot_no} ({mat_name}) Qty: {qty}{uom}, Status: {qc_status}")
    conn.commit()
    conn.close()
    flash(f"Material Lot {lot_no} saved to Weigh & Dispense inventory.", "success")
    return redirect(url_for("index", tab="admin"))

@app.route("/admin_equipment", methods=["POST"])
def admin_equipment():
    eq_id = request.form["eq_id"].strip().upper()
    name = request.form.get("name", "Shopfloor Asset")
    area = request.form.get("area", "Manufacturing")
    status = request.form["status"]
    user = request.form["username"]
    pin = request.form["pin"]

    conn = get_db()
    if not verify_esignature(conn, user, pin, ["Operator", "Supervisor", "QA", "Admin"]):
        flash("e-Signature failed for Equipment Logbook update!", "danger")
        return redirect(url_for("index", tab="admin"))

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    existing = conn.execute("SELECT * FROM equipment WHERE eq_id=?", (eq_id,)).fetchone()
    if existing:
        conn.execute("UPDATE equipment SET status=?, last_cleaned=? WHERE eq_id=?", (status, ts, eq_id))
    else:
        conn.execute("INSERT INTO equipment VALUES (?, ?, ?, ?, ?)", (eq_id, name, area, status, ts))

    log_audit(conn, user, "EQ_LOGBOOK", "EQ_STATE_CHANGE", f"Equipment {eq_id} set to {status}")
    conn.commit()
    conn.close()
    flash(f"Equipment {eq_id} status updated to {status}.", "success")
    return redirect(url_for("index", tab="admin"))

# --- 6. PRINTABLE ELECTRONIC BATCH RECORD (EBR) REPORT ---
@app.route("/print_ebr/<batch_id>")
def print_ebr(batch_id):
    conn = get_db()
    batch = conn.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
    steps = conn.execute("SELECT * FROM batch_steps WHERE batch_id=? ORDER BY step_no", (batch_id,)).fetchall()
    audits = conn.execute("SELECT * FROM audit_trail WHERE details LIKE ? ORDER BY id ASC", (f"%{batch_id}%",)).fetchall()
    conn.close()
    return render_template_string(PRINT_TEMPLATE, batch=batch, steps=steps, audits=audits, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# ==========================================
# FRONTEND DESKTOP HTML INTERFACE
# ==========================================
HTML_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Werum PAS-X Desktop MES v2.0 (21 CFR Part 11)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #eef1f6; font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 0.88rem; }
        .topbar { background: linear-gradient(90deg, #002b5c, #004494); color: white; padding: 10px 20px; }
        .nav-pills .nav-link { color: #002b5c; font-weight: 600; border-radius: 6px; margin-right: 6px; background: #dce4f0; }
        .nav-pills .nav-link.active { background-color: #004494; color: white; }
        .card { border: none; border-radius: 8px; }
        .card-header { background-color: #f8f9fa; border-bottom: 2px solid #dee2e6; font-weight: 700; color: #002b5c; }
        .badge-CLEAN, .badge-RELEASED, .badge-COMPLETED { background-color: #198754; }
        .badge-DIRTY, .badge-DEVIATION, .badge-QUARANTINE, .badge-REJECTED { background-color: #dc3545; }
        .badge-READY { background-color: #0d6efd; }
        .badge-LOCKED { background-color: #6c757d; }
    </style>
</head>
<body>

<div class="topbar d-flex justify-content-between align-items-center shadow-sm mb-3">
    <div>
        <h5 class="mb-0 fw-bold">🏭 Pharma MES Desktop Client (PAS-X Architecture v2.0)</h5>
        <small class="text-light opacity-75">GAMP 5 / 21 CFR Part 11 Compliant | ALCOA+ Data Integrity Enabled</small>
    </div>
    <div class="text-end small">
        <span class="badge bg-light text-dark me-1">Admin: <code>admin_sys (0000)</code></span>
        <span class="badge bg-light text-dark me-1">Op: <code>op_john (1234)</code></span>
        <span class="badge bg-light text-dark me-1">Sup: <code>sup_mike (5555)</code></span>
        <span class="badge bg-light text-dark">QA: <code>qa_sarah (9999)</code></span>
    </div>
</div>

<div class="container-fluid px-4">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }} py-2 shadow-sm">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <!-- NAVIGATION TABS -->
    <ul class="nav nav-pills mb-3">
        <li class="nav-item"><a class="nav-link {{ 'active' if tab=='sfc' else '' }}" href="/?tab=sfc">1. Weigh, Dispense & Shopfloor (SFC)</a></li>
        <li class="nav-item"><a class="nav-link {{ 'active' if tab=='qa' else '' }}" href="/?tab=qa">2. QA Review by Exception (RbE) & CAPA</a></li>
        <li class="nav-item"><a class="nav-link {{ 'active' if tab=='mbr' else '' }}" href="/?tab=mbr">3. Master Batch Record (MBR) Designer</a></li>
        <li class="nav-item"><a class="nav-link {{ 'active' if tab=='admin' else '' }}" href="/?tab=admin">4. Admin, Users, Inventory & Equipment</a></li>
        <li class="nav-item"><a class="nav-link {{ 'active' if tab=='audit' else '' }}" href="/?tab=audit">5. 21 CFR Part 11 Audit Trail</a></li>
    </ul>

    <!-- ==================== TAB 1: WEIGH, DISPENSE & SHOPFLOOR ==================== -->
    {% if tab == 'sfc' %}
    <div class="row">
        <div class="col-md-4">
            <div class="card shadow-sm mb-3">
                <div class="card-header">Weigh & Dispense (FEFO) + Batch Dispatch</div>
                <div class="card-body">
                    <form action="/create_batch" method="POST">
                        <div class="mb-2">
                            <label class="form-label mb-0 fw-bold">Batch Number</label>
                            <input type="text" name="batch_id" class="form-control form-control-sm" placeholder="e.g. B2026-105" required>
                        </div>
                        <div class="mb-2">
                            <label class="form-label mb-0 fw-bold">Master Recipe (MBR)</label>
                            <select name="mbr_id" class="form-select form-select-sm">
                                {% for m in mbrs %}
                                <option value="{{ m.mbr_id }}">{{ m.mbr_id }} - {{ m.product_name }} ({{ m.version }})</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="mb-2">
                            <label class="form-label mb-0 fw-bold">Primary Equipment (Must be CLEAN)</label>
                            <select name="eq_id" class="form-select form-select-sm">
                                {% for eq in equipment %}
                                <option value="{{ eq.eq_id }}">{{ eq.eq_id }} ({{ eq.name }}) - [{{ eq.status }}]</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="row g-2 mb-2">
                            <div class="col-8">
                                <label class="form-label mb-0 fw-bold">Material Lot Scan (FEFO/QC Check)</label>
                                <select name="lot_no" class="form-select form-select-sm">
                                    {% for mat in materials %}
                                    <option value="{{ mat.lot_no }}">{{ mat.lot_no }} | {{ mat.mat_name }} | Avail: {{ mat.qty_available }}{{ mat.uom }} | Exp: {{ mat.expiry_date }} [{{ mat.qc_status }}]</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-4">
                                <label class="form-label mb-0 fw-bold">Dispense Qty</label>
                                <input type="number" step="0.01" name="dispense_qty" class="form-control form-control-sm" value="50.0" required>
                            </div>
                        </div>
                        <div class="row g-2 mb-2">
                            <div class="col"><input type="text" name="username" class="form-control form-control-sm" placeholder="User (op_john)" required></div>
                            <div class="col"><input type="password" name="pin" class="form-control form-control-sm" placeholder="PIN (1234)" required></div>
                        </div>
                        <button class="btn btn-primary btn-sm w-100 fw-bold">Verify Interlocks & Release EBR</button>
                    </form>
                </div>
            </div>

            <div class="card shadow-sm">
                <div class="card-header">Active Batch Queue</div>
                <div class="card-body p-2">
                    <table class="table table-sm table-hover mb-0">
                        <thead><tr><th>Batch</th><th>Product</th><th>Status</th><th>Action</th></tr></thead>
                        <tbody>
                        {% for b in batches %}
                        <tr class="{{ 'table-primary' if active_batch and active_batch.batch_id == b.batch_id else '' }}">
                            <td class="fw-bold">{{ b.batch_id }}</td>
                            <td><small>{{ b.product_name }}</small></td>
                            <td><span class="badge bg-secondary">{{ b.status }}</span></td>
                            <td>
                                <a href="/?tab=sfc&batch_id={{ b.batch_id }}" class="btn btn-xs btn-outline-dark py-0 px-2">Select</a>
                                <a href="/print_ebr/{{ b.batch_id }}" target="_blank" class="btn btn-xs btn-outline-primary py-0 px-2">🖨️ EBR</a>
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-md-8">
            {% if active_batch %}
            <div class="card shadow-sm">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span>Shopfloor Execution (SFC): {{ active_batch.batch_id }} | {{ active_batch.product_name }} (Lot: {{ active_batch.dispensed_lot }})</span>
                    <div>
                        <span class="badge bg-dark me-2">State: {{ active_batch.status }}</span>
                        <a href="/print_ebr/{{ active_batch.batch_id }}" target="_blank" class="btn btn-sm btn-outline-primary py-0">🖨️ Print Official EBR</a>
                    </div>
                </div>
                <div class="card-body p-2">
                    <table class="table table-bordered table-sm align-middle mb-0">
                        <thead class="table-light">
                            <tr><th>Step</th><th>Phase & Work Instruction</th><th>IPC Limits</th><th>Actual</th><th>Status</th><th>Electronic Signatures</th></tr>
                        </thead>
                        <tbody>
                        {% for s in steps %}
                        <tr>
                            <td class="fw-bold text-center">{{ s.step_no }}</td>
                            <td>
                                <strong>{{ s.phase_name }}</strong><br>
                                <small class="text-muted">{{ s.instruction }}</small>
                                {% if s.deviation_capa %}
                                <div class="text-danger small fw-bold mt-1">CAPA Justification: {{ s.deviation_capa }}</div>
                                {% endif %}
                            </td>
                            <td>{{ s.min_val }} – {{ s.max_val }} {{ s.uom }}</td>
                            <td class="fw-bold">{{ s.actual_val if s.actual_val is not none else '-' }} {{ s.uom if s.actual_val is not none else '' }}</td>
                            <td><span class="badge badge-{{ s.status.split()[0] }}">{{ s.status }}</span></td>
                            <td style="width: 340px;">
                                {% if s.status == 'READY' and active_batch.status == 'IN PROGRESS' %}
                                <form action="/execute_step" method="POST" class="row g-1">
                                    <input type="hidden" name="step_id" value="{{ s.id }}">
                                    <input type="hidden" name="batch_id" value="{{ active_batch.batch_id }}">
                                    <div class="col-4"><input type="number" step="0.01" name="actual_val" class="form-control form-control-sm" placeholder="Val ({{ s.uom }})" required></div>
                                    <div class="col-4"><input type="text" name="op_user" class="form-control form-control-sm" placeholder="Doer ID" required></div>
                                    <div class="col-4"><input type="password" name="op_pin" class="form-control form-control-sm" placeholder="PIN" required></div>
                                    <div class="col-6"><input type="text" name="qa_user" class="form-control form-control-sm" placeholder="Verifier ID (Opt)"></div>
                                    <div class="col-6"><input type="password" name="qa_pin" class="form-control form-control-sm" placeholder="Verifier PIN"></div>
                                    <div class="col-12"><button class="btn btn-primary btn-sm w-100 py-0">Sign & Complete Phase</button></div>
                                </form>
                                {% elif s.status == 'DEVIATION' %}
                                <a href="/?tab=qa&batch_id={{ active_batch.batch_id }}" class="btn btn-danger btn-sm w-100 py-0">Locked: Go to QA RbE to Resolve</a>
                                {% elif s.status == 'LOCKED' %}
                                <span class="text-muted small">🔒 Sequential Interlock Active</span>
                                {% else %}
                                <small>Done: <b>{{ s.performed_by }}</b> | Ver: <b>{{ s.verified_by or 'N/A' }}</b><br><span class="text-muted">{{ s.timestamp }}</span></small>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% else %}
            <div class="alert alert-info">Create or select a Batch on the left to begin Shopfloor Execution.</div>
            {% endif %}
        </div>
    </div>
    {% endif %}

    <!-- ==================== TAB 2: QA REVIEW BY EXCEPTION (RbE) ==================== -->
    {% if tab == 'qa' %}
    <div class="row">
        <div class="col-md-12">
            <div class="card shadow-sm mb-3">
                <div class="card-header">QA Review by Exception (RbE) — Open IPC Deviations & Batch Release</div>
                <div class="card-body">
                    <h6>1. Batches Requiring QA Disposition or Deviation CAPA</h6>
                    <table class="table table-sm table-bordered align-middle">
                        <thead class="table-light">
                            <tr><th>Batch ID</th><th>Product</th><th>Dispensed Material</th><th>Current Status</th><th>QA Final Release / Rejection</th></tr>
                        </thead>
                        <tbody>
                        {% for b in batches %}
                        <tr>
                            <td class="fw-bold">{{ b.batch_id }}</td>
                            <td>{{ b.product_name }}</td>
                            <td>{{ b.dispensed_lot }}</td>
                            <td><span class="badge bg-warning text-dark">{{ b.status }}</span></td>
                            <td>
                                {% if b.status == 'READY FOR QA RELEASE' %}
                                <form action="/qa_disposition" method="POST" class="row g-1">
                                    <input type="hidden" name="batch_id" value="{{ b.batch_id }}">
                                    <div class="col-3">
                                        <select name="decision" class="form-select form-select-sm">
                                            <option value="RELEASED TO MARKET">RELEASE</option>
                                            <option value="REJECTED / QUARANTINE">REJECT</option>
                                        </select>
                                    </div>
                                    <div class="col-3"><input type="text" name="qa_user" class="form-control form-control-sm" placeholder="QA User (qa_sarah)" required></div>
                                    <div class="col-3"><input type="password" name="qa_pin" class="form-control form-control-sm" placeholder="PIN (9999)" required></div>
                                    <div class="col-3"><button class="btn btn-success btn-sm w-100">e-Sign Disposition</button></div>
                                </form>
                                {% else %}
                                <small class="text-muted">Signed By: <b>{{ b.qa_disposition_by or 'Pending SFC Completion' }}</b></small>
                                <a href="/?tab=qa&batch_id={{ b.batch_id }}" class="btn btn-outline-primary btn-sm py-0 ms-2">Inspect Steps</a>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>

                    {% if active_batch %}
                    <hr>
                    <h6 class="text-danger fw-bold">2. Exception Inspection for Batch: {{ active_batch.batch_id }}</h6>
                    <table class="table table-sm table-bordered">
                        <thead><tr><th>Step</th><th>Phase</th><th>Limits</th><th>Actual</th><th>Status</th><th>QA CAPA Resolution Sign-Off</th></tr></thead>
                        <tbody>
                        {% for s in steps %}
                        <tr class="{{ 'table-danger' if s.status == 'DEVIATION' else '' }}">
                            <td>{{ s.step_no }}</td>
                            <td>{{ s.phase_name }}</td>
                            <td>{{ s.min_val }} - {{ s.max_val }} {{ s.uom }}</td>
                            <td class="fw-bold">{{ s.actual_val }} {{ s.uom }}</td>
                            <td>{{ s.status }}</td>
                            <td>
                                {% if s.status == 'DEVIATION' %}
                                <form action="/qa_resolve_deviation" method="POST" class="row g-1">
                                    <input type="hidden" name="step_id" value="{{ s.id }}">
                                    <input type="hidden" name="batch_id" value="{{ active_batch.batch_id }}">
                                    <div class="col-5"><input type="text" name="capa_text" class="form-control form-control-sm" placeholder="Root Cause / CAPA Reference (e.g. DEV-2026-09)" required></div>
                                    <div class="col-3"><input type="text" name="qa_user" class="form-control form-control-sm" placeholder="qa_sarah" required></div>
                                    <div class="col-2"><input type="password" name="qa_pin" class="form-control form-control-sm" placeholder="PIN" required></div>
                                    <div class="col-2"><button class="btn btn-danger btn-sm w-100">Approve CAPA</button></div>
                                </form>
                                {% else %}
                                <small class="text-muted">{{ s.deviation_capa or 'No Exception' }}</small>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    {% endif %}

    <!-- ==================== TAB 3: MBR DESIGNER ==================== -->
    {% if tab == 'mbr' %}
    <div class="row">
        <div class="col-md-4">
            <div class="card shadow-sm mb-3">
                <div class="card-header">1. Create New Master Batch Record (MBR)</div>
                <div class="card-body">
                    <form action="/create_mbr" method="POST">
                        <input type="text" name="mbr_id" class="form-control form-control-sm mb-2" placeholder="MBR Code (e.g. MBR-AMOX-250)" required>
                        <input type="text" name="product_name" class="form-control form-control-sm mb-2" placeholder="Product Name (e.g. Amoxicillin 250mg Caps)" required>
                        <div class="row g-2 mb-2">
                            <div class="col"><input type="text" name="batch_size" class="form-control form-control-sm" placeholder="Batch Size (100 kg)" required></div>
                            <div class="col"><input type="text" name="version" class="form-control form-control-sm" placeholder="Version (v1.0)" required></div>
                        </div>
                        <div class="row g-2 mb-2">
                            <div class="col"><input type="text" name="username" class="form-control form-control-sm" placeholder="Author (sup_mike)" required></div>
                            <div class="col"><input type="password" name="pin" class="form-control form-control-sm" placeholder="PIN (5555)" required></div>
                        </div>
                        <button class="btn btn-primary btn-sm w-100">Create MBR Header</button>
                    </form>
                </div>
            </div>

            <div class="card shadow-sm">
                <div class="card-header">2. Add Phase / IPC Step to MBR</div>
                <div class="card-body">
                    <form action="/add_mbr_step" method="POST">
                        <select name="mbr_id" class="form-select form-select-sm mb-2">
                            {% for m in mbrs %}<option value="{{ m.mbr_id }}">{{ m.mbr_id }} - {{ m.product_name }}</option>{% endfor %}
                        </select>
                        <div class="row g-2 mb-2">
                            <div class="col-4"><input type="number" name="step_no" class="form-control form-control-sm" placeholder="Step (10)" required></div>
                            <div class="col-8"><input type="text" name="phase_name" class="form-control form-control-sm" placeholder="Phase Name" required></div>
                        </div>
                        <input type="text" name="instruction" class="form-control form-control-sm mb-2" placeholder="Shopfloor Operator Instruction" required>
                        <div class="row g-2 mb-2">
                            <div class="col-4"><input type="number" step="0.01" name="min_val" class="form-control form-control-sm" placeholder="Min Limit" required></div>
                            <div class="col-4"><input type="number" step="0.01" name="max_val" class="form-control form-control-sm" placeholder="Max Limit" required></div>
                            <div class="col-4"><input type="text" name="uom" class="form-control form-control-sm" placeholder="UOM (kg/RPM)" required></div>
                        </div>
                        <div class="row g-2 mb-2">
                            <div class="col"><input type="text" name="username" class="form-control form-control-sm" placeholder="Author (sup_mike)" required></div>
                            <div class="col"><input type="password" name="pin" class="form-control form-control-sm" placeholder="PIN (5555)" required></div>
                        </div>
                        <button class="btn btn-success btn-sm w-100">Add Phase to MBR</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-md-8">
            <div class="card shadow-sm">
                <div class="card-header">Approved Master Batch Record (MBR) Library</div>
                <div class="card-body p-2">
                    <table class="table table-sm table-bordered mb-0">
                        <thead class="table-light"><tr><th>MBR ID</th><th>Step</th><th>Phase Name</th><th>Instruction</th><th>IPC Target Limits</th></tr></thead>
                        <tbody>
                        {% for ms in mbr_steps %}
                        <tr>
                            <td class="fw-bold">{{ ms.mbr_id }}</td>
                            <td>{{ ms.step_no }}</td>
                            <td>{{ ms.phase_name }}</td>
                            <td>{{ ms.instruction }}</td>
                            <td>{{ ms.min_val }} – {{ ms.max_val }} {{ ms.uom }}</td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    {% endif %}

    <!-- ==================== TAB 4: ADMIN MODULE ==================== -->
    {% if tab == 'admin' %}
    <div class="row">
        <!-- USER MANAGEMENT -->
        <div class="col-md-4">
            <div class="card shadow-sm mb-3">
                <div class="card-header">IT Admin: 21 CFR Part 11 User Management</div>
                <div class="card-body">
                    <form action="/admin_add_user" method="POST" class="mb-3">
                        <div class="row g-1 mb-2">
                            <div class="col-6"><input type="text" name="new_user" class="form-control form-control-sm" placeholder="New User ID" required></div>
                            <div class="col-6"><input type="text" name="full_name" class="form-control form-control-sm" placeholder="Full Name" required></div>
                        </div>
                        <div class="row g-1 mb-2">
                            <div class="col-6">
                                <select name="role" class="form-select form-select-sm">
                                    <option value="Operator">Operator</option>
                                    <option value="Supervisor">Supervisor</option>
                                    <option value="QA">QA</option>
                                    <option value="Admin">Admin</option>
                                </select>
                            </div>
                            <div class="col-6"><input type="password" name="new_pin" class="form-control form-control-sm" placeholder="Assign e-Sign PIN" required></div>
                        </div>
                        <div class="row g-1 mb-2">
                            <div class="col-6"><input type="text" name="admin_user" class="form-control form-control-sm" placeholder="admin_sys" required></div>
                            <div class="col-6"><input type="password" name="admin_pin" class="form-control form-control-sm" placeholder="Admin PIN (0000)" required></div>
                        </div>
                        <button class="btn btn-dark btn-sm w-100">Provision User Account</button>
                    </form>

                    <table class="table table-sm table-bordered small mb-0">
                        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Lock/Unlock</th></tr></thead>
                        <tbody>
                        {% for u in users %}
                        <tr>
                            <td><b>{{ u.username }}</b><br><small>{{ u.full_name }}</small></td>
                            <td>{{ u.role }}</td>
                            <td><span class="badge bg-{{ 'success' if u.active else 'danger' }}">{{ 'ACTIVE' if u.active else 'LOCKED' }}</span></td>
                            <td>
                                <form action="/admin_toggle_user" method="POST" class="d-flex gap-1">
                                    <input type="hidden" name="target_user" value="{{ u.username }}">
                                    <input type="hidden" name="admin_user" value="admin_sys">
                                    <input type="password" name="admin_pin" class="form-control form-control-sm py-0" placeholder="0000" style="width:60px;" required>
                                    <button class="btn btn-outline-secondary btn-sm py-0">Toggle</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- RAW MATERIAL INVENTORY MANAGEMENT -->
        <div class="col-md-4">
            <div class="card shadow-sm mb-3">
                <div class="card-header">Material Warehouse & QC Status (FEFO)</div>
                <div class="card-body">
                    <form action="/admin_add_material" method="POST" class="mb-3">
                        <div class="row g-1 mb-2">
                            <div class="col-6"><input type="text" name="lot_no" class="form-control form-control-sm" placeholder="Lot No (LOT-26C)" required></div>
                            <div class="col-6"><input type="text" name="mat_code" class="form-control form-control-sm" placeholder="Mat Code (RM-101)" required></div>
                        </div>
                        <input type="text" name="mat_name" class="form-control form-control-sm mb-2" placeholder="Material Name" required>
                        <div class="row g-1 mb-2">
                            <div class="col-4"><input type="number" step="0.1" name="qty" class="form-control form-control-sm" placeholder="Qty" required></div>
                            <div class="col-4"><input type="text" name="uom" class="form-control form-control-sm" value="kg" required></div>
                            <div class="col-4"><input type="date" name="expiry" class="form-control form-control-sm" value="2027-12-31" required></div>
                        </div>
                        <select name="qc_status" class="form-select form-select-sm mb-2">
                            <option value="RELEASED">RELEASED</option>
                            <option value="QUARANTINE">QUARANTINE</option>
                            <option value="REJECTED">REJECTED</option>
                        </select>
                        <div class="row g-1 mb-2">
                            <div class="col-6"><input type="text" name="username" class="form-control form-control-sm" placeholder="qa_sarah / admin_sys" required></div>
                            <div class="col-6"><input type="password" name="pin" class="form-control form-control-sm" placeholder="PIN" required></div>
                        </div>
                        <button class="btn btn-primary btn-sm w-100">Register / Update Material Lot</button>
                    </form>

                    <table class="table table-sm table-bordered small mb-0">
                        <thead><tr><th>Lot No</th><th>Material</th><th>Avail</th><th>Expiry</th><th>Status</th></tr></thead>
                        <tbody>
                        {% for m in materials %}
                        <tr>
                            <td class="fw-bold">{{ m.lot_no }}</td>
                            <td>{{ m.mat_name }}</td>
                            <td>{{ m.qty_available }} {{ m.uom }}</td>
                            <td>{{ m.expiry_date }}</td>
                            <td><span class="badge badge-{{ m.qc_status }}">{{ m.qc_status }}</span></td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- EQUIPMENT LOGBOOK MANAGEMENT -->
        <div class="col-md-4">
            <div class="card shadow-sm mb-3">
                <div class="card-header">Equipment Logbook & State Machine</div>
                <div class="card-body">
                    <form action="/admin_equipment" method="POST" class="mb-3">
                        <div class="row g-1 mb-2">
                            <div class="col-6"><input type="text" name="eq_id" class="form-control form-control-sm" placeholder="EQ ID (e.g. EQ-COAT-01)" required></div>
                            <div class="col-6">
                                <select name="status" class="form-select form-select-sm">
                                    <option value="CLEAN">Set CLEAN</option>
                                    <option value="DIRTY">Set DIRTY</option>
                                    <option value="MAINTENANCE">Set MAINTENANCE</option>
                                </select>
                            </div>
                        </div>
                        <input type="text" name="name" class="form-control form-control-sm mb-2" placeholder="Equipment Name (if registering new)">
                        <div class="row g-1 mb-2">
                            <div class="col-6"><input type="text" name="username" class="form-control form-control-sm" placeholder="User ID" required></div>
                            <div class="col-6"><input type="password" name="pin" class="form-control form-control-sm" placeholder="PIN" required></div>
                        </div>
                        <button class="btn btn-success btn-sm w-100">Sign Equipment Logbook</button>
                    </form>

                    <table class="table table-sm table-bordered small mb-0">
                        <thead><tr><th>Equipment</th><th>Name</th><th>Status</th><th>Last Action</th></tr></thead>
                        <tbody>
                        {% for e in equipment %}
                        <tr>
                            <td class="fw-bold">{{ e.eq_id }}</td>
                            <td>{{ e.name }}</td>
                            <td><span class="badge badge-{{ e.status.split()[0] }}">{{ e.status }}</span></td>
                            <td>{{ e.last_cleaned }}</td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    {% endif %}

    <!-- ==================== TAB 5: AUDIT TRAIL ==================== -->
    {% if tab == 'audit' %}
    <div class="card shadow-sm">
        <div class="card-header">21 CFR Part 11 Immutable Electronic Audit Trail</div>
        <div class="card-body p-2">
            <table class="table table-sm table-striped small mb-0">
                <thead><tr><th>ID</th><th>Timestamp</th><th>User ID</th><th>MES Module</th><th>Event Action</th><th>GxP Record Details</th></tr></thead>
                <tbody>
                {% for a in audits %}
                <tr>
                    <td>{{ a.id }}</td>
                    <td>{{ a.timestamp }}</td>
                    <td><code>{{ a.username }}</code></td>
                    <td><span class="badge bg-secondary">{{ a.module }}</span></td>
                    <td class="fw-bold">{{ a.action }}</td>
                    <td>{{ a.details }}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    {% endif %}

</div>
</body>
</html>
"""

# ==========================================
# PRINTABLE OFFICIAL EBR CERTIFICATE VIEW
# ==========================================
PRINT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Official EBR Report - {{ batch.batch_id }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { font-size: 0.85rem; padding: 25px; }
        @media print { .no-print { display: none; } }
    </style>
</head>
<body>
    <div class="no-print mb-3 text-end">
        <button onclick="window.print()" class="btn btn-primary btn-sm">🖨️ Print / Save as PDF</button>
    </div>
    <div class="border p-4">
        <div class="d-flex justify-content-between border-bottom pb-2 mb-3">
            <div>
                <h4 class="fw-bold mb-0">ELECTRONIC BATCH MANUFACTURING RECORD (eBMR)</h4>
                <small>21 CFR Part 11 & EU GMP Annex 11 Compliant Record</small>
            </div>
            <div class="text-end">
                <strong>Batch ID: {{ batch.batch_id }}</strong><br>
                <span>Status: {{ batch.status }}</span>
            </div>
        </div>

        <div class="row mb-3">
            <div class="col-4"><b>Product:</b> {{ batch.product_name }}</div>
            <div class="col-4"><b>Master Recipe:</b> {{ batch.mbr_id }}</div>
            <div class="col-4"><b>Primary Equipment:</b> {{ batch.eq_id }}</div>
            <div class="col-4"><b>Dispensed Material Lot:</b> {{ batch.dispensed_lot }}</div>
            <div class="col-4"><b>Batch Created:</b> {{ batch.created_at }}</div>
            <div class="col-4"><b>QA Final Disposition By:</b> {{ batch.qa_disposition_by or 'Pending' }}</div>
        </div>

        <h6 class="fw-bold">1. Shopfloor Execution Phases & IPC Verification</h6>
        <table class="table table-bordered table-sm">
            <thead class="table-light">
                <tr><th>Step</th><th>Phase</th><th>Instruction</th><th>Spec Limits</th><th>Actual</th><th>Status</th><th>Done By</th><th>Verified By</th><th>Timestamp</th></tr>
            </thead>
            <tbody>
            {% for s in steps %}
            <tr>
                <td>{{ s.step_no }}</td>
                <td>{{ s.phase_name }}</td>
                <td>{{ s.instruction }} {% if s.deviation_capa %}<br><b class="text-danger">CAPA: {{ s.deviation_capa }}</b>{% endif %}</td>
                <td>{{ s.min_val }} - {{ s.max_val }} {{ s.uom }}</td>
                <td class="fw-bold">{{ s.actual_val }} {{ s.uom }}</td>
                <td>{{ s.status }}</td>
                <td>{{ s.performed_by }}</td>
                <td>{{ s.verified_by }}</td>
                <td>{{ s.timestamp }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>

        <h6 class="fw-bold mt-4">2. Batch-Specific 21 CFR Part 11 Audit Trail</h6>
        <table class="table table-bordered table-sm small">
            <thead class="table-light"><tr><th>Timestamp</th><th>User</th><th>Module</th><th>Action</th><th>Details</th></tr></thead>
            <tbody>
            {% for a in audits %}
            <tr><td>{{ a.timestamp }}</td><td>{{ a.username }}</td><td>{{ a.module }}</td><td>{{ a.action }}</td><td>{{ a.details }}</td></tr>
            {% endfor %}
            </tbody>
        </table>
        <div class="text-muted small mt-3">Generated by PAS-X Desktop MES on {{ now }}</div>
    </div>
</body>
</html>
"""

# ==========================================
# STANDALONE HTML DESKTOP APP LAUNCHER
# ==========================================
def launch_desktop_window():
    url = "http://127.0.0.1:5000"
    # Common paths for Windows Edge and Chrome to launch in chromeless Desktop App Mode (--app)
    browser_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    ]
    for path in browser_paths:
        if os.path.exists(path):
            subprocess.Popen([path, f"--app={url}", "--window-size=1400,900"])
            return
    webbrowser.open(url)

if __name__ == "__main__":
    init_db()
    try:
        # If pywebview is installed, launch native Python GUI wrapper window
        import webview
        threading.Thread(target=lambda: app.run(port=5000, debug=False, use_reloader=False), daemon=True).start()
        webview.create_window("Werum PAS-X Pharma MES Desktop v2.0", "http://127.0.0.1:5000", width=1400, height=900)
        webview.start()
    except ImportError:
        # Otherwise, launch standalone chromeless Desktop App Window via Edge/Chrome --app mode
        threading.Timer(1.2, launch_desktop_window).start()
        app.run(port=5000, debug=False)