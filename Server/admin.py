from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    send_file,
    flash,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
import pyotp
import base64, io, csv, secrets
from config import DB_CONFIG
from db_utils import DBUtils
from cryptography.fernet import Fernet
import qrcode
from io import BytesIO
from flask import send_file
import csv
import io
import os
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from datetime import timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
limiter = Limiter(get_remote_address, app=app)
csrf = CSRFProtect()
csrf.init_app(app)


Talisman(
    app,
    content_security_policy=None,
    force_https=True,  # Force HTTPS in production
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,  # 1 year
    content_security_policy_nonce_in=["script-src", "style-src"],
)

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

db = DBUtils()


@app.before_request
def extend_session_if_active():
    session.permanent = True


# ---------------------------- Login ----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        session.permanent = False
        username = request.form["username"]
        password = request.form["password"]
        totp_code = request.form.get("totp")

        user = db.get_user(username)
        if user and check_password_hash(user["password_hash"], password):
            totp = pyotp.TOTP(user["mfa_secret"])

           # if totp.verify(totp_code, valid_window=1):
            session["user"] = username
            session["role"] = user["role"]
            return redirect("/admin")
           # else:
           #     return "Invalid MFA code"
           # print("going /admin")
           # return redirect("/admin")   
        return "Invalid login"
        print("gon login")
   

    return render_template("login.html")


# --------------------- Admin Panel ---------------------
@app.route("/admin")
def admin_panel():
    # if session.get('role') != 'admin':
    #     return "Unauthorized", 403

    if "user" not in session:
        return redirect("/admin/login")

    readonly = session.get("role") != "admin"

    logs_page = int(request.args.get("logs_page", 1))
    keys_page = int(request.args.get("keys_page", 1))
    per_page = 4

    devices = db.get_all_authorized_devices()
    users = db.get_all_users()
    logs, total_logs = db.get_paginated_logs(logs_page, per_page)
    keys, total_keys = db.get_paginated_keys(keys_page, per_page)

    # Get offline sync statistics for dashboard
    sync_stats = db.get_sync_statistics()

    logs_pages = (total_logs + per_page - 1) // per_page
    keys_pages = (total_keys + per_page - 1) // per_page

    return render_template(
        "admin.html",
        devices=devices,
        users=users,
        logs=logs,
        keys=keys,
        logs_page=logs_page,
        logs_pages=logs_pages,
        keys_page=keys_page,
        keys_pages=keys_pages,
        sync_stats=sync_stats,  # Add sync stats
        readonly=readonly,
    )


@app.route("/admin/offline")
def offline_panel():
    """Admin panel for offline sync management"""
    if "user" not in session:
        return redirect("/admin/login")

    readonly = session.get("role") != "admin"

    # Get pagination parameters
    offline_logs_page = int(request.args.get("offline_logs_page", 1))
    offline_keys_page = int(request.args.get("offline_keys_page", 1))
    per_page = 10

    # Get offline data
    offline_logs, total_offline_logs = db.get_paginated_offline_logs(
        offline_logs_page, per_page
    )
    offline_keys, total_offline_keys = db.get_offline_keys_paginated(
        offline_keys_page, per_page
    )
    sync_stats = db.get_sync_statistics()

    # Calculate pagination
    offline_logs_pages = (total_offline_logs + per_page - 1) // per_page
    offline_keys_pages = (total_offline_keys + per_page - 1) // per_page

    return render_template(
        "offline_admin.html",
        offline_logs=offline_logs,
        offline_keys=offline_keys,
        sync_stats=sync_stats,
        offline_logs_page=offline_logs_page,
        offline_logs_pages=offline_logs_pages,
        offline_keys_page=offline_keys_page,
        offline_keys_pages=offline_keys_pages,
        total_offline_logs=total_offline_logs,
        total_offline_keys=total_offline_keys,
        readonly=readonly,
    )


@app.route("/admin/download_offline_logs")
def download_offline_logs():
    """Download offline logs as CSV"""
    if "user" not in session:
        return redirect("/admin/login")

    logs = db.get_all_offline_logs()

    fieldnames = [
        "id",
        "username",
        "action",
        "details",
        "usb_serial_hash",
        "machine_id",
        "operation",
        "status",
        "files",
        "timestamp",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for log in logs:
        writer.writerow(
            {
                "id": log[0],
                "username": log[1],
                "action": log[2],
                "details": log[3],
                "usb_serial_hash": log[4],
                "machine_id": log[5],
                "operation": log[6],
                "status": log[7],
                "files": log[8],
                "timestamp": log[9],
            }
        )

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="offline_audit_logs.csv",
    )


@app.route("/admin/cleanup_offline", methods=["POST"])
def cleanup_offline_data():
    """Clean up old offline data"""
    if session.get("role") != "admin":
        return "Unauthorized", 403

    try:
        days_old = int(request.form.get("days_old", 90))
        result = db.cleanup_old_offline_data(days_old)

        flash(
            f"Cleaned up {result['deleted_logs']} old offline logs and {result['deleted_keys']} old offline keys",
            "success",
        )
    except Exception as e:
        flash(f"Cleanup failed: {str(e)}", "danger")

    return redirect(url_for("offline_panel"))


@app.route("/admin/sync_stats_api")
def sync_stats_api():
    """API endpoint for real-time sync statistics"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        stats = db.get_sync_statistics()
        return jsonify({"status": "success", "data": stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --------------------- Machine Management ---------------------
@app.route("/admin/add_machine", methods=["POST"])
def add_machine():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    try:
        data = request.form
        device_id = data["device_id"]
        enc_id = data["encryption_machine_id"]
        dec_id = data["decryption_machine_id"]
        # Checkboxes return 'on' if checked, else None
        allow_encrypt = "allow_encrypt" in data
        allow_decrypt = "allow_decrypt" in data
        excluded_extensions = data["excluded_extensions"]

        encryption_key = data.get("encryption_key")
        if not encryption_key:
            # fallback if no key provided (shouldn't happen due to readonly in form)
            encryption_key = Fernet.generate_key().decode()

        db.add_or_update_device(
            device_id=device_id,
            encryption_machine_id=enc_id,
            decryption_machine_id=dec_id,
            allow_encrypt=allow_encrypt,
            allow_decrypt=allow_decrypt,
            encryption_key=encryption_key,
            decryption_key=None,
            excluded_extensions=excluded_extensions,
        )
        print(f"[INFO] Machine {device_id} added or updated.")
        return redirect("/admin")
    except Exception as e:
        print(f"[ERROR] Failed to add machine: {e}")
        return "Internal Server Error", 500


@app.route("/admin/delete_machine", methods=["POST"])
def delete_machine():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    try:
        device_id = request.form["device_id"]
        db.delete_device(device_id)
        print(f"[INFO] Device {device_id} deleted.")
        return redirect("/admin")
    except Exception as e:
        print(f"[ERROR] Failed to delete machine: {e}")
        return "Internal Server Error", 500


@app.route("/admin/edit_machine", methods=["POST"])
def edit_machine():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    try:
        device_id = request.form.get("device_id")
        encryption_machine_id = request.form.get("encryption_machine_id")
        decryption_machine_id = request.form.get("decryption_machine_id")
        excluded_extensions = request.form.get("excluded_extensions", "").strip()

        # ✅ Fix: Match checkbox values
        allow_encrypt = 1 if request.form.get("allow_encrypt") == "1" else 0
        allow_decrypt = 1 if request.form.get("allow_decrypt") == "1" else 0

        if not device_id:
            flash("Device ID missing", "danger")
            return redirect(url_for("admin_panel"))

        success = db.update_device_settings(
            device_id,
            encryption_machine_id,
            decryption_machine_id,
            allow_encrypt,
            allow_decrypt,
            excluded_extensions,
        )
        if success is None:
            flash("Failed to update device", "danger")
        else:
            flash("Device updated successfully", "success")
    except Exception as e:
        print(f"Error in /admin/edit_machine: {e}")
        flash(f"Internal error: {e}", "danger")

    return redirect(url_for("admin_panel"))


@app.route("/admin/generate_key")
def generate_encryption_key():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    key = Fernet.generate_key().decode()
    return jsonify({"key": key})


# --------------------- User Management ---------------------
@app.route("/admin/add_user", methods=["POST"])
def add_user():
    if session.get("role") != "admin":
        return "Unauthorized", 403

    user = request.form["username"]
    pwd = request.form["password"]
    role = request.form["role"]
    password_hash = generate_password_hash(pwd)
    mfa_secret = pyotp.random_base32()

    db.add_user(user, password_hash, role, mfa_secret)
    session["new_mfa_secret"] = mfa_secret
    session["new_username"] = user
    return redirect("/admin/mfa_qr")


@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    if session.get("role") != "admin":
        return "Unauthorized", 403
    db.delete_user(request.form["username"])
    return redirect("/admin")


# --------------------- MFA ---------------------
@app.route("/admin/mfa_qr")
def show_new_qr():
    if session.get("role") != "admin":
        return "Unauthorized", 403
    mfa_secret = session.get("new_mfa_secret")
    username = session.get("new_username")
    if not mfa_secret:
        return redirect("/admin")
    otp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
        name=username, issuer_name="USB-Security"
    )
    return render_template(
        "mfa_qr.html", username=username, otp_uri=otp_uri, secret=mfa_secret
    )


@app.route("/admin/show_qr/<username>")
def show_qr(username):
    if session.get("role") != "admin":
        return "Unauthorized", 403
    mfa_secret = db.get_mfa_secret(username)
    if not mfa_secret:
        return f"<h3>No MFA secret set for {username}</h3>"

    otp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
        name=username, issuer_name="USB Security Admin"
    )
    qr = qrcode.make(otp_uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    b64_img = base64.b64encode(buf.getvalue()).decode()

    return f"""
    <h3>MFA QR for <b>{username}</b></h3>
    <p>Scan with Google Authenticator or Microsoft Authenticator</p>
    <img src="data:image/png;base64,{b64_img}"><br>
    <p><b>Manual Entry Code:</b> {mfa_secret}</p>
    """


# --------------------- Utilities ---------------------
@app.route("/admin/export_logs")
def export_logs():
    logs = db.get_all_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Username",
            "Device ID",
            "Encryption Machine",
            "Decrypt Machine",
            "Action",
            "Time",
            "Files",
        ]
    )
    for row in logs:
        writer.writerow(row)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="audit_logs.csv",
    )


@app.route("/admin/download_logs")
def download_logs():
    db = DBUtils()
    logs = db.get_all_logs()  # Each log must now include `usb_serial_hash`

    # Add the new field
    fieldnames = [
        "id",
        "username",
        "action",
        "details",
        "usb_serial_hash",  # ✅ New column
        "machine_id",
        "operation",
        "status",
        "files",
        "timestamp",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for log in logs:
        writer.writerow({key: log.get(key, "") for key in fieldnames})

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="audit_logs.csv",
    )


@app.route("/admin/export_emergency_logs")
def export_emergency_logs():
    logs = db.get_emergency_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["Username", "Device ID", "Decrypt Machine", "Action", "Time", "Files"]
    )
    for row in logs:
        writer.writerow(row)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="emergency_logs.csv",
    )


# @app.route("/device/extensions/<usb_serial_hash>", methods=["GET"])
# def get_device_extensions(usb_serial_hash):
#     """Return excluded extensions for a specific USB device"""
#     try:
#         extensions = db.get_excluded_extensions(usb_serial_hash=usb_serial_hash,)
#         return jsonify(
#             {
#                 "status": "success",
#                 "usb_serial_hash": usb_serial_hash,
#                 "excluded_extensions": extensions,
#             }
#         ), 200
#     except Exception as e:
#         return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/admin/download_client")
def download_client():
    return send_file("static/downloads/gui_client256.exe", as_attachment=True)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/test")
def test():
    return "Test page works!"


@app.route("/")
def home():
    if "user" in session:
        return (
            redirect("/admin")
            if session["role"] == "admin"
            else render_template("index.html")
        )
    return redirect("/admin/login")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8055, debug=True)
