# app.py - WORKING VERSION with Built-in Talisman Nonce Support
# https://usbapp.titan.in

from flask import Flask, request, jsonify, make_response, abort
from werkzeug.security import check_password_hash
import pyotp
import jwt
import datetime
import logging
import os
import re
from functools import wraps
from flask_talisman import Talisman
from datetime import datetime
import datetime
from werkzeug.serving import WSGIRequestHandler

from dotenv import load_dotenv
from db_utils import DBUtils
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json

load_dotenv()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.before_request
def deny_browser_requests():
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")

    if origin or referer:
        logger.warning(
            f"[🚨] Blocked browser request | Origin: {origin}, Referer: {referer}"
        )
        abort(403)


@app.before_request
def block_trace_and_options():
    if request.method == "TRACE":
        abort(405)


@app.after_request
def remove_cors_headers(response):
    cors_headers = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Methods",
    ]

    for header in cors_headers:
        response.headers.pop(header, None)

    return response


# Make nonce available in templates
@app.context_processor
def inject_csp_nonce():
    """Make CSP nonce available in templates"""
    try:
        from flask_talisman import csp_nonce

        return {"csp_nonce": csp_nonce}
    except ImportError:
        return {"csp_nonce": lambda: ""}


app.config["JWT_SECRET_KEY"] = os.getenv("SERVER_SECRET") or "fallback-secret"
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_COOKIE_SAMESITE"] = "Strict"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=1)
jwt = JWTManager(app)

# Enhanced Rate limiting setup with different limits per endpoint
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100000 per day", "10000 per hour"],
    # For production, use Redis: storage_uri="redis://localhost:6379"
)


# Input Validation Classes
class ValidationError(Exception):
    pass


class InputValidator:
    @staticmethod
    def validate_username(username):
        """Validate username: 3-50 chars, alphanumeric + underscore only"""
        if not username:
            raise ValidationError("Username is required")
        if not isinstance(username, str):
            raise ValidationError("Username must be a string")
        if len(username) < 3 or len(username) > 50:
            raise ValidationError("Username must be 3-50 characters long")
        if not re.match("^[a-zA-Z0-9_]+$", username):
            raise ValidationError(
                "Username can only contain letters, numbers, and underscores"
            )
        return username.lower().strip()

    @staticmethod
    def validate_password(password):
        """Validate password: minimum 8 chars, at least one letter and one number"""
        if not password:
            raise ValidationError("Password is required")
        if not isinstance(password, str):
            raise ValidationError("Password must be a string")
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        if len(password) > 128:
            raise ValidationError("Password too long (max 128 characters)")
        # Check for at least one letter and one number
        if not re.search(r"[A-Za-z]", password):
            raise ValidationError("Password must contain at least one letter")
        if not re.search(r"[0-9]", password):
            raise ValidationError("Password must contain at least one number")
        return password

    @staticmethod
    def validate_totp_code(totp_code):
        """Validate TOTP code: 6 digits only"""
        if totp_code is None:
            return None
        if not isinstance(totp_code, str):
            raise ValidationError("TOTP code must be a string")
        totp_code = totp_code.strip()
        if not re.match("^[0-9]{6}$", totp_code):
            raise ValidationError("TOTP code must be exactly 6 digits")
        return totp_code

    @staticmethod
    def validate_hash_string(hash_string, field_name):
        """Validate hash strings (USB serial hash, machine ID)"""
        if not hash_string:
            raise ValidationError(f"{field_name} is required")
        if not isinstance(hash_string, str):
            raise ValidationError(f"{field_name} must be a string")
        hash_string = hash_string.strip()
        if len(hash_string) < 10 or len(hash_string) > 128:
            raise ValidationError(f"{field_name} must be 10-128 characters long")
        # Allow alphanumeric and common hash characters
        if not re.match("^[a-zA-Z0-9_-]+$", hash_string):
            raise ValidationError(f"{field_name} contains invalid characters")
        return hash_string

    @staticmethod
    def validate_purpose(purpose):
        """Validate purpose field"""
        if not purpose:
            raise ValidationError("Purpose is required")
        if not isinstance(purpose, str):
            raise ValidationError("Purpose must be a string")
        purpose = purpose.strip()
        allowed_purposes = ["Auto Encrypt", "Auto Decrypt", "GUI Decrypt"]
        if purpose not in allowed_purposes:
            raise ValidationError(
                f"Purpose must be one of: {', '.join(allowed_purposes)}"
            )
        return purpose

    @staticmethod
    def validate_file_list(files: list[str]):
        """Validate file list"""
        if files is None:
            return []
        if not isinstance(files, list):
            raise ValidationError("Files must be a list")
        if len(files) > 100:  # Reasonable limit
            raise ValidationError("Too many files (max 100)")

        validated_files = []
        for file_name in files:
            if not isinstance(file_name, str):
                raise ValidationError("File names must be strings")
            file_name = file_name.strip()
            if len(file_name) > 255:  # File system limit
                raise ValidationError("File name too long")
            # Basic file name validation (allow most characters but prevent path traversal)
            if (
                ".." in file_name
                or file_name.startswith("/")
                or file_name.startswith("\\")
            ):
                raise ValidationError("Invalid file name")
            validated_files.append(file_name)
        return validated_files


# Security decorator for additional request validation
def secure_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check Content-Type for POST requests
        if request.method == "POST":
            if not request.is_json:
                return jsonify({"error": "Content-Type must be application/json"}), 400

            # Check request size (prevent DoS)
            if (
                request.content_length and request.content_length > 1024 * 1024
            ):  # 1MB limit
                return jsonify({"error": "Request too large"}), 413

        # Add security headers to response
        response = f(*args, **kwargs)
        if hasattr(response, "headers"):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"
        return response

    return decorated_function


SYSTEM_USER = "system"
db = DBUtils()


@app.route("/", methods=["GET"])
def test():
    return "Welcome"


def is_machine_valid(machine_id: str, usb_serial_hash: str):
    try:
        usb_serial_hash = InputValidator.validate_hash_string(
            usb_serial_hash, "USB Serial Hash"
        )
        machine_id = InputValidator.validate_hash_string(machine_id, "Machine ID")

        device = db.get_device_by_usb_and_machine_id(
            serial_hash=usb_serial_hash, machine_id=machine_id
        )
        if not device:
            return False

        return True

    except Exception as e:
        print("ERROR IN is machine valid", e)
        return jsonify(
            {"error": "Access Denied", "detail": "Invalid Machine or USB hash"}
        ), 403


# Additional sync endpoints to add to your existing app.py

from datetime import datetime

# Add these new endpoints to your existing app.py


@app.route("/sync/log", methods=["POST"])
@limiter.limit("50 per minute")  # Higher limit for sync operations
@secure_request
def sync_offline_log():
    """Receive and store offline logs from clients"""
    try:
        data = json.loads(request.data, object_pairs_hook=dict)

        if not data:
            return jsonify({"error": "JSON payload required"}), 400

        if len(data) != len(set(data.keys())):
            return jsonify({"error": "Duplicate keys in JSON"}), 400

        # Validate required fields
        required_fields = [
            "username",
            "action",
            "usb_serial_hash",
            "machine_id",
            "operation",
            "status",
        ]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Validate username
        username = InputValidator.validate_username(
            data.get("username", "offline_user")
        )

        if not is_machine_valid(
            machine_id=data["machine_id"], usb_serial_hash=data["usb_serial_hash"]
        ):
            return jsonify(
                {"error": "403: Access Denied", "detail": "Invalid Machine or USB hash"}
            ), 403

        if username.strip().lower() not in ["offline_user", "online_user"]:
            return jsonify(
                {"error": "400: Bad Request", "detail": "Invalid Username"}
            ), 400

        # Allowed values
        allowed_actions = [
            "authorization_check",
            "key_retrieval",
            "key_not_found",
            "auto_decrypt",
            "authorization_failed",
            "authorization_denied",
            "decryption_completed",
            "usb_removed",
            "key_generation",
            "new_files_encrypted",
            "encryption_completed",
        ]
        allowed_operations = ["Auto Encrypt", "Auto Decrypt"]
        allowed_statuses = ["success", "denied"]

        # Validate action
        action = data.get("action", "").strip()
        if action not in allowed_actions:
            return jsonify({"error": "Invalid action"}), 400
        if not re.match(r"^[a-z0-9_]+$", action):
            return jsonify({"error": "Action contains invalid characters"}), 400

        # Validate operation
        operation = data.get("operation", "").strip()
        if operation not in allowed_operations:
            return jsonify({"error": "Invalid operation"}), 400
        if not re.match(r"^[A-Za-z0-9_ ]+$", operation):
            return jsonify({"error": "Operation contains invalid characters"}), 400

        # Validate status
        status = data.get("status", "").strip()
        if status not in allowed_statuses:
            return jsonify({"error": "Invalid status"}), 400

        # Validate details: allow only letters, numbers, underscores
        raw_details = data.get("details", "")
        if not re.match(r"^[a-zA-Z0-9_]*$", raw_details):
            return jsonify({"error": "Details contains invalid characters"}), 400
        details = raw_details.strip()

        # Insert offline log with offline_source flag
        raw_files = data.get("files", "")
        validated_files = InputValidator.validate_file_list(files=raw_files.split(","))
        success = db.insert_log(
            username=username,
            action=action,
            details=details,
            usb_serial_hash=data["usb_serial_hash"],
            machine_id=data["machine_id"],
            operation=operation,
            status=status,
            files=(", ").join(validated_files),
            offline_source=True,
            timestamp=data.get("timestamp"),  # Use client timestamp if provided
        )

        if success:
            logger.info(
                f"[✅] Synced offline log: {action} for USB {data['usb_serial_hash'][:8]}..."
            )
            return jsonify(
                {"status": "success", "message": "Log synced successfully"}
            ), 200
        else:
            logger.error(f"[❌] Failed to sync offline log")
            return jsonify({"error": "Failed to store log"}), 500

    except Exception as e:
        logger.error(f"[❌] Error syncing offline log: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/get_excluded_extensions", methods=["POST"])
@limiter.limit("200 per minute")
@secure_request
def get_excluded_extensions():
    """Get excluded file extensions for a USB device"""
    try:
        data = json.loads(request.data, object_pairs_hook=dict)

        if not data:
            return jsonify({"error": "JSON payload required"}), 400

        usb_serial_hash = data.get("usb_serial_hash")
        machine_id = data.get("machine_id")

        if not usb_serial_hash:
            return jsonify({"error": "USB serial hash required"}), 400

        if not is_machine_valid(machine_id=machine_id, usb_serial_hash=usb_serial_hash):
            return jsonify(
                {"error": "403: Access Denied", "detail": "Invalid Machine or USB hash"}
            ), 403

        extensions = db.get_excluded_extensions(usb_serial_hash, machine_id=machine_id)

        return jsonify({"status": "success", "excluded_extensions": extensions}), 200

    except Exception as e:
        logger.error(f"[❌] Error getting excluded extensions: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/sync/status", methods=["GET"])
@limiter.limit("10 per minute")  # Allow frequent status checks
@secure_request
def sync_status():
    """Get sync status and statistics"""
    try:
        # Get offline sync statistics from database
        stats = db.get_sync_statistics()

        return (
            jsonify(
                {
                    "status": "success",
                    "server_time": datetime.utcnow().isoformat(),
                    "sync_stats": stats,
                    "server_reachable": True,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"[❌] Error getting sync status: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/health", methods=["GET"])
@limiter.limit("50 per minute")  # High limit for health checks
def health_check():
    """Simple health check endpoint for offline manager"""
    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "service": "USB Security Server",
            }
        ),
        200,
    )


def generate_token(user):
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user.get("role"),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    token = create_access_token(identity=payload)
    return token


@app.route("/authorize", methods=["POST"])
@limiter.limit("20 per minute")  # Higher limit for device authorization
@secure_request
def authorize_device():
    try:
        data = json.loads(request.data, object_pairs_hook=dict)

        if not data:
            return jsonify({"error": "JSON payload required"}), 400
        # Input validation
        usb_serial_hash = InputValidator.validate_hash_string(
            data.get("usb_serial_hash"), "USB Serial Hash"
        )
        machine_id = InputValidator.validate_hash_string(
            data.get("machine_id"), "Machine ID"
        )
        purpose = InputValidator.validate_purpose(data.get("purpose"))
        files = InputValidator.validate_file_list(data.get("files", "").split(","))

        file_names = ", ".join(files)

    except ValidationError as e:
        logger.warning(f"[❌] Input validation failed: {str(e)}")
        return jsonify({"error": f"Validation error: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"[❌] Unexpected error in input validation: {str(e)}")
        return jsonify({"error": "Invalid request format"}), 400

    logger.info(
        f"[🔍] Checking authorization for USB={usb_serial_hash}, Machine={machine_id}, Purpose={purpose}"
    )

    device = db.get_device_by_serial_and_machine(usb_serial_hash, machine_id, purpose)

    logger.info(f"[ℹ️] DB Record: {device}")

    if not device:
        logger.warning("[❌] Device not found in DB")

        # 🚨 Insert audit log for denial
        db.insert_log(
            username=SYSTEM_USER,
            action="authorization_check",
            details="Authorization denied - device not found",
            usb_serial_hash=usb_serial_hash,
            machine_id=machine_id,
            operation=purpose,
            status="denied",
            files=file_names,
        )
        return jsonify({"status": "denied", "key": None})

    is_encrypt = (
        purpose == "Auto Encrypt"
        and device.get("allow_encrypt")
        and device.get("encryption_machine_id") == machine_id
    )

    is_decrypt = (
        purpose in ["Auto Decrypt", "GUI Decrypt"]
        and device.get("allow_decrypt")
        and device.get("decryption_machine_id") == machine_id
    )

    if is_encrypt or is_decrypt:
        key = (
            device.get("encryption_key")
            if is_encrypt
            else device.get("decryption_key") or device.get("encryption_key")
        )

        if not key:
            logger.warning("[⚠️] Key missing in DB")

            db.insert_log(
                username=SYSTEM_USER,
                action="authorization_check",
                details="Authorization denied - key missing",
                usb_serial_hash=usb_serial_hash,
                machine_id=machine_id,
                operation=purpose,
                status="denied",
                files=file_names,
            )

            return jsonify({"status": "denied", "key": None})

        logger.info("[✅] Authorization GRANTED | 🔐 Key sent")

        # ✅ Insert audit log for success
        db.insert_log(
            username=SYSTEM_USER,
            action="authorization_check",
            details="Authorization granted",
            usb_serial_hash=usb_serial_hash,
            machine_id=machine_id,
            operation=purpose,
            status="granted",
            files=file_names,
        )

        return jsonify({"status": "granted", "key": key})
    else:
        logger.warning("[❌] Authorization DENIED")

        # 🚫 Insert audit log for failure
        db.insert_log(
            username=SYSTEM_USER,
            action="authorization_check",
            details="Authorization denied - rules mismatch",
            usb_serial_hash=usb_serial_hash,
            machine_id=machine_id,
            operation=purpose,
            status="denied",
            files=file_names,
        )

        return jsonify({"status": "denied", "key": None})


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # Strict rate limit for login attempts
@secure_request
def login():
    try:
        data = json.loads(request.data, object_pairs_hook=dict)

        if not data:
            return jsonify({"error": "JSON payload required"}), 400

        # Input validation
        username = InputValidator.validate_username(data.get("username"))
        password = InputValidator.validate_password(data.get("password"))
        totp_code = InputValidator.validate_totp_code(data.get("totp"))

    except ValidationError as e:
        logger.warning(f"[❌] Login validation failed: {str(e)}")
        return jsonify({"error": f"Validation error: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"[❌] Unexpected error in login validation: {str(e)}")
        return jsonify({"error": "Invalid request format"}), 400

    user = db.get_user(username)
    if not user:
        logger.warning(f"[❌] User not found: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user["password_hash"], password):
        logger.warning(f"[❌] Password mismatch for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if MFA is enabled (mfa_secret non-empty)
    mfa_secret = user.get("mfa_secret")
    if mfa_secret:
        if not totp_code:
            # Inform client MFA is required
            logger.info(f"[ℹ️] MFA required for user: {username}")
            return jsonify({"mfa_required": True, "message": "MFA code required"}), 200

        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(totp_code, valid_window=1):
            logger.warning(f"[❌] Invalid MFA code for user: {username}")
            return jsonify({"error": "Invalid MFA code"}), 401

    token = generate_token(user)
    logger.info(f"[✅] Login successful for user: {username}")
    return jsonify({"token": token, "status": "success"}), 200


@app.route("/secure-data", methods=["GET"])
@jwt_required()
@secure_request
def secure_data():
    current_user = get_jwt_identity()
    logger.info(f"[🔒] Protected route accessed by: {current_user}")
    return jsonify(
        {"message": f"Hello {current_user}, you are accessing a secure endpoint!"}
    )


# Custom CSP violation handler
@app.route("/csp-report", methods=["POST"])
@limiter.limit("10 per minute")  # Rate limit CSP reports
def csp_report():
    """Handle CSP violation reports"""
    try:
        report = request.get_json()
        logger.warning(f"[⚠️] CSP Violation: {report}")
        return jsonify({"status": "received"}), 200
    except Exception as e:
        logger.error(f"[❌] CSP report error: {e}")
        return jsonify({"error": "Invalid report"}), 400


# Error handlers for rate limiting and validation
@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"[⚠️] Rate limit exceeded: {get_remote_address()}")
    return (
        jsonify(
            {
                "error": "Rate limit exceeded",
                "message": "Too many requests. Please try again later.",
            }
        ),
        429,
    )


@app.errorhandler(413)
def payload_too_large(e):
    logger.warning(f"[⚠️] Payload too large: {get_remote_address()}")
    return (
        jsonify(
            {
                "error": "Payload too large",
                "message": "Request size exceeds maximum allowed limit",
            }
        ),
        413,
    )


@app.errorhandler(400)
def bad_request(e):
    return (
        jsonify(
            {"error": "Bad request", "message": "Invalid request format or parameters"}
        ),
        400,
    )


class NoServerHeaderWSGIRequestHandler(WSGIRequestHandler):
    def version_string(self):
        # Return empty string to completely suppress Werkzeug/Python version
        return ""


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8054,
        debug=False,
        request_handler=NoServerHeaderWSGIRequestHandler,
    )  # Disable debug in production


# @app.route("/sync/logs_bulk", methods=["POST"])
# @limiter.limit("10 per minute")
# @secure_request
# def sync_offline_bulk():
#     """Receive and store multiple offline logs and keys in a single request efficiently"""
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({"error": "JSON payload required"}), 400

#         logs = data.get("logs", [])
#         keys = data.get("keys", [])

#         synced_logs = db.insert_offline_logs_bulk(logs)
#         synced_keys = db.store_offline_keys_bulk(keys)

#         logger.info(
#             f"[📊] Bulk batch sync completed: {synced_logs} logs, {synced_keys} keys"
#         )

#         return jsonify(
#             {
#                 "status": "completed",
#                 "synced_logs": synced_logs,
#                 "synced_keys": synced_keys,
#                 "errors": [],  # Optional: collect validation errors beforehand if needed
#             }
#         ), 200

#     except Exception as e:
#         logger.error(f"[❌] Error in batch sync: {e}")
#         return jsonify({"error": "Internal server error"}), 500


# @app.route("/sync/key", methods=["POST"])
# @limiter.limit("20 per minute")  # Moderate limit for key sync
# @secure_request
# def sync_offline_key():
#     """Receive and store offline keys from clients"""
#     try:
#         data = json.loads(request.data, object_pairs_hook=dict)

#         if not data:
#             return jsonify({"error": "JSON payload required"}), 400

#         if not data:
#             return jsonify({"error": "JSON payload required"}), 400

#         # Validate required fields
#         required_fields = ["usb_serial_hash", "machine_id", "encryption_key", "purpose"]
#         for field in required_fields:
#             if field not in data:
#                 return jsonify({"error": f"Missing required field: {field}"}), 400

#         if (
#             not data.get("encryption_key")
#             or data.get("encryption_key", "").strip() == ""
#         ):
#             return jsonify(
#                 {"error": "400: Bad Request", "detail": "Empty Encryption key"}
#             )

#         usb_serial_hash = InputValidator.validate_hash_string(
#             data.get("usb_serial_hash"), "USB Serial Hash"
#         )
#         machine_id = InputValidator.validate_hash_string(
#             data.get("machine_id"), "Machine ID"
#         )
#         purpose = InputValidator.validate_purpose(data.get("purpose"))

#         device = db.get_device_by_serial_and_machine(
#             serial_hash=usb_serial_hash, machine_id=machine_id, purpose=purpose
#         )

#         if not device:
#             return jsonify(
#                 {"error": "403: Access Denied", "detail": "Invalid Machine or USB hash"}
#             ), 403

#         is_encrypt = (
#             purpose == "Auto Encrypt"
#             and device.get("allow_encrypt")
#             and device.get("encryption_machine_id") == machine_id
#         )

#         is_decrypt = (
#             purpose in ["Auto Decrypt", "GUI Decrypt"]
#             and device.get("allow_decrypt")
#             and device.get("decryption_machine_id") == machine_id
#         )

#         if is_encrypt or is_decrypt:
#             key = (
#                 device.get("encryption_key")
#                 if is_encrypt
#                 else device.get("decryption_key") or device.get("encryption_key")
#             )

#             if key:
#                 return jsonify(
#                     {"error": "400: Bad Request", "detail": "Key already exists"}
#                 ), 400

#         # Store offline key in keys table (you may need to create this table)
#         success = db.store_offline_key(
#             usb_serial_hash=data["usb_serial_hash"],
#             machine_id=data["machine_id"],
#             encryption_key=data["encryption_key"],
#             purpose=data["purpose"],
#             created_at=data.get("created_at"),
#             offline_source=True,
#         )

#         if success:
#             logger.info(
#                 f"[✅] Synced offline key for USB {data['usb_serial_hash'][:8]}..."
#             )
#             return (
#                 jsonify({"status": "success", "message": "Key synced successfully"}),
#                 200,
#             )
#         else:
#             logger.error(f"[❌] Failed to sync offline key")
#             return jsonify({"error": "Failed to store key"}), 500

#     except Exception as e:
#         logger.error(f"[❌] Error syncing offline key: {e}")
#         return jsonify({"error": "Internal server error"}), 500


# @app.route("/sync/batch", methods=["POST"])
# @limiter.limit("10 per minute")  # Lower limit for batch operations
# @secure_request
# def sync_offline_batch():
#     """Receive and store multiple offline logs and keys in a single request"""
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({"error": "JSON payload required"}), 400

#         logs = data.get("logs", [])
#         keys = data.get("keys", [])

#         synced_logs = 0
#         synced_keys = 0
#         errors = []

#         # Process logs
#         for log_data in logs:
#             try:
#                 success = db.insert_log(
#                     username=log_data.get("username", "offline_user"),
#                     action=log_data["action"],
#                     details=log_data.get("details", ""),
#                     usb_serial_hash=log_data["usb_serial_hash"],
#                     machine_id=log_data["machine_id"],
#                     operation=log_data["operation"],
#                     status=log_data["status"],
#                     files=log_data.get("files", ""),
#                     offline_source=True,
#                     timestamp=log_data.get("timestamp"),
#                 )
#                 if success:
#                     synced_logs += 1
#                 else:
#                     errors.append(
#                         f"Failed to sync log: {log_data.get('action', 'unknown')}"
#                     )
#             except Exception as e:
#                 errors.append(f"Log sync error: {str(e)}")

#         # Process keys
#         for key_data in keys:
#             try:
#                 success = db.store_offline_key(
#                     usb_serial_hash=key_data["usb_serial_hash"],
#                     machine_id=key_data["machine_id"],
#                     encryption_key=key_data["encryption_key"],
#                     purpose=key_data["purpose"],
#                     created_at=key_data.get("created_at"),
#                     offline_source=True,
#                 )
#                 if success:
#                     synced_keys += 1
#                 else:
#                     errors.append(
#                         f"Failed to sync key for USB: {key_data.get('usb_serial_hash', 'unknown')[:8]}..."
#                     )
#             except Exception as e:
#                 errors.append(f"Key sync error: {str(e)}")

#         logger.info(
#             f"[📊] Batch sync completed: {synced_logs} logs, {synced_keys} keys"
#         )

#         return (
#             jsonify(
#                 {
#                     "status": "completed",
#                     "synced_logs": synced_logs,
#                     "synced_keys": synced_keys,
#                     "errors": errors,
#                 }
#             ),
#             200,
#         )

#     except Exception as e:
#         logger.error(f"[❌] Error in batch sync: {e}")
#         return jsonify({"error": "Internal server error"}), 500

# Configure Talisman with automatic nonce generation
# Talisman(
#     app,
#     # HTTPS configuration
#     force_https=False,
#     strict_transport_security=True,
#     strict_transport_security_max_age=31536000,
#     strict_transport_security_include_subdomains=True,
#     strict_transport_security_preload=True,
#     # CSP without problematic CDNs - Talisman handles nonces automatically
#     content_security_policy={
#         "default-src": "'self'",
#         "script-src": "",  # Talisman adds nonce automatically
#         "style-src": "'self' https://fonts.googleapis.com",  # Talisman adds nonce automatically
#         "font-src": "'self' https://fonts.gstatic.com",
#         "img-src": "'self' data:",
#         "connect-src": "'self' https://usbapp.titancustomers.com",
#         "base-uri": "'self'",
#         "form-action": "'self'",
#         "form-action": "'self'",
#         "frame-ancestors": "'self'",
#         "object-src": "'none'",
#         "media-src": "'self'",
#         "worker-src": "'self'",
#         "child-src": "'self'",
#         "manifest-src": "'self'",
#         "report-uri": "/csp-report",
#     },
#     # Enable automatic nonce generation
#     content_security_policy_nonce_in=["script-src", "style-src"],
#     # Security headers
#     frame_options="DENY",
#     x_content_type_options=True,
#     x_xss_protection=True,
#     referrer_policy="strict-origin-when-cross-origin",
#     # Cookie settings for HTTP
#     session_cookie_secure=True,
#     # Permissions Policy
#     permissions_policy={
#         "geolocation": "()",
#         "microphone": "()",
#         "camera": "()",
#         "payment": "()",
#         "usb": "()",
#         "accelerometer": "()",
#         "gyroscope": "()",
#         "magnetometer": "()",
#         "fullscreen": "(self)",
#     },
# )


# ----------------- Removing Origin Headers from Nginx ------------------

# if ($http_origin) {
#     return 403;
# }

# if ($request_method = TRACE) {
#     return 405;
# }

# location / {
#     if ($request_method !~ ^(GET|POST)$ ) {
#         return 405;
#     }
# }


# server {
#     listen 443 ssl http2;
#     server_name usbapp.titan.in;

#     # Paths to your certificate and key
#     ssl_certificate /etc/ssl/certs/your_cert.crt;
#     ssl_certificate_key /etc/ssl/private/your_key.key;

#     # Only strong TLS protocols
#     ssl_protocols TLSv1.2 TLSv1.3;

#     # Strong ciphers (AEAD + forward secrecy), no CBC
#     ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:
#                  ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
#                  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

#     ssl_prefer_server_ciphers on;

#     # Session security
#     ssl_session_cache shared:SSL:10m;
#     ssl_session_timeout 10m;

#     # HSTS
#     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

#     # Security headers
#     add_header X-Content-Type-Options nosniff;
#     add_header X-Frame-Options DENY;
#     add_header X-XSS-Protection "1; mode=block";
#     add_header Referrer-Policy "no-referrer-when-downgrade";

#     # Flask app proxy
#     location / {
#         proxy_pass http://127.0.0.1:8054;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto $scheme;
#     }

#     # Deny TRACE, OPTIONS, and other unsafe methods
#     if ($request_method ~* "(TRACE|DELETE|TRACK|OPTIONS)") {
#         return 405;
#     }
# }

# # Redirect HTTP to HTTPS
# server {
#     listen 80;
#     server_name usbapp.titan.in;
#     return 301 https://$host$request_uri;
# }
