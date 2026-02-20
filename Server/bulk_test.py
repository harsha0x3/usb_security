from db_utils import DBUtils
from datetime import datetime, timezone

db = DBUtils()

data = {
    "logs": [
        {
            "username": "user1",
            "action": "file_encryption",
            "details": "Encrypted confidential document",
            "usb_serial_hash": "USB123HASH001",
            "machine_id": "MACHINE001",
            "operation": "Auto Encrypt",
            "status": "success",
            "files": ", ".join(["doc1.pdf", "doc2.docx"]),
            "timestamp": datetime.now(timezone.utc),
        },
        {
            "username": "user2",
            "action": "file_decryption",
            "details": "Decrypted backup files",
            "usb_serial_hash": "USB456HASH002",
            "machine_id": "MACHINE002",
            "operation": "GUI Decrypt",
            "status": "success",
            "files": ", ".join(["backup1.zip", "backup2.zip"]),
            "timestamp": datetime.now(timezone.utc),
        },
        {
            "username": "user3",
            "action": "file_encryption",
            "details": "Encrypted financial reports",
            "usb_serial_hash": "USB789HASH003",
            "machine_id": "MACHINE003",
            "operation": "Auto Encrypt",
            "status": "failed",
            "files": ", ".join(["report1.xlsx"]),
            "timestamp": datetime.now(timezone.utc),
        },
    ],
    "keys": [
        {
            "usb_serial_hash": "USB123HASH001",
            "machine_id": "MACHINE001",
            "encryption_key": "ENC_KEY_001",
            "purpose": "Auto Encrypt",
            "created_at": "2025-12-19T10:00:00Z",
        },
        {
            "usb_serial_hash": "USB456HASH002",
            "machine_id": "MACHINE002",
            "encryption_key": "ENC_KEY_002",
            "purpose": "GUI Decrypt",
            "created_at": "2025-12-19T10:05:00Z",
        },
    ],
}

logs = data.get("logs", [])


db.insert_offline_logs_bulk(logs=logs)
