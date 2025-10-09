from config import DB_CONFIG
import pymysql
from datetime import datetime


class DBUtils:
    def __init__(self):
        pass  # Removed persistent connection; better to use fresh connections per query

    def insert_log(
        self,
        username,
        action,
        details,
        usb_serial_hash,
        machine_id,
        operation,
        status,
        files=None,
        offline_source=False,
        timestamp=None,
    ):
        """Insert audit log with offline support"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()

            # Use provided timestamp or current timestamp
            log_timestamp = timestamp if timestamp else datetime.utcnow()

            cursor.execute(
                """
                INSERT INTO audit_logs 
                (username, action, details, usb_serial_hash, machine_id, operation, 
                status, files, offline_source, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    username,
                    action,
                    details,
                    usb_serial_hash,
                    machine_id,
                    operation,
                    status,
                    files,
                    offline_source,
                    log_timestamp,
                ),
            )

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"[ERROR] Failed to insert log: {e}")
            return False

    def store_offline_key(
        self,
        usb_serial_hash,
        machine_id,
        encryption_key,
        purpose,
        created_at=None,
        offline_source=False,
    ):
        """Store offline key in database"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()

            key_timestamp = created_at if created_at else datetime.utcnow()

            # Create offline_keys table if it doesn't exist
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_keys (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    usb_serial_hash VARCHAR(128) NOT NULL,
                    machine_id VARCHAR(128) NOT NULL,
                    encryption_key TEXT NOT NULL,
                    purpose VARCHAR(50) NOT NULL,
                    offline_source BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_usb_machine (usb_serial_hash, machine_id),
                    INDEX idx_offline (offline_source)
                )
            """
            )

            cursor.execute(
                """
                INSERT INTO offline_keys 
                (usb_serial_hash, machine_id, encryption_key, purpose, offline_source, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                encryption_key = VALUES(encryption_key),
                synced_at = CURRENT_TIMESTAMP
            """,
                (
                    usb_serial_hash,
                    machine_id,
                    encryption_key,
                    purpose,
                    offline_source,
                    key_timestamp,
                ),
            )

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"[ERROR] Failed to store offline key: {e}")
            return False

    def get_sync_statistics(self):
        """Get synchronization statistics"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            stats = {}

            # Offline logs statistics
            cursor.execute(
                """
                SELECT 
                    COUNT(*) as total_offline_logs,
                    COUNT(CASE WHEN DATE(timestamp) = CURDATE() THEN 1 END) as today_offline_logs
                FROM audit_logs 
                WHERE offline_source = 1
            """
            )
            offline_logs_stats = cursor.fetchone()
            stats.update(offline_logs_stats)

            # Offline keys statistics
            cursor.execute(
                """
                SELECT 
                    COUNT(*) as total_offline_keys,
                    COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) as today_offline_keys
                FROM offline_keys 
                WHERE offline_source = 1
            """
            )
            offline_keys_stats = cursor.fetchone()
            stats.update(offline_keys_stats)

            # Recent sync activity
            cursor.execute(
                """
                SELECT operation, status, COUNT(*) as count
                FROM audit_logs 
                WHERE offline_source = 1 AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY operation, status
                ORDER BY count DESC
            """
            )
            recent_activity = cursor.fetchall()
            stats["recent_activity"] = recent_activity

            conn.close()
            return stats

        except Exception as e:
            print(f"[ERROR] Failed to get sync statistics: {e}")
            return {}

    def get_paginated_offline_logs(self, page=1, per_page=10):
        """Get paginated offline logs"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            offset = (page - 1) * per_page

            # Get logs with offline_source = 1
            cursor.execute(
                """
                SELECT * FROM audit_logs 
                WHERE offline_source = 1
                ORDER BY timestamp DESC 
                LIMIT %s OFFSET %s
            """,
                (per_page, offset),
            )

            logs = cursor.fetchall()

            # Get total count
            cursor.execute(
                "SELECT COUNT(*) as total FROM audit_logs WHERE offline_source = 1"
            )
            total = cursor.fetchone()["total"]

            conn.close()
            return logs, total

        except Exception as e:
            print(f"[ERROR] Failed to get offline logs: {e}")
            return [], 0

    def get_all_offline_logs(self):
        """Get all offline logs for export"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id, username, action, details, usb_serial_hash, machine_id, 
                    operation, status, files, timestamp
                FROM audit_logs 
                WHERE offline_source = 1
                ORDER BY timestamp DESC
            """
            )

            logs = cursor.fetchall()
            conn.close()
            return logs

        except Exception as e:
            print(f"[ERROR] Failed to get all offline logs: {e}")
            return []

    def get_offline_keys_paginated(self, page=1, per_page=10):
        """Get paginated offline keys"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            offset = (page - 1) * per_page

            cursor.execute(
                """
                SELECT id, usb_serial_hash, machine_id, purpose, created_at, synced_at
                FROM offline_keys 
                WHERE offline_source = 1
                ORDER BY created_at DESC 
                LIMIT %s OFFSET %s
            """,
                (per_page, offset),
            )

            keys = cursor.fetchall()

            # Get total count
            cursor.execute(
                "SELECT COUNT(*) as total FROM offline_keys WHERE offline_source = 1"
            )
            total = cursor.fetchone()["total"]

            conn.close()
            return keys, total

        except Exception as e:
            print(f"[ERROR] Failed to get offline keys: {e}")
            return [], 0

    def cleanup_old_offline_data(self, days_old=90):
        """Clean up old offline data"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()

            # Delete old offline logs
            cursor.execute(
                """
                DELETE FROM audit_logs 
                WHERE offline_source = 1 
                AND timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)
            """,
                (days_old,),
            )

            deleted_logs = cursor.rowcount

            # Delete old offline keys
            cursor.execute(
                """
                DELETE FROM offline_keys 
                WHERE offline_source = 1 
                AND created_at < DATE_SUB(NOW(), INTERVAL %s DAY)
            """,
                (days_old,),
            )

            deleted_keys = cursor.rowcount

            conn.commit()
            conn.close()

            print(
                f"[INFO] Cleaned up {deleted_logs} old offline logs and {deleted_keys} old offline keys"
            )
            return {"deleted_logs": deleted_logs, "deleted_keys": deleted_keys}

        except Exception as e:
            print(f"[ERROR] Failed to cleanup old offline data: {e}")
            return {"deleted_logs": 0, "deleted_keys": 0}

    def update_audit_logs_table(self):
        """Update audit_logs table to support offline logs"""
        try:
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()

            # Add column if it doesn't exist
            cursor.execute("SHOW COLUMNS FROM audit_logs LIKE 'offline_source'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE audit_logs ADD COLUMN offline_source BOOLEAN DEFAULT FALSE"
                )

            # Add index if it doesn't exist
            cursor.execute(
                """
                SELECT 1
                FROM INFORMATION_SCHEMA.STATISTICS
                WHERE table_schema=DATABASE()
                AND table_name='audit_logs'
                AND index_name='idx_offline'
            """
            )
            if not cursor.fetchone():
                cursor.execute("CREATE INDEX idx_offline ON audit_logs(offline_source)")

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f"[ERROR] Failed to update audit_logs table: {e}")
            return False

    def get_connection(self):
        return pymysql.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            database=DB_CONFIG["database"],
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )

    def _execute(self, query, args=None, fetchone=False, fetchall=False, commit=False):
        try:
            conn = self.get_connection()
            with conn.cursor() as cursor:
                cursor.execute(query, args or ())
                if commit:
                    conn.commit()
                if fetchone:
                    return cursor.fetchone()
                if fetchall:
                    return cursor.fetchall()
        except Exception as e:
            print(f"[DB ERROR] {e}")
            return None
        finally:
            if "conn" in locals():
                conn.close()

    # ---------------------- Audit Logs ----------------------
    # def insert_log(
    #     self,
    #     username,
    #     action,
    #     details,
    #     machine_id=None,
    #     usb_serial_hash=None,
    #     operation=None,
    #     status=None,
    #     files=None,
    # ):
    #     return self._execute(
    #         """
    #         INSERT INTO audit_logs (
    #             username, action, details,
    #             machine_id, usb_serial_hash,
    #             operation, status, files
    #         ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    #     """,
    #         (
    #             username,
    #             action,
    #             details,
    #             machine_id,
    #             usb_serial_hash,
    #             operation,
    #             status,
    #             files,
    #         ),
    #         commit=True,
    #     )

    def get_paginated_logs(self, page, per_page):
        offset = (page - 1) * per_page
        total_result = self._execute(
            "SELECT COUNT(*) AS count FROM audit_logs", fetchone=True
        )
        logs = self._execute(
            """
            SELECT * FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """,
            (per_page, offset),
            fetchall=True,
        )
        return logs, total_result["count"] if total_result else 0

    def get_all_logs(self):
        return self._execute(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC", fetchall=True
        )

    def get_emergency_logs(self):
        return self._execute(
            "SELECT * FROM emergency_logs ORDER BY timestamp DESC", fetchall=True
        )

    # ---------------------- Users ----------------------
    def get_user(self, username):
        return self._execute(
            "SELECT * FROM users WHERE username = %s", (username,), fetchone=True
        )

    def get_all_users(self):
        return self._execute(
            "SELECT id, username, role, created_at FROM users", fetchall=True
        )

    def add_user(self, username, password_hash, role, mfa_secret):
        return self._execute(
            """
            INSERT INTO users (username, password_hash, role, mfa_secret)
            VALUES (%s, %s, %s, %s)
        """,
            (username, password_hash, role, mfa_secret),
            commit=True,
        )

    def delete_user(self, username):
        return self._execute(
            "DELETE FROM users WHERE username = %s", (username,), commit=True
        )

    def get_mfa_secret(self, username):
        result = self._execute(
            "SELECT mfa_secret FROM users WHERE username = %s",
            (username,),
            fetchone=True,
        )
        return result["mfa_secret"] if result else None

    # ---------------------- Devices ----------------------
    def get_device_by_serial(self, serial_hash):
        return self._execute(
            "SELECT * FROM authorized_devices WHERE usb_serial_hash = %s",
            (serial_hash,),
            fetchone=True,
        )

    def get_device_by_serial_and_machine(self, serial_hash, machine_id, purpose):
        if purpose == "encrypt":
            sql = """
                SELECT * FROM authorized_devices
                WHERE usb_serial_hash = %s AND encryption_machine_id = %s AND allow_encrypt = 1
            """
        else:
            sql = """
                SELECT * FROM authorized_devices
                WHERE usb_serial_hash = %s AND decryption_machine_id = %s AND allow_decrypt = 1
            """
        return self._execute(sql, (serial_hash, machine_id), fetchone=True)

    def get_all_authorized_devices(self):
        return self._execute(
            """
            SELECT usb_serial_hash, encryption_machine_id, decryption_machine_id,
                   allow_encrypt, allow_decrypt, created_at
            FROM authorized_devices
            ORDER BY created_at DESC
        """,
            fetchall=True,
        )

    def add_or_update_device(
        self,
        device_id,
        encryption_machine_id,
        decryption_machine_id,
        allow_encrypt,
        allow_decrypt,
        encryption_key,
        decryption_key,
    ):
        try:
            conn = self.get_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) AS count FROM authorized_devices WHERE usb_serial_hash = %s",
                    (device_id,),
                )
                exists = cursor.fetchone()["count"] > 0

                if exists:
                    if encryption_key:
                        cursor.execute(
                            """
                            UPDATE authorized_devices
                            SET encryption_machine_id = %s,
                                decryption_machine_id = %s,
                                allow_encrypt = %s,
                                allow_decrypt = %s,
                                encryption_key = %s
                            WHERE usb_serial_hash = %s
                        """,
                            (
                                encryption_machine_id,
                                decryption_machine_id,
                                allow_encrypt,
                                allow_decrypt,
                                encryption_key,
                                device_id,
                            ),
                        )

                        cursor.execute(
                            """
                            INSERT INTO encryption_keys (key_name, key_value)
                            VALUES (%s, %s)
                        """,
                            (device_id, encryption_key),
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE authorized_devices
                            SET encryption_machine_id = %s,
                                decryption_machine_id = %s,
                                allow_encrypt = %s,
                                allow_decrypt = %s
                            WHERE usb_serial_hash = %s
                        """,
                            (
                                encryption_machine_id,
                                decryption_machine_id,
                                allow_encrypt,
                                allow_decrypt,
                                device_id,
                            ),
                        )
                else:
                    cursor.execute(
                        """
                        INSERT INTO authorized_devices (
                            usb_serial_hash, encryption_machine_id, decryption_machine_id,
                            allow_encrypt, allow_decrypt, encryption_key
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                        (
                            device_id,
                            encryption_machine_id,
                            decryption_machine_id,
                            allow_encrypt,
                            allow_decrypt,
                            encryption_key,
                        ),
                    )

                    cursor.execute(
                        """
                        INSERT INTO encryption_keys (key_name, key_value)
                        VALUES (%s, %s)
                    """,
                        (device_id, encryption_key),
                    )

                conn.commit()
        except Exception as e:
            print(f"[DB ERROR] Failed to add/update device: {e}")
            conn.rollback()
        finally:
            conn.close()

    def update_device_settings(
        self,
        device_id,
        encryption_machine_id,
        decryption_machine_id,
        allow_encrypt,
        allow_decrypt,
    ):
        try:
            conn = self.get_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE authorized_devices
                    SET encryption_machine_id = %s,
                        decryption_machine_id = %s,
                        allow_encrypt = %s,
                        allow_decrypt = %s
                    WHERE usb_serial_hash = %s
                """,
                    (
                        encryption_machine_id,
                        decryption_machine_id,
                        allow_encrypt,
                        allow_decrypt,
                        device_id,
                    ),
                )
                conn.commit()
                updated = cursor.rowcount
                return updated > 0
        except Exception as e:
            print(f"[DB ERROR] update_device_settings: {e}")
            return False
        finally:
            if "conn" in locals():
                conn.close()

    def delete_device(self, device_id):
        return self._execute(
            "DELETE FROM authorized_devices WHERE usb_serial_hash = %s",
            (device_id,),
            commit=True,
        )

    def get_encryption_key(self, device_id):
        result = self._execute(
            "SELECT encryption_key FROM authorized_devices WHERE usb_serial_hash = %s",
            (device_id,),
            fetchone=True,
        )
        return result["encryption_key"] if result else None

    # ---------------------- Key History ----------------------
    def get_paginated_keys(self, page, per_page):
        offset = (page - 1) * per_page
        total_result = self._execute(
            "SELECT COUNT(*) AS count FROM encryption_keys", fetchone=True
        )
        keys = self._execute(
            """
            SELECT * FROM encryption_keys
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """,
            (per_page, offset),
            fetchall=True,
        )
        return keys, total_result["count"] if total_result else 0
