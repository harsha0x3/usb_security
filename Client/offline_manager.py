# offline_manager.py - Local Storage and Sync Manager

import sqlite3
import json
import os
import threading
import time
import requests
from datetime import datetime
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)


class OfflineManager:
    def __init__(self, server_url, db_path="offline_usb_data.db"):
        self.server_url = server_url.rstrip("/")
        self.db_path = db_path
        self.sync_lock = threading.Lock()
        self.sync_thread = None
        self.running = True
        self.init_database()
        self.start_sync_thread()

    def init_database(self):
        """Initialize local SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Table for offline encryption keys
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usb_serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    encryption_key TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    synced INTEGER DEFAULT 0,
                    UNIQUE(usb_serial_hash, machine_id, purpose)
                )
            """
            )

            # Table for offline audit logs
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT DEFAULT 'offline_user',
                    action TEXT NOT NULL,
                    details TEXT,
                    usb_serial_hash TEXT,
                    machine_id TEXT,
                    operation TEXT,
                    status TEXT,
                    files TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    synced INTEGER DEFAULT 0
                )
            """
            )

            # Table for device permissions cache
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cached_devices (
                    usb_serial_hash TEXT PRIMARY KEY,
                    encryption_machine_id TEXT,
                    decryption_machine_id TEXT,
                    allow_encrypt INTEGER,
                    allow_decrypt INTEGER,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            conn.commit()
            conn.close()
            logger.info("[✅] Offline database initialized")

        except Exception as e:
            logger.error(f"[❌] Failed to initialize offline database: {e}")

    def store_offline_key(self, usb_serial_hash, machine_id, key, purpose):
        """Store encryption key locally for offline use"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO offline_keys 
                (usb_serial_hash, machine_id, encryption_key, purpose, synced)
                VALUES (?, ?, ?, ?, 0)
            """,
                (usb_serial_hash, machine_id, key, purpose),
            )

            conn.commit()
            conn.close()
            logger.info(f"[💾] Stored offline key for USB {usb_serial_hash[:8]}...")

        except Exception as e:
            logger.error(f"[❌] Failed to store offline key: {e}")

    def get_offline_key(self, usb_serial_hash, machine_id, purpose):
        """Retrieve encryption key from local storage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT encryption_key FROM offline_keys 
                WHERE usb_serial_hash = ? AND machine_id = ? AND purpose = ?
                ORDER BY created_at DESC LIMIT 1
            """,
                (usb_serial_hash, machine_id, purpose),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                logger.info(
                    f"[🔑] Retrieved offline key for USB {usb_serial_hash[:8]}..."
                )
                return result[0]
            return None

        except Exception as e:
            logger.error(f"[❌] Failed to retrieve offline key: {e}")
            return None

    def log_offline_activity(
        self,
        action,
        details,
        usb_serial_hash,
        machine_id,
        operation,
        status,
        files=None,
    ):
        """Store audit log locally"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            files_str = ", ".join(files) if files else None

            cursor.execute(
                """
                INSERT INTO offline_logs 
                (username, action, details, usb_serial_hash, machine_id, 
                 operation, status, files, synced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
                (
                    "offline_user",
                    action,
                    details,
                    usb_serial_hash,
                    machine_id,
                    operation,
                    status,
                    files_str,
                ),
            )

            conn.commit()
            conn.close()
            logger.info(f"[📝] Logged offline activity: {action} - {status}")

        except Exception as e:
            logger.error(f"[❌] Failed to log offline activity: {e}")

    def cache_device_permissions(self, usb_serial_hash, device_data):
        """Cache device permissions for offline validation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO cached_devices 
                (usb_serial_hash, encryption_machine_id, decryption_machine_id, 
                 allow_encrypt, allow_decrypt, last_updated)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (
                    usb_serial_hash,
                    device_data.get("encryption_machine_id"),
                    device_data.get("decryption_machine_id"),
                    device_data.get("allow_encrypt", 0),
                    device_data.get("allow_decrypt", 0),
                ),
            )

            conn.commit()
            conn.close()
            logger.info(f"[💾] Cached device permissions for {usb_serial_hash[:8]}...")

        except Exception as e:
            logger.error(f"[❌] Failed to cache device permissions: {e}")

    def get_cached_device_permissions(self, usb_serial_hash):
        """Get cached device permissions for offline validation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT encryption_machine_id, decryption_machine_id, 
                       allow_encrypt, allow_decrypt
                FROM cached_devices 
                WHERE usb_serial_hash = ?
            """,
                (usb_serial_hash,),
            )

            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    "encryption_machine_id": result[0],
                    "decryption_machine_id": result[1],
                    "allow_encrypt": bool(result[2]),
                    "allow_decrypt": bool(result[3]),
                }
            return None

        except Exception as e:
            logger.error(f"[❌] Failed to get cached device permissions: {e}")
            return None

    def is_server_reachable(self):
        """Check if server is reachable"""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "USB-Encryption-Agent/1.0",
        }
        try:
            response = requests.get(f"{self.server_url}/", headers=headers, timeout=5)
            print(response.status_code, response.text)
            return response.status_code == 200
        except:
            return False

    def sync_offline_data(self):
        """Sync unsynced data with server"""
        if not self.is_server_reachable():
            logger.info("[⚠️] Server unreachable, skipping sync")
            return False

        with self.sync_lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                # Sync offline logs
                cursor.execute("SELECT * FROM offline_logs WHERE synced = 0")
                unsynced_logs = cursor.fetchall()

                if unsynced_logs:
                    logger.info(f"[🔄] Syncing {len(unsynced_logs)} offline logs...")

                    for log in unsynced_logs:
                        log_data = {
                            "username": log[1],
                            "action": log[2],
                            "details": log[3],
                            "usb_serial_hash": log[4],
                            "machine_id": log[5],
                            "operation": log[6],
                            "status": log[7],
                            "files": log[8],
                            "timestamp": log[9],
                            "offline_source": True,
                        }

                        try:
                            response = requests.post(
                                f"{self.server_url}/sync/log",
                                json=log_data,
                                timeout=10,
                                headers={
                                    "Content-Type": "application/json",
                                    "Accept": "application/json",
                                    "User-Agent": "USB-Encryption-Agent/1.0",
                                },
                            )

                            if response.status_code == 200:
                                # Mark as synced
                                cursor.execute(
                                    "UPDATE offline_logs SET synced = 1 WHERE id = ?",
                                    (log[0],),
                                )
                                logger.info(f"[✅] Synced log ID {log[0]}")
                            else:
                                logger.warning(
                                    f"[⚠️] Failed to sync log ID {log[0]}: {response.status_code}"
                                )
                                logger.warning(f"response error {response.text}")

                        except Exception as e:
                            logger.error(f"[❌] Error syncing log ID {log[0]}: {e}")

                # Sync offline keys (if server supports it)
                cursor.execute("SELECT * FROM offline_keys WHERE synced = 0")
                unsynced_keys = cursor.fetchall()

                if unsynced_keys:
                    logger.info(f"[🔄] Syncing {len(unsynced_keys)} offline keys...")

                    for key_record in unsynced_keys:
                        key_data = {
                            "usb_serial_hash": key_record[1],
                            "machine_id": key_record[2],
                            "encryption_key": key_record[3],
                            "purpose": key_record[4],
                            "created_at": key_record[5],
                            "offline_source": True,
                        }

                        try:
                            response = requests.post(
                                f"{self.server_url}/sync/key",
                                json=key_data,
                                timeout=10,
                                headers={
                                    "Content-Type": "application/json",
                                    "Accept": "application/json",
                                    "User-Agent": "USB-Encryption-Agent/1.0",
                                },
                            )

                            if response.status_code == 200:
                                cursor.execute(
                                    "UPDATE offline_keys SET synced = 1 WHERE id = ?",
                                    (key_record[0],),
                                )
                                logger.info(f"[✅] Synced key ID {key_record[0]}")
                            else:
                                logger.warning(
                                    f"[⚠️] Failed to sync key ID {key_record[0]}: {response.status_code}"
                                )

                        except Exception as e:
                            logger.error(
                                f"[❌] Error syncing key ID {key_record[0]}: {e}"
                            )

                conn.commit()
                conn.close()
                return True

            except Exception as e:
                logger.error(f"[❌] Sync operation failed: {e}")
                return False

    def start_sync_thread(self):
        """Start background sync thread"""

        def sync_worker():
            while self.running:
                try:
                    if self.is_server_reachable():
                        self.sync_offline_data()
                    time.sleep(60)  # Sync every minute when server is reachable
                except Exception as e:
                    logger.error(f"[❌] Sync thread error: {e}")
                    time.sleep(30)  # Wait 30 seconds on error

        self.sync_thread = threading.Thread(target=sync_worker, daemon=True)
        self.sync_thread.start()
        logger.info("[🔄] Sync thread started")

    def stop_sync_thread(self):
        """Stop background sync thread"""
        self.running = False
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.join(timeout=5)
        logger.info("[⏹️] Sync thread stopped")

    def get_offline_stats(self):
        """Get statistics about offline data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM offline_logs WHERE synced = 0")
            unsynced_logs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM offline_logs WHERE synced = 1")
            synced_logs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM offline_keys WHERE synced = 0")
            unsynced_keys = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM offline_keys WHERE synced = 1")
            synced_keys = cursor.fetchone()[0]

            conn.close()

            return {
                "unsynced_logs": unsynced_logs,
                "synced_logs": synced_logs,
                "unsynced_keys": unsynced_keys,
                "synced_keys": synced_keys,
                "server_reachable": self.is_server_reachable(),
            }

        except Exception as e:
            logger.error(f"[❌] Failed to get offline stats: {e}")
            return {
                "unsynced_logs": 0,
                "synced_logs": 0,
                "unsynced_keys": 0,
                "synced_keys": 0,
                "server_reachable": False,
            }

    def cleanup_old_data(self, days_old=30):
        """Clean up old synced data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Delete synced logs older than specified days
            cursor.execute(
                """
                DELETE FROM offline_logs 
                WHERE synced = 1 AND timestamp < datetime('now', '-{} days')
            """.format(
                    days_old
                )
            )

            cursor.execute(
                """
                DELETE FROM offline_keys 
                WHERE synced = 1 AND created_at < datetime('now', '-{} days')
            """.format(
                    days_old
                )
            )

            conn.commit()
            conn.close()
            logger.info(f"[🧹] Cleaned up data older than {days_old} days")

        except Exception as e:
            logger.error(f"[❌] Failed to cleanup old data: {e}")
