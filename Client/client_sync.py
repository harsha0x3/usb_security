# client_sync.py
import sqlite3
import requests
import threading
from queue import Queue
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class ClientSync:
    def __init__(
        self, server_url, db_path="offline_usb_data.db", batch_size=250, max_threads=3
    ):
        self.server_url = server_url.rstrip("/")
        self.db_path = db_path
        self.batch_size = batch_size
        self.max_threads = max_threads
        self.sync_lock = threading.Lock()

    def fetch_unsynced_logs(self):
        """Fetch unsynced logs from local DB in batches"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM offline_logs WHERE synced = 0")
        total_unsynced = cursor.fetchone()[0]

        batches = []
        offset = 0
        while offset < total_unsynced:
            cursor.execute(
                "SELECT * FROM offline_logs WHERE synced = 0 LIMIT ? OFFSET ?",
                (self.batch_size, offset),
            )
            batch = cursor.fetchall()
            if batch:
                batches.append(batch)
            offset += self.batch_size

        conn.close()
        return batches

    def mark_logs_as_synced(self, log_ids):
        """Mark logs as synced after successful upload"""
        if not log_ids:
            return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.executemany(
            "UPDATE offline_logs SET synced = 1 WHERE id = ?",
            [(log_id,) for log_id in log_ids],
        )
        conn.commit()
        conn.close()

    def send_log_batch(self, batch):
        """Send a single batch of logs to the server"""
        log_ids = []
        payload = []
        for log in batch:
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
            payload.append(log_data)
            log_ids.append(log[0])

        try:
            response = requests.post(
                f"{self.server_url}/sync/logs_bulk",
                json={"logs": payload},
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "USB-Encryption-Agent/1.0",
                },
                timeout=15,
            )

            if response.status_code == 200:
                logger.info(f"[✅] Successfully synced batch of {len(batch)} logs")
                self.mark_logs_as_synced(log_ids)
            else:
                logger.warning(
                    f"[⚠️] Failed to sync batch: {response.status_code} - {response.text}"
                )

        except Exception as e:
            logger.error(f"[❌] Error syncing batch: {e}")

    def sync_all_logs(self):
        """Sync all unsynced logs in parallel using threads"""
        batches = self.fetch_unsynced_logs()
        if not batches:
            logger.info("[ℹ️] No unsynced logs to send")
            return

        logger.info(f"[🔄] Starting sync for {len(batches)} batches")

        q = Queue()

        for batch in batches:
            q.put(batch)

        def worker():
            while not q.empty():
                batch = q.get()
                try:
                    self.send_log_batch(batch)
                finally:
                    q.task_done()

        threads = []
        for _ in range(min(self.max_threads, len(batches))):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        q.join()
        for t in threads:
            t.join()

        logger.info("[✅] All offline logs synced")


if __name__ == "__main__":
    server_url = "http://localhost:8054"  # Your server URL
    client_sync = ClientSync(server_url)
    client_sync.sync_all_logs()
