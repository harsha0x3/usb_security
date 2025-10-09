# usb_auto_encrypt_agent - Updated with Offline Support

import os
import time
import socket
import requests
import hashlib
import wmi
from cryptography.fernet import Fernet
import ctypes
from ctypes import wintypes
from dotenv import load_dotenv
import win32file
import win32con
import pywintypes
from offline_manager import OfflineManager

load_dotenv()

# Config
SERVER_URL = "https://usbapp.titan.in"
ENCRYPTED_EXT = ".locked"
EXCLUDED_EXTENSIONS = [".exe", ".dll", ".sys", ".bat", ".cmd"]

# Request timeout and retry settings
REQUEST_TIMEOUT = 30
MAX_RETRIES = 2  # Reduced retries for faster offline fallback
RETRY_DELAY = 2

# Initialize offline manager
offline_manager = OfflineManager(SERVER_URL)


def get_usb_hardware_serial(drive_letter):
    """Get hardware-based USB serial hash"""
    try:
        drive_letter = drive_letter.replace(":\\", "")
        c = wmi.WMI()
        for disk in c.Win32_DiskDrive():
            for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators(
                    "Win32_LogicalDiskToPartition"
                ):
                    if logical_disk.DeviceID.startswith(drive_letter):
                        serial = disk.SerialNumber or disk.PNPDeviceID
                        if serial:
                            serial = serial.strip()
                            print(f"[🔍] Raw USB Hardware Serial: {serial}")
                            serial_hash = hashlib.sha256(serial.encode()).hexdigest()
                            return serial_hash

        print(f"[⚠️] USB hardware serial not found for drive {drive_letter}")
        return None

    except Exception as e:
        print(f"[⚠️] Error getting USB serial for {drive_letter}: {e}")
        return None


def get_machine_id():
    """Get machine ID"""
    return socket.gethostname()


def encrypt_file(filepath, key):
    """Encrypt single file"""
    if filepath.endswith(ENCRYPTED_EXT):
        return
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(filepath + ENCRYPTED_EXT, "wb") as file:
        file.write(encrypted)
    os.remove(filepath)


def encrypt_usb(usb_path, key):
    """Encrypt all valid files in USB"""
    encrypted_count = 0
    for root, _, files in os.walk(usb_path):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath.endswith(ENCRYPTED_EXT):
                continue
            if any(filepath.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                continue
            try:
                encrypt_file(filepath, key)
                print(f"[🔐] Encrypted: {filepath}")
                encrypted_count += 1
            except Exception as e:
                print(f"[⚠️] Failed to encrypt {filepath}: {e}")
    return encrypted_count


def get_files_to_encrypt(usb_path):
    """Get list of files to encrypt"""
    files_to_encrypt = []
    try:
        for root, _, files in os.walk(usb_path):
            for file in files:
                filepath = os.path.join(root, file)
                if filepath.endswith(ENCRYPTED_EXT):
                    continue
                if any(filepath.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                    continue
                files_to_encrypt.append(filepath)
    except Exception as e:
        print(f"[⚠️] Error scanning files in {usb_path}: {e}")
    return files_to_encrypt


def get_encryption_key_online(device_id, machine_id, files):
    """Try to get encryption key from server"""
    for attempt in range(MAX_RETRIES):
        try:
            data = {
                "usb_serial_hash": device_id,
                "machine_id": machine_id,
                "purpose": "Auto Encrypt",
                "files": [os.path.basename(f) for f in files],
            }

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "USB-Encryption-Agent/1.0",
            }

            base_url = SERVER_URL.rstrip("/")
            endpoint_url = f"{base_url}/authorize"

            print(
                f"[📡] Attempt {attempt + 1}/{MAX_RETRIES}: Contacting server at {endpoint_url}"
            )

            response = requests.post(
                endpoint_url,
                json=data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=True,
            )

            print(f"[📡] Server responded: {response.status_code}")

            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get("status") == "granted":
                        print("[✅] Access granted by server")

                        # Cache device permissions for future offline use
                        offline_manager.cache_device_permissions(
                            device_id,
                            {
                                "encryption_machine_id": machine_id,
                                "allow_encrypt": True,
                            },
                        )

                        return result.get("key")
                    else:
                        print(f"[❌] Access denied by server: {result}")
                        return None
                except ValueError as e:
                    print(f"[❌] Invalid JSON response: {e}")
                    return None

            elif response.status_code in [500, 502, 503, 504]:
                print(f"[⚠️] Server error {response.status_code} - retrying...")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return "SERVER_UNREACHABLE"

            else:
                print(f"[❌] Unexpected server response: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print(f"[⚠️] Request timeout (attempt {attempt + 1}/{MAX_RETRIES})")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue

        except requests.exceptions.ConnectionError as e:
            print(f"[❌] Connection error: {e}")
            if attempt < MAX_RETRIES - 1:
                print("[🔄] Retrying connection...")
                time.sleep(RETRY_DELAY)
                continue

        except Exception as e:
            print(f"[❌] Unexpected error contacting server: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue

    return "SERVER_UNREACHABLE"


def get_encryption_key_offline(device_id, machine_id, files):
    """Try to get/generate encryption key for offline use"""
    print("[🔄] Server unreachable, checking offline capabilities...")

    # Check cached device permissions
    cached_device = offline_manager.get_cached_device_permissions(device_id)
    if cached_device and not cached_device.get("allow_encrypt"):
        print("[❌] Cached device permissions deny encryption")
        offline_manager.log_offline_activity(
            "authorization_check",
            "Offline encryption denied - cached permissions",
            device_id,
            machine_id,
            "Auto Encrypt",
            "denied",
            [os.path.basename(f) for f in files],
        )
        return None

    # Try to get existing offline key
    existing_key = offline_manager.get_offline_key(
        device_id, machine_id, "Auto Encrypt"
    )
    if existing_key:
        print("[🔑] Using existing offline encryption key")
        offline_manager.log_offline_activity(
            "key_retrieval",
            "Retrieved existing offline encryption key",
            device_id,
            machine_id,
            "Auto Encrypt",
            "success",
            [os.path.basename(f) for f in files],
        )
        return existing_key

    # Generate new key for offline use
    new_key = Fernet.generate_key().decode()
    offline_manager.store_offline_key(device_id, machine_id, new_key, "Auto Encrypt")

    print("[🆕] Generated new offline encryption key")
    offline_manager.log_offline_activity(
        "key_generation",
        "Generated new offline encryption key",
        device_id,
        machine_id,
        "Auto Encrypt",
        "success",
        [os.path.basename(f) for f in files],
    )

    return new_key


def get_encryption_key(device_id, machine_id, files):
    """Get encryption key with online/offline fallback"""
    # Try online first
    if offline_manager.is_server_reachable():
        key = get_encryption_key_online(device_id, machine_id, files)
        if key and key != "SERVER_UNREACHABLE":
            # Store key offline for future use
            if key:
                offline_manager.store_offline_key(
                    device_id, machine_id, key, "Auto Encrypt"
                )
            return key

    # Fall back to offline
    return get_encryption_key_offline(device_id, machine_id, files)


def eject_usb(drive_letter):
    """Eject USB drive"""
    try:
        volume = f"\\\\.\\{drive_letter[0]}:"
        handle = win32file.CreateFile(
            volume,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None,
        )
        IOCTL_STORAGE_EJECT_MEDIA = 0x2D4808
        win32file.DeviceIoControl(handle, IOCTL_STORAGE_EJECT_MEDIA, None, 0)
        print(f"[✅] Ejected USB drive {drive_letter}")
        time.sleep(2)

    except pywintypes.error as e:
        print(f"[❌] Failed to eject {drive_letter}: {e}")


def get_connected_usb():
    """Detect USB drives"""
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drive_letter = f"{chr(65 + i)}:\\"
                if (
                    ctypes.windll.kernel32.GetDriveTypeW(wintypes.LPCWSTR(drive_letter))
                    == 2
                ):
                    drives.append(drive_letter)
    except Exception as e:
        print(f"[⚠️] Error detecting USB drives: {e}")
    return drives


def main():
    """Main loop with offline support"""
    print("🔌 Waiting for USB device...")
    print(
        "🔄 Offline support enabled - operations will continue even without server connection"
    )

    if not SERVER_URL:
        print("[❌] SERVER_URL not configured")
        return

    print(f"[ℹ️] Server URL: {SERVER_URL}")

    # Display offline stats at startup
    stats = offline_manager.get_offline_stats()
    print(
        f"[📊] Offline Status: Server {'🟢 Reachable' if stats['server_reachable'] else '🔴 Unreachable'}"
    )
    print(
        f"[📊] Unsynced Logs: {stats['unsynced_logs']}, Unsynced Keys: {stats['unsynced_keys']}"
    )

    active_drives = {}
    failed_drives = set()

    while True:
        try:
            usb_drives = get_connected_usb()

            # Clean up unplugged drives from tracking
            active_drives = {d: k for d, k in active_drives.items() if d in usb_drives}
            failed_drives = {d for d in failed_drives if d in usb_drives}

            for drive in usb_drives:
                if drive in failed_drives:
                    continue

                try:
                    if drive not in active_drives:
                        print(f"[🆕] USB Detected: {drive}")

                        device_id = get_usb_hardware_serial(drive)
                        if not device_id:
                            print(
                                f"[⚠️] Could not get hardware serial for {drive}, skipping..."
                            )
                            failed_drives.add(drive)
                            continue

                        machine_id = get_machine_id()
                        print(f"[🧬] USB Serial Hash: {device_id}")
                        print(f"[🖥️] Machine ID: {machine_id}")

                        files_to_encrypt = get_files_to_encrypt(drive)
                        print(f"[📂] Found {len(files_to_encrypt)} files to encrypt")

                        if not files_to_encrypt:
                            print(
                                "[ℹ️] No files to encrypt, monitoring for new files..."
                            )
                            active_drives[drive] = None
                            continue

                        # Get encryption key (online or offline)
                        key = get_encryption_key(
                            device_id, machine_id, files_to_encrypt
                        )

                        if not key:
                            print("[❌] No encryption key available. Ejecting USB...")
                            offline_manager.log_offline_activity(
                                "authorization_denied",
                                "No encryption key available",
                                device_id,
                                machine_id,
                                "Auto Encrypt",
                                "denied",
                                [os.path.basename(f) for f in files_to_encrypt],
                            )
                            eject_usb(drive)
                            failed_drives.add(drive)
                            continue
                        else:
                            active_drives[drive] = key.encode()
                            print(
                                "[✅] Encryption key obtained. Starting encryption..."
                            )
                            encrypted_count = encrypt_usb(drive, active_drives[drive])

                            # Log encryption activity
                            offline_manager.log_offline_activity(
                                "encryption_completed",
                                f"Encrypted {encrypted_count} files",
                                device_id,
                                machine_id,
                                "Auto Encrypt",
                                "success",
                                [os.path.basename(f) for f in files_to_encrypt],
                            )

                    else:
                        # Drive already being monitored
                        print(f"[🔄] Scanning {drive} for new files to encrypt...")

                        device_id = get_usb_hardware_serial(drive)
                        if not device_id:
                            print(
                                f"[⚠️] Lost connection to {drive}, removing from active drives"
                            )
                            active_drives.pop(drive, None)
                            continue

                        machine_id = get_machine_id()
                        files_to_encrypt = get_files_to_encrypt(drive)

                        if files_to_encrypt:
                            print(f"[📂] Found {len(files_to_encrypt)} new files")
                            key = get_encryption_key(
                                device_id, machine_id, files_to_encrypt
                            )

                            if not key:
                                print("[❌] Cannot get encryption key. Ejecting USB...")
                                eject_usb(drive)
                                active_drives.pop(drive, None)
                                failed_drives.add(drive)
                                continue
                            else:
                                active_drives[drive] = key.encode()
                                encrypted_count = encrypt_usb(
                                    drive, active_drives[drive]
                                )

                                # Log new file encryption activity
                                offline_manager.log_offline_activity(
                                    "new_files_encrypted",
                                    f"Encrypted {encrypted_count} new files",
                                    device_id,
                                    machine_id,
                                    "Auto Encrypt",
                                    "success",
                                    [os.path.basename(f) for f in files_to_encrypt],
                                )
                        else:
                            print("[ℹ️] No new files to encrypt.")

                except Exception as e:
                    print(f"[⚠️] Error processing drive {drive}: {e}")
                    import traceback

                    traceback.print_exc()
                    failed_drives.add(drive)
                    active_drives.pop(drive, None)

        except Exception as e:
            print(f"[⚠️] Error in main loop: {e}")
            import traceback

            traceback.print_exc()

        # Display periodic sync status
        stats = offline_manager.get_offline_stats()
        if stats["unsynced_logs"] > 0 or stats["unsynced_keys"] > 0:
            print(
                f"[📊] Sync Status: {stats['unsynced_logs']} logs, {stats['unsynced_keys']} keys pending sync"
            )

        # Clear failed drives after some time
        if len(failed_drives) > 0:
            print(f"[ℹ️] Temporarily ignoring {len(failed_drives)} failed drives")
            time.sleep(30)
            failed_drives.clear()
        else:
            time.sleep(10)


if __name__ == "__main__":
    try:
        main()
    finally:
        # Clean shutdown
        offline_manager.stop_sync_thread()
        print("[👋] Encryption agent stopped")
