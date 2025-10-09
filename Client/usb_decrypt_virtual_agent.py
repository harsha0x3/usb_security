# usb_decrypt_virtual_agent_offline.py - Updated with Offline Support

import os
import time
import socket
import hashlib
import requests
import shutil
import ctypes
from ctypes import wintypes
import wmi
import win32file
import win32con
import pywintypes
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from offline_manager import OfflineManager

load_dotenv()

SERVER_URL = "https://usbapp.titan.in"
ENCRYPTED_EXT = ".locked"
DECRYPTED_BASE = r"C:\Temp\.decrypted_usb"
VIRTUAL_DRIVE_LETTER = "Z:"

# Request settings
REQUEST_TIMEOUT = 30
MAX_RETRIES = 2  # Reduced for faster offline fallback
RETRY_DELAY = 2


def get_available_drive_letter():
    """Get next available drive letter for virtual mapping"""
    import subprocess

    # Get all currently used drive letters
    used_drives = set()
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            used_drives.add(chr(65 + i))

    # Get existing subst drives
    try:
        result = subprocess.run(["subst"], capture_output=True, text=True, shell=True)
        subst_output = result.stdout
        for line in subst_output.split("\n"):
            if line.strip() and ": => " in line:
                drive_letter = line.split(":")[0].strip()
                if drive_letter:
                    used_drives.add(drive_letter)
    except:
        pass

    print(f"[🔍] Currently used/mapped drives: {sorted(used_drives)}")

    # Check letters from Z to D
    for letter in "ZYXWVUTSRQPONMLKJIHGFED":
        if letter not in used_drives:
            print(f"[✅] Found available drive letter: {letter}:")
            return f"{letter}:"

    print("[⚠️] No available drive letters found")
    return None


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
                            return hashlib.sha256(serial.strip().encode()).hexdigest()

        print(f"[⚠️] USB hardware serial not found for drive {drive_letter}")
        return None
    except Exception as e:
        print(f"[⚠️] Error getting USB serial for {drive_letter}: {e}")
        return None


def get_machine_id():
    """Get machine ID"""
    return socket.gethostname()


def eject_usb(drive_letter):
    """Eject USB drive safely"""
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
        return True
    except pywintypes.error as e:
        print(f"[❌] Failed to eject {drive_letter}: {e}")
        return False


def decrypt_file(src_path, dest_path, key):
    """Decrypt single file"""
    fernet = Fernet(key)
    with open(src_path, "rb") as f:
        decrypted_data = fernet.decrypt(f.read())
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "wb") as f:
        f.write(decrypted_data)


def get_files_to_decrypt(drive_path):
    """Get list of encrypted files"""
    files = []
    try:
        for root, _, file_names in os.walk(drive_path):
            for file in file_names:
                if file.endswith(ENCRYPTED_EXT):
                    files.append(file)
    except Exception as e:
        print(f"[⚠️] Error scanning files in {drive_path}: {e}")
    return files


def get_decryption_key_online(device_id, machine_id, drive_path):
    """Try to get decryption key from server"""
    files = get_files_to_decrypt(drive_path)

    for attempt in range(MAX_RETRIES):
        try:
            data = {
                "usb_serial_hash": device_id,
                "machine_id": machine_id,
                "purpose": "Auto Decrypt",
                "files": files,
            }

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "USB-Decrypt-Agent/1.0",
            }

            base_url = SERVER_URL.rstrip("/")
            endpoint_url = f"{base_url}/authorize"

            print(
                f"[📡] Attempt {attempt + 1}/{MAX_RETRIES}: Requesting decrypt key from {endpoint_url}"
            )

            resp = requests.post(
                endpoint_url,
                json=data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=True,
            )

            print(f"[📡] Server responded: {resp.status_code}")

            if resp.status_code == 200:
                try:
                    result = resp.json()
                    if result.get("status") == "granted":
                        print("[✅] Decryption key granted")

                        # Cache device permissions for future offline use
                        offline_manager.cache_device_permissions(
                            device_id,
                            {
                                "decryption_machine_id": machine_id,
                                "allow_decrypt": True,
                            },
                        )

                        return result.get("key")
                    elif result.get("status") == "denied":
                        print("[❌] Access denied by server")
                        return "UNAUTHORIZED"
                    else:
                        print(f"[❌] Unexpected response: {result}")
                        return None
                except ValueError as e:
                    print(f"[❌] Invalid JSON response: {e}")
                    return None

            elif resp.status_code in [500, 502, 503, 504]:
                print(f"[⚠️] Server error {resp.status_code} - retrying...")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return "SERVER_UNREACHABLE"

            else:
                print(f"[❌] Unexpected server response: {resp.status_code}")
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


def get_decryption_key_offline(device_id, machine_id, drive_path):
    """Try to get decryption key for offline use"""
    print("[🔄] Server unreachable, checking offline capabilities...")
    files = get_files_to_decrypt(drive_path)

    # Check cached device permissions
    cached_device = offline_manager.get_cached_device_permissions(device_id)
    if cached_device and not cached_device.get("allow_decrypt"):
        print("[❌] Cached device permissions deny decryption")
        offline_manager.log_offline_activity(
            "authorization_check",
            "Offline decryption denied - cached permissions",
            device_id,
            machine_id,
            "Auto Decrypt",
            "denied",
            files,
        )
        return "UNAUTHORIZED"

    # Try to get existing offline key (could be from encrypt or previous decrypt)
    existing_key = offline_manager.get_offline_key(
        device_id, machine_id, "Auto Decrypt"
    )
    if not existing_key:
        # Try encryption key (same key used for both operations)
        existing_key = offline_manager.get_offline_key(
            device_id, machine_id, "Auto Encrypt"
        )

    if existing_key:
        print("[🔑] Using existing offline decryption key")
        offline_manager.log_offline_activity(
            "key_retrieval",
            "Retrieved existing offline decryption key",
            device_id,
            machine_id,
            "Auto Decrypt",
            "success",
            files,
        )
        return existing_key

    print("[❌] No offline decryption key available")
    offline_manager.log_offline_activity(
        "key_not_found",
        "No offline decryption key available",
        device_id,
        machine_id,
        "Auto Decrypt",
        "denied",
        files,
    )
    return None


def get_decryption_key(device_id, machine_id, drive_path):
    """Get decryption key with online/offline fallback"""
    # Try online first
    if offline_manager.is_server_reachable():
        key = get_decryption_key_online(device_id, machine_id, drive_path)
        if key and key not in ["SERVER_UNREACHABLE", "UNAUTHORIZED"]:
            # Store key offline for future use
            offline_manager.store_offline_key(
                device_id, machine_id, key, "Auto Decrypt"
            )
            return key
        elif key == "UNAUTHORIZED":
            return key

    # Fall back to offline
    return get_decryption_key_offline(device_id, machine_id, drive_path)


def get_connected_usb():
    """Detect USB drives"""
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            drive_letter = f"{chr(65 + i)}:\\"
            if (
                bitmask & (1 << i)
                and ctypes.windll.kernel32.GetDriveTypeW(wintypes.LPCWSTR(drive_letter))
                == 2
            ):
                drives.append(drive_letter)
    except Exception as e:
        print(f"[⚠️] Error detecting USB drives: {e}")
    return drives


def decrypt_usb_to_virtual_view(drive, key, usb_id):
    """Decrypt USB files to virtual directory"""
    virtual_path = os.path.join(DECRYPTED_BASE, usb_id)
    os.makedirs(virtual_path, exist_ok=True)

    decrypted_count = 0
    for root, _, files in os.walk(drive):
        for file in files:
            if file.endswith(ENCRYPTED_EXT):
                src = os.path.join(root, file)
                relative = os.path.relpath(src, drive)
                dest = os.path.join(virtual_path, relative.replace(ENCRYPTED_EXT, ""))
                try:
                    decrypt_file(src, dest, key)
                    print(f"[🔓] Decrypted: {src} → {dest}")
                    decrypted_count += 1
                except Exception as e:
                    print(f"[⚠️] Decryption failed for {src}: {e}")

    print(f"[📊] Decrypted {decrypted_count} files to virtual view")
    return virtual_path, decrypted_count


def map_virtual_drive(folder_path, drive_letter):
    """Map virtual drive to specific letter"""
    try:
        result = os.system(f'subst {drive_letter} "{folder_path}"')
        if result != 0:
            print(f"[⚠️] Failed to map drive {drive_letter} to {folder_path}")
            return False
        else:
            os.system(f"label {drive_letter} usb_read_{drive_letter[0]}")
            print(f"[ℹ️] Mapped {drive_letter} to {folder_path}")
            return True
    except Exception as e:
        print(f"[❌] Error mapping virtual drive {drive_letter}: {e}")
        return False


def unmap_virtual_drive(drive_letter):
    """Unmap specific virtual drive"""
    try:
        result = os.system(f"subst {drive_letter} /D")
        if result != 0:
            print(f"[⚠️] Failed to unmap {drive_letter}")
            return False
        else:
            print(f"[ℹ️] Unmapped virtual drive {drive_letter}")
            return True
    except Exception as e:
        print(f"[❌] Error unmapping virtual drive {drive_letter}: {e}")
        return False


# USB .locked File Monitor
class USBFileMonitor(FileSystemEventHandler):
    def __init__(self, usb_drive, virtual_path, key, usb_id, machine_id):
        self.usb_drive = usb_drive
        self.virtual_path = virtual_path
        self.key = key
        self.usb_id = usb_id
        self.machine_id = machine_id

    def on_created(self, event):
        self._process(event)

    def on_modified(self, event):
        self._process(event)

    def _process(self, event):
        if event.is_directory or not event.src_path.endswith(ENCRYPTED_EXT):
            return
        try:
            relative = os.path.relpath(event.src_path, self.usb_drive)
            dest = os.path.join(self.virtual_path, relative.replace(ENCRYPTED_EXT, ""))

            if os.path.exists(dest):
                print(f"[↩️] Already decrypted: {dest}")
                return

            decrypt_file(event.src_path, dest, self.key)
            print(f"[🔥] Auto-decrypted: {event.src_path} → {dest}")

            # Log auto-decryption activity
            offline_manager.log_offline_activity(
                "auto_decrypt",
                f"Auto-decrypted new file: {os.path.basename(event.src_path)}",
                self.usb_id,
                self.machine_id,
                "Auto Decrypt",
                "success",
                [os.path.basename(event.src_path)],
            )

        except Exception as e:
            print(f"[⚠️] Auto-decrypt error: {e}")


def start_usb_monitor(usb_drive, virtual_path, key, usb_id, machine_id):
    """Start monitoring USB for new encrypted files"""
    try:
        observer = Observer()
        handler = USBFileMonitor(usb_drive, virtual_path, key, usb_id, machine_id)
        observer.schedule(handler, usb_drive, recursive=True)
        observer.daemon = True
        observer.start()
        print(f"[👁️] Watching USB {usb_drive} for .locked files...")
        return observer
    except Exception as e:
        print(f"[❌] Error starting USB monitor: {e}")
        return None


def main():
    """Main loop with offline support"""
    print("🔍 Waiting for authorized USB...")
    print(
        "🔄 Offline support enabled - decryption will continue even without server connection"
    )

    if not SERVER_URL:
        print("[❌] SERVER_URL not configured in .env file")
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

    os.makedirs(DECRYPTED_BASE, exist_ok=True)

    failed_drives = set()
    usb_states = {}

    while True:
        try:
            connected = get_connected_usb()
            new_drives = [d for d in connected if d not in usb_states]

            for drive in new_drives:
                print(f"[🟢] USB Detected: {drive}")
                try:
                    usb_id = get_usb_hardware_serial(drive)
                    if not usb_id:
                        print(
                            f"[⚠️] Could not get hardware serial for {drive}, skipping..."
                        )
                        failed_drives.add(drive)
                        continue

                    machine_id = get_machine_id()
                    print(f"[🧬] USB ID: {usb_id}")
                    print(f"[🖥️] Machine ID: {machine_id}")

                    key = get_decryption_key(usb_id, machine_id, drive)

                    if key == "SERVER_UNREACHABLE":
                        print(
                            "[❌] Server unreachable and no offline key available. Ejecting USB..."
                        )
                        offline_manager.log_offline_activity(
                            "authorization_failed",
                            "Server unreachable, no offline key",
                            usb_id,
                            machine_id,
                            "Auto Decrypt",
                            "denied",
                            get_files_to_decrypt(drive),
                        )
                        eject_usb(drive)
                        failed_drives.add(drive)
                        continue
                    elif key == "UNAUTHORIZED" or not key:
                        print("[❌] Unauthorized device. Ejecting USB...")
                        offline_manager.log_offline_activity(
                            "authorization_denied",
                            "Unauthorized device",
                            usb_id,
                            machine_id,
                            "Auto Decrypt",
                            "denied",
                            get_files_to_decrypt(drive),
                        )
                        eject_usb(drive)
                        failed_drives.add(drive)
                        continue
                    else:
                        key = key.encode()
                        print("[🔐] Key granted. Decrypting to virtual folder...")
                        virtual_path, decrypted_count = decrypt_usb_to_virtual_view(
                            drive, key, usb_id
                        )

                        # Log decryption activity
                        offline_manager.log_offline_activity(
                            "decryption_completed",
                            f"Decrypted {decrypted_count} files to virtual view",
                            usb_id,
                            machine_id,
                            "Auto Decrypt",
                            "success",
                            get_files_to_decrypt(drive),
                        )

                        # Get available virtual drive letter
                        virtual_drive = get_available_drive_letter()
                        if not virtual_drive:
                            print(f"[❌] USB {drive} - No available drive letters")
                            if os.path.exists(virtual_path):
                                shutil.rmtree(virtual_path)
                            continue

                        if map_virtual_drive(virtual_path, virtual_drive):
                            monitor = start_usb_monitor(
                                drive, virtual_path, key, usb_id, machine_id
                            )
                            usb_states[drive] = {
                                "usb_id": usb_id,
                                "virtual_path": virtual_path,
                                "virtual_drive": virtual_drive,  # <-- Store the letter
                                "observer": monitor,
                                "key": key,
                            }
                            print(f"[✅] USB {drive} - Mounted as {virtual_drive}")
                        else:
                            print(f"[❌] USB {drive} - Failed to map virtual drive")
                            if os.path.exists(virtual_path):
                                shutil.rmtree(virtual_path)

                except Exception as e:
                    print(f"[❌] Error processing drive {drive}: {e}")
                    import traceback

                    traceback.print_exc()
                    print("[❌] Ejecting USB due to error...")
                    eject_usb(drive)
                    failed_drives.add(drive)

            # Handle removed drives
            removed = []
            for drive, state in list(usb_states.items()):
                if drive not in connected:
                    print(f"[🔌] USB Removed: {drive}. Cleaning up...")
                    try:
                        if state.get("virtual_drive"):
                            unmap_virtual_drive(state["virtual_drive"])

                        # Stop file monitor
                        if state.get("observer"):
                            state["observer"].stop()
                            state["observer"].join(timeout=2)

                        # Clean up virtual folder
                        if state.get("virtual_path") and os.path.exists(
                            state["virtual_path"]
                        ):
                            shutil.rmtree(state["virtual_path"])
                            print(f"[🧹] Cleaned: {state['virtual_path']}")

                        # Log USB removal
                        offline_manager.log_offline_activity(
                            "usb_removed",
                            "USB disconnected, cleaned up virtual view",
                            state.get("usb_id", "unknown"),
                            get_machine_id(),
                            "Auto Decrypt",
                            "success",
                            [],
                        )

                    except Exception as e:
                        print(f"[⚠️] Cleanup error: {e}")
                    removed.append(drive)

            for drive in removed:
                del usb_states[drive]

            # Display periodic sync status
            stats = offline_manager.get_offline_stats()
            if stats["unsynced_logs"] > 0 or stats["unsynced_keys"] > 0:
                print(
                    f"[📊] Sync Status: {stats['unsynced_logs']} logs, {stats['unsynced_keys']} keys pending sync"
                )

            # Clear failed drives periodically
            if len(failed_drives) > 0:
                print(f"[ℹ️] Temporarily ignoring {len(failed_drives)} failed drives")
                time.sleep(30)
                failed_drives.clear()
            else:
                time.sleep(5)

        except KeyboardInterrupt:
            print("\n[🛑] Shutting down...")
            try:
                # Clean up all virtual drives
                for drive, state in usb_states.items():
                    print(f"[🧹] Cleaning up {drive}...")
                    if state.get("virtual_drive"):
                        unmap_virtual_drive(state["virtual_drive"])
                    if state.get("observer"):
                        state["observer"].stop()
                        state["observer"].join(timeout=2)
                    if state.get("virtual_path") and os.path.exists(
                        state["virtual_path"]
                    ):
                        shutil.rmtree(state["virtual_path"])
            except:
                pass
            break
        except Exception as e:
            print(f"[⚠️] Error in main loop: {e}")
            import traceback

            traceback.print_exc()
            time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    finally:
        offline_manager.stop_sync_thread()
        print("[👋] Decrypt agent stopped")
