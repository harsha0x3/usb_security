# Client\usb_gui_froce_dycrypt.py

import os
import time
import socket
import requests
import hashlib
import wmi
from cryptography.fernet import Fernet
import ctypes
from ctypes import wintypes
import tkinter as tk
from tkinter import messagebox, simpledialog
from colorama import init, Fore, Style
from dotenv import load_dotenv

load_dotenv()

init(autoreset=True)  # for terminal colors

# === Config ===
SERVER_URL = "https://usbapp.titan.in"
LOGIN_URL = "https://usbapp.titan.in"
ENCRYPTED_EXT = ".locked"

# Request settings
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2


# === Get USB Serial ===
def get_usb_hardware_serial(drive_letter):
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
                            return hashlib.sha256(serial.encode()).hexdigest()
        print(f"[⚠️] USB hardware serial not found for drive {drive_letter}")
        return None
    except Exception as e:
        print(f"[⚠️] Error getting USB serial for {drive_letter}: {e}")
        return None


def get_machine_id():
    return socket.gethostname()


def decrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        encrypted_data = file.read()
    decrypted = fernet.decrypt(encrypted_data)
    original_path = filepath.replace(ENCRYPTED_EXT, "")
    with open(original_path, "wb") as file:
        file.write(decrypted)
    os.remove(filepath)


def decrypt_usb(usb_path, key):
    decrypted_count = 0
    failed_count = 0

    for root, _, files in os.walk(usb_path):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath.endswith(ENCRYPTED_EXT):
                try:
                    decrypt_file(filepath, key)
                    print(Fore.GREEN + f"[🔓] Decrypted: {filepath}")
                    decrypted_count += 1
                except Exception as e:
                    print(Fore.YELLOW + f"[⚠️] Failed to decrypt {filepath}: {e}")
                    failed_count += 1

    print(f"[📊] Decryption complete: {decrypted_count} success, {failed_count} failed")
    return decrypted_count, failed_count


def get_files_to_decrypt(usb_path):
    files = []
    try:
        for root, _, filenames in os.walk(usb_path):
            for file in filenames:
                if file.endswith(ENCRYPTED_EXT):
                    files.append(file)
    except Exception as e:
        print(f"[⚠️] Error scanning files in {usb_path}: {e}")
    return files


def get_decryption_key(device_id, machine_id, auth_token, usb_path):
    files = get_files_to_decrypt(usb_path)

    for attempt in range(MAX_RETRIES):
        try:
            data = {
                "usb_serial_hash": device_id,
                "machine_id": machine_id,
                "purpose": "GUI Decrypt",
                "files": files,
            }

            # Fixed headers and URL construction
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {auth_token}",
                "User-Agent": "USB-GUI-Decrypt/1.0",
            }

            # Construct full URL properly
            base_url = SERVER_URL.rstrip("/")
            endpoint_url = f"{base_url}/authorize"

            print(
                f"[📡] Attempt {attempt + 1}/{MAX_RETRIES}: Requesting decrypt key from {endpoint_url}"
            )
            print(f"[📋] Request data: {data}")

            response = requests.post(
                endpoint_url,
                json=data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=True,
            )

            print(f"[📡] Server responded: {response.status_code}")
            print(f"[📝] Response text: {response.text}")

            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get("status") == "granted":
                        print(Fore.GREEN + "[✅] Decryption key granted")
                        return result.get("key")
                    else:
                        print(Fore.RED + f"[❌] Access denied: {result}")
                        return None
                except ValueError as e:
                    print(Fore.RED + f"[❌] Invalid JSON response: {e}")
                    return None

            elif response.status_code == 404:
                print(Fore.RED + "[❌] 404 Not Found - Check server URL and endpoint")
                return None

            elif response.status_code == 406:
                print(
                    Fore.RED
                    + "[❌] 406 Not Acceptable - Check headers and CSP settings"
                )
                return None

            elif response.status_code == 401:
                print(Fore.RED + "[❌] 401 Unauthorized - Token may be expired")
                return None

            elif response.status_code == 429:
                print(Fore.YELLOW + "[⚠️] Rate limit exceeded - waiting before retry")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                return None

            elif response.status_code in [500, 502, 503, 504]:
                print(
                    Fore.YELLOW
                    + f"[⚠️] Server error {response.status_code} - retrying..."
                )
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                    continue
                return None

            else:
                print(
                    Fore.RED
                    + f"[❌] Unexpected server response: {response.status_code}"
                )
                return None

        except requests.exceptions.Timeout:
            print(
                Fore.YELLOW
                + f"[⚠️] Request timeout (attempt {attempt + 1}/{MAX_RETRIES})"
            )
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue

        except requests.exceptions.ConnectionError as e:
            print(Fore.RED + f"[❌] Connection error: {e}")
            if attempt < MAX_RETRIES - 1:
                print("[🔄] Retrying connection...")
                time.sleep(RETRY_DELAY)
                continue

        except Exception as e:
            print(Fore.RED + f"[❌] Unexpected error: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                continue

    print(Fore.RED + "[❌] All retry attempts failed")
    return None


def get_connected_usb():
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


# === GUI Login ===
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔑 Secure USB Login")
        self.root.geometry("350x260")
        self.root.configure(bg="#f0f4f7")
        self.root.resizable(False, False)

        self.token = None

        title = tk.Label(
            root,
            text="🔑 USB Decryption Login",
            bg="#f0f4f7",
            fg="#333",
            font=("Helvetica", 14, "bold"),
        )
        title.pack(pady=10)

        tk.Label(root, text="Username:", bg="#f0f4f7", fg="#555").pack()
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack(pady=2)

        tk.Label(root, text="Password:", bg="#f0f4f7", fg="#555").pack()
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack(pady=2)

        tk.Label(root, text="MFA Code (TOTP):", bg="#f0f4f7", fg="#555").pack()
        self.mfa_entry = tk.Entry(root, width=30)
        self.mfa_entry.pack(pady=2)

        login_btn = tk.Button(
            root,
            text="🔐 Login",
            command=self.login,
            bg="#4CAF50",
            fg="white",
            width=20,
            font=("Helvetica", 10, "bold"),
        )
        login_btn.pack(pady=12)

        # Bind Enter key to login
        root.bind("<Return>", lambda event: self.login())

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        mfa_code = self.mfa_entry.get().strip()

        if not username or not password or not mfa_code:
            messagebox.showerror(
                "⚠ Input Error", "Please enter username, password, and MFA code."
            )
            return

        try:
            # Construct login URL properly
            base_url = LOGIN_URL.rstrip("/") if LOGIN_URL else SERVER_URL.rstrip("/")
            login_endpoint = f"{base_url}/login"

            print(f"[📡] Attempting login to: {login_endpoint}")

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "USB-GUI-Decrypt/1.0",
            }

            response = requests.post(
                login_endpoint,
                json={"username": username, "password": password, "totp": mfa_code},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=True,
            )

            print(f"[📡] Login response: {response.status_code}")
            print(f"[📝] Response: {response.text}")

            data = response.json()

            if response.status_code == 200:
                if "token" in data:
                    self.token = data["token"]
                    messagebox.showinfo("✅ Success", "Login successful with MFA!")
                    self.root.destroy()
                elif data.get("mfa_required"):
                    messagebox.showwarning(
                        "🔐 MFA Required", "Please enter your MFA code."
                    )
                else:
                    messagebox.showerror(
                        "❌ Login Failed", data.get("error", "Unknown error")
                    )
            else:
                error_msg = data.get("error", f"HTTP {response.status_code}")
                messagebox.showerror("❌ Login Failed", error_msg)

        except requests.exceptions.ConnectionError:
            messagebox.showerror(
                "⚠️ Network Error",
                "Could not connect to server. Check your internet connection and server URL.",
            )
        except requests.exceptions.Timeout:
            messagebox.showerror("⚠️ Timeout", "Request timed out. Please try again.")
        except ValueError:
            messagebox.showerror(
                "⚠️ Invalid Response", "Server returned invalid response format."
            )
        except Exception as e:
            messagebox.showerror("⚠️ Error", f"Unexpected error: {str(e)}")


# === Decryption Mode ===
def ask_decryption_mode():
    mode_window = tk.Tk()
    mode_window.title("🔧 Choose Decryption Mode")
    mode_window.geometry("300x180")
    mode_window.configure(bg="#eef2f5")
    mode_window.resizable(False, False)

    choice = {"mode": None}

    def choose_auto():
        choice["mode"] = "auto"
        mode_window.destroy()

    def choose_manual():
        choice["mode"] = "manual"
        mode_window.destroy()

    tk.Label(
        mode_window,
        text="Select Decryption Mode:",
        bg="#eef2f5",
        fg="#222",
        font=("Arial", 12, "bold"),
    ).pack(pady=15)
    tk.Button(
        mode_window,
        text="🔐 Auto (Server Key)",
        width=25,
        bg="#007ACC",
        fg="white",
        command=choose_auto,
    ).pack(pady=5)
    tk.Button(
        mode_window,
        text="🔑 Manual (Enter Key)",
        width=25,
        bg="#FFA500",
        fg="white",
        command=choose_manual,
    ).pack(pady=5)

    mode_window.mainloop()
    return choice["mode"]


# === Main USB Monitoring ===
def start_decryption_flow(auth_token, mode):
    print(Fore.CYAN + "🔍 Waiting for USB device...")

    if not SERVER_URL:
        print(Fore.RED + "[❌] SERVER_URL not configured in .env file")
        return

    print(f"[ℹ️] Server URL: {SERVER_URL}")
    print(f"[🔧] Mode: {mode}")

    seen = set()
    failed_drives = set()

    while True:
        try:
            usb_drives = get_connected_usb()
            new_drives = [
                d for d in usb_drives if d not in seen and d not in failed_drives
            ]

            if new_drives:
                for drive in new_drives:
                    print(Fore.GREEN + f"[🟢] USB Detected: {drive}")
                    try:
                        device_id = get_usb_hardware_serial(drive)
                        if not device_id:
                            print(
                                f"[⚠️] Could not get hardware serial for {drive}, skipping..."
                            )
                            failed_drives.add(drive)
                            continue

                        machine_id = get_machine_id()
                        print(f"[🧬] USB ID: {device_id}")
                        print(f"[🖥️] Machine ID: {machine_id}")

                        # Check if there are encrypted files
                        encrypted_files = get_files_to_decrypt(drive)
                        if not encrypted_files:
                            print(Fore.YELLOW + "[ℹ️] No encrypted files found on USB")
                            seen.add(drive)
                            continue

                        print(f"[📂] Found {len(encrypted_files)} encrypted files")

                        if mode == "auto":
                            key = get_decryption_key(
                                device_id, machine_id, auth_token, drive
                            )
                            if key:
                                print(Fore.BLUE + "[🔑] Key received. Decrypting...")
                                success_count, fail_count = decrypt_usb(
                                    drive, key.encode()
                                )
                                if success_count > 0:
                                    print(
                                        Fore.GREEN
                                        + f"[✅] Decryption complete: {success_count} files"
                                    )
                                    messagebox.showinfo(
                                        "✅ Success",
                                        f"Successfully decrypted {success_count} files!",
                                    )
                                else:
                                    print(Fore.RED + "[❌] No files were decrypted")
                                    messagebox.showerror(
                                        "❌ Error", "Failed to decrypt any files"
                                    )
                            else:
                                print(Fore.RED + "[❌] Server denied access or failed")
                                messagebox.showerror(
                                    "❌ Access Denied",
                                    "Server denied access or authorization failed",
                                )

                        elif mode == "manual":
                            root = tk.Tk()
                            root.withdraw()
                            manual_key = simpledialog.askstring(
                                "Manual Key Entry",
                                f"Enter decryption key for USB {drive}:\n({len(encrypted_files)} encrypted files found)",
                                show="*",
                            )
                            root.destroy()

                            if manual_key:
                                try:
                                    success_count, fail_count = decrypt_usb(
                                        drive, manual_key.encode()
                                    )
                                    if success_count > 0:
                                        print(
                                            Fore.GREEN
                                            + f"[✅] Manual decryption complete: {success_count} files"
                                        )
                                        messagebox.showinfo(
                                            "✅ Success",
                                            f"Successfully decrypted {success_count} files with manual key!",
                                        )
                                    else:
                                        print(
                                            Fore.RED + "[❌] Manual decryption failed"
                                        )
                                        messagebox.showerror(
                                            "❌ Error",
                                            "Failed to decrypt files. Check if the key is correct.",
                                        )
                                except Exception as e:
                                    print(
                                        Fore.RED + f"[❌] Manual decryption error: {e}"
                                    )
                                    messagebox.showerror(
                                        "❌ Decryption Error",
                                        f"Decryption failed: {str(e)}",
                                    )
                            else:
                                print(Fore.YELLOW + "[🚫] No manual key entered")

                    except Exception as e:
                        print(Fore.RED + f"[❌] Error processing USB {drive}: {e}")
                        import traceback

                        traceback.print_exc()
                        failed_drives.add(drive)

                    finally:
                        seen.add(drive)

            # Clear failed drives after some time
            if len(failed_drives) > 0:
                print(f"[ℹ️] Temporarily ignoring {len(failed_drives)} failed drives")
                time.sleep(30)
                failed_drives.clear()
            else:
                time.sleep(5)

        except KeyboardInterrupt:
            print(Fore.CYAN + "\n[🛑] Shutting down...")
            break
        except Exception as e:
            print(Fore.RED + f"[⚠️] Error in main loop: {e}")
            import traceback

            traceback.print_exc()
            time.sleep(5)


# === Entry Point ===
if __name__ == "__main__":
    # Validate configuration
    if not SERVER_URL:
        print(Fore.RED + "[❌] SERVER_URL not configured in .env file")
        print("Please set SERVER_URL=https://usbapp.titan.in in your .env file")
        input("Press Enter to exit...")
        exit(1)

    if not LOGIN_URL:
        print(Fore.YELLOW + "[⚠️] LOGIN_URL not set, using SERVER_URL for login")

    print(f"[ℹ️] Server URL: {SERVER_URL}")
    print(f"[ℹ️] Login URL: {LOGIN_URL or SERVER_URL}")

    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()

    if app.token:
        mode = ask_decryption_mode()
        if mode:
            try:
                start_decryption_flow(app.token, mode)
            except KeyboardInterrupt:
                print(Fore.CYAN + "\n[🛑] Application stopped by user")
            except Exception as e:
                print(Fore.RED + f"[❌] Application error: {e}")
                input("Press Enter to exit...")
        else:
            print(Fore.YELLOW + "[ℹ️] No decryption mode selected")
    else:
        print(Fore.YELLOW + "[ℹ️] Login cancelled or failed")
