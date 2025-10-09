# setup_offline.py - Initialize offline support for existing installations

import sys
import os
from db_utils import DBUtils


def setup_offline_support():
    """Set up offline support for existing USB security system"""
    print("🔄 Setting up offline support for USB Security System...")

    try:
        # Initialize database utilities
        db = DBUtils()

        # Update audit_logs table for offline support
        print("\n📋 Updating audit_logs table...")
        if db.update_audit_logs_table():
            print("✅ audit_logs table updated successfully")
        else:
            print("❌ Failed to update audit_logs table")
            return False

        # Create offline_keys table
        print("\n🔑 Creating offline_keys table...")
        try:
            import pymysql
            from config import DB_CONFIG

            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()

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
                    UNIQUE KEY unique_key (usb_serial_hash, machine_id, purpose),
                    INDEX idx_usb_machine (usb_serial_hash, machine_id),
                    INDEX idx_offline (offline_source),
                    INDEX idx_created (created_at)
                )
            """
            )

            conn.commit()
            conn.close()
            print("✅ offline_keys table created successfully")

        except Exception as e:
            print(f"❌ Failed to create offline_keys table: {e}")
            return False

        # Create offline data directory
        print("\n📁 Creating offline data directories...")
        offline_dirs = [r"C:\Temp\.decrypted_usb", "offline_data"]

        for directory in offline_dirs:
            try:
                os.makedirs(directory, exist_ok=True)
                print(f"✅ Created directory: {directory}")
            except Exception as e:
                print(f"⚠️ Could not create directory {directory}: {e}")

        # Verify installation
        print("\n🔍 Verifying installation...")

        # Check if required modules are available
        required_modules = [
            "sqlite3",
            "threading",
            "requests",
            "cryptography",
            "watchdog",
        ]

        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
                print(f"✅ {module} - Available")
            except ImportError:
                missing_modules.append(module)
                print(f"❌ {module} - Missing")

        if missing_modules:
            print(f"\n⚠️ Missing required modules: {', '.join(missing_modules)}")
            print("Please install them using:")
            print(f"pip install {' '.join(missing_modules)}")

        # Display setup completion
        print("\n" + "=" * 50)
        print("🎉 Offline Support Setup Complete!")
        print("=" * 50)
        print("\n📋 Next Steps:")
        print("1. Update your agents to use the new offline-enabled versions")
        print("2. Copy offline_manager.py to your project directory")
        print("3. Update app.py with the new sync endpoints")
        print("4. Update admin.py with the offline management routes")
        print("5. Add offline_admin.html template to your templates directory")
        print("6. Restart your agents and server")

        print("\n🔧 Usage:")
        print("- Agents will automatically use offline mode when server is unreachable")
        print("- Data syncs automatically when connection is restored")
        print("- View offline data at /admin/offline")
        print("- Download offline logs as CSV from admin panel")

        return True

    except Exception as e:
        print(f"❌ Setup failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def verify_offline_setup():
    """Verify that offline support is properly configured"""
    print("🔍 Verifying offline support setup...")

    checks = []

    # Check database tables
    try:
        db = DBUtils()
        import pymysql
        from config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Check audit_logs has offline_source column
        cursor.execute("DESCRIBE audit_logs")
        columns = [row[0] for row in cursor.fetchall()]
        if "offline_source" in columns:
            checks.append("✅ audit_logs.offline_source column exists")
        else:
            checks.append("❌ audit_logs.offline_source column missing")

        # Check offline_keys table exists
        cursor.execute("SHOW TABLES LIKE 'offline_keys'")
        if cursor.fetchone():
            checks.append("✅ offline_keys table exists")
        else:
            checks.append("❌ offline_keys table missing")

        conn.close()

    except Exception as e:
        checks.append(f"❌ Database check failed: {e}")

    # Check file existence
    files_to_check = ["offline_manager.py", "templates/offline_admin.html"]

    for file_path in files_to_check:
        if os.path.exists(file_path):
            checks.append(f"✅ {file_path} exists")
        else:
            checks.append(f"❌ {file_path} missing")

    # Display results
    print("\n📋 Verification Results:")
    for check in checks:
        print(f"  {check}")

    failed_checks = [c for c in checks if c.startswith("❌")]
    if failed_checks:
        print(f"\n⚠️ {len(failed_checks)} issues found")
        return False
    else:
        print("\n🎉 All checks passed! Offline support is ready.")
        return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        verify_offline_setup()
    else:
        setup_offline_support()
        print("\n🔍 Running verification...")
        verify_offline_setup()
