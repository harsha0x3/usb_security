@echo off
REM Change to the script directory
cd /d "C:\Users\Administrator\Projects\usb_Security\Server"

REM Optional: Activate virtual environment if needed
REM call venv\Scripts\activate

REM Run the Python script and log output
python admin.py >> admin_log.txt 2>&1
