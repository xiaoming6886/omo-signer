import subprocess, time, sys
from pathlib import Path

ROOT = Path(__file__).parent
SIGNER = str(ROOT / "src" / "omo_signer.py")
DAEMON = str(ROOT / "src" / "omo_signing_daemon.py")
PID_FILE = ROOT / "state" / "omo_daemon.pid"
LOCKED = ROOT / "state" / "omo_keystore" / "oracle" / ".private_key_locked"

def py_run(args, timeout=15):
    return subprocess.run([sys.executable] + args, capture_output=True, text=True, timeout=timeout)

# 1. Start daemon
print("1. Starting daemon...")
py_run([DAEMON, "--daemon"], timeout=15)
time.sleep(2)
print(f"   PID file: {PID_FILE.exists()}")

# 2. Sign
print("2. Signing before crash...")
r = py_run([SIGNER, "sign", "oracle", "pre-crash"], timeout=15)
print(f"   rc={r.returncode} {'OK' if r.returncode == 0 else r.stderr.strip()[:60]}")

# 3. Kill (taskkill uses numeric PID only, no Chinese)
print("3. Killing daemon...")
pid = PID_FILE.read_text().strip() if PID_FILE.exists() else None
if pid:
    subprocess.run(f"taskkill /F /PID {pid}", shell=True, timeout=10)
time.sleep(1.5)
PID_FILE.unlink(missing_ok=True)

# 4. Check locked
print(f"4. .locked exists: {LOCKED.exists()}")

# 5. Restart + sign
print("5. Restarting and signing...")
py_run([DAEMON, "--daemon"], timeout=15)
time.sleep(2)
r = py_run([SIGNER, "sign", "oracle", "post-crash"], timeout=15)
print(f"   rc={r.returncode} {'OK' if r.returncode == 0 else r.stderr.strip()[:60]}")

print(f"\n6. Recovery: {'PASS' if r.returncode == 0 else 'FAIL'}")
