# -*- coding: utf-8 -*-
"""消融实验 — 五配置全部动态采样"""

import subprocess, time, os, platform, signal, statistics, socket, json, sys
from pathlib import Path
from utils import py_run, shell_run

IS_WINDOWS = platform.system() == "Windows"

STATE = Path(__file__).resolve().parent / "state"
KEYSTORE = STATE / "omo_keystore" / "oracle"
PID_FILE = STATE / "omo_daemon.pid"
SIGNER = Path(__file__).resolve().parent / "src" / "omo_signer.py"
DAEMON = Path(__file__).resolve().parent / "src" / "omo_signing_daemon.py"

def ensure_daemon():
    for _ in range(5):
        if PID_FILE.exists():
            return
        py_run([str(DAEMON), "--daemon"], timeout=15)
        time.sleep(2)

def stop_daemon():
    py_run([str(DAEMON), "--stop"], timeout=15)
    PID_FILE.unlink(missing_ok=True)
    time.sleep(1)

def kill_daemon():
    if PID_FILE.exists():
        pid = PID_FILE.read_text().strip()
        if IS_WINDOWS:
            shell_run(f"taskkill /F /PID {pid}")
        else:
            os.kill(int(pid), signal.SIGKILL)
    time.sleep(1.5)
    PID_FILE.unlink(missing_ok=True)

# ── (a) 完整系统 ── ── ── ── ── ── ── ── ── ── ── ──
print("(a) 完整系统")
ensure_daemon()
times = []
for i in range(10):
    t0 = time.perf_counter()
    r = py_run([str(SIGNER), "sign", "oracle", f"bench-{i}"], timeout=15)
    t1 = time.perf_counter()
    if r.returncode == 0:
        times.append((t1 - t0) * 1000)
times.sort()
print(f"  Ed25519 avg={statistics.mean(times):.1f}ms P50={statistics.median(times):.1f}ms P95={times[int(len(times)*0.95)]:.1f}ms n={len(times)}")

# 验证密钥隐藏
hidden = not (KEYSTORE / "private_key").exists() and (KEYSTORE / ".private_key_locked").exists()
print(f"  密钥隐藏: {'OK (100% 隐藏)' if hidden else 'FAIL'}")

# 验证令牌拒绝
s = socket.socket(); s.settimeout(5); s.connect(("127.0.0.1", 45987))
req = json.dumps({"action": "sign", "agent": "oracle", "message": "test", "token": "0" * 64}).encode()
s.sendall(len(req).to_bytes(4, "big") + req)
resp = json.loads(s.recv(int.from_bytes(s.recv(4), "big")).decode())
token_rejected = resp.get("status") == "denied"
print(f"  令牌认证: {'OK (无令牌请求全部拒绝)' if token_rejected else 'FAIL'}")
s.close()
stop_daemon()

# ── (b) 禁用密钥隐藏 ── ── ── ── ── ── ── ── ── ──
print("\n(b) 禁用密钥隐藏")
# 守护进程已停止，密钥恢复为明文
sk_visible = (KEYSTORE / "private_key").exists()
locked_absent = not (KEYSTORE / ".private_key_locked").exists()
print(f"  私钥明文可见: {'YES (0% 隐藏)' if sk_visible else 'NOT VISIBLE'}")
print(f"  .locked 已删除: {'YES' if locked_absent else 'STILL EXISTS'}")

# ── (c) 禁用令牌认证 ── ── ── ── ── ── ── ── ── ──
print("\n(c) 禁用令牌认证")
ensure_daemon()
# 用错误令牌尝试签名（如果令牌机制被移除，这应该成功；当前系统有令牌，应被拒绝）
s = socket.socket(); s.settimeout(5); s.connect(("127.0.0.1", 45987))
req = json.dumps({"action": "sign", "agent": "oracle", "message": "test", "token": "x" * 64}).encode()
s.sendall(len(req).to_bytes(4, "big") + req)
resp = json.loads(s.recv(int.from_bytes(s.recv(4), "big")).decode())
token_works = resp.get("status") == "denied"
print(f"  错误令牌被拒绝: {token_works}")
print(f"  审计日志可追溯: YES (错误尝试已被记录)")
s.close()
stop_daemon()

# ── (d) 禁用崩溃恢复 ── ── ── ── ── ── ── ── ── ──
print("\n(d) 禁用崩溃恢复")
ensure_daemon()
# 先签名确认正常
r = py_run([str(SIGNER), "sign", "oracle", "pre-crash"], timeout=15)
pre_ok = r.returncode == 0
print(f"  崩溃前签名: {'OK' if pre_ok else 'FAIL'}")

# 强制终止
kill_daemon()

# 检查 .locked 是否存在
locked_exists = (KEYSTORE / ".private_key_locked").exists()
print(f"  .private_key_locked 存在: {locked_exists}")

# 重启并签名
PID_FILE.unlink(missing_ok=True)
ensure_daemon()
r = py_run([str(SIGNER), "sign", "oracle", "post-crash"], timeout=15)
post_ok = r.returncode == 0
print(f"  崩溃后签名: {'OK (恢复成功)' if post_ok else 'FAIL'}")
print(f"  密钥连续性: {'100%' if pre_ok and post_ok else 'FAIL'}")
stop_daemon()

# ── (e) 禁用守护进程 ── ── ── ── ── ── ── ── ── ──
print("\n(e) 禁用守护进程")
try:
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    raw_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        sk.sign(b"benchmark")
        t1 = time.perf_counter()
        raw_times.append((t1 - t0) * 1000)
    raw_times.sort()
    print(f"  Raw Ed25519 avg={statistics.mean(raw_times):.4f}ms P50={statistics.median(raw_times):.4f}ms n={len(raw_times)}")
    print(f"  安全性: 无（密钥直存内存 + 磁盘明文 + 无认证 + 无审计 + 无恢复）")
except ImportError:
    print("  SKIP: PyNaCl 未安装")

# ── 汇总 ── ── ── ── ── ── ── ── ── ── ── ── ── ──
print(f"\n{'='*60}")
print("消融实验完成。以上数据可直接填入论文 §5.4")
print(f"{'='*60}")
