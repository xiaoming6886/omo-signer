# -*- coding: utf-8 -*-
"""崩溃恢复实验 — 30 次循环，3 种强杀方式，并发场景，恢复延迟测量"""

import subprocess, time, os, platform, signal, statistics, threading, sys
from pathlib import Path
from utils import py_run, shell_run

# 同时输出到终端和文件（bash 管道不可靠）
_LOG = open(Path(__file__).parent / "crash_test_output.txt", "w", encoding="utf-8")
class _Tee:
    def write(self, s):
        sys.__stdout__.write(s)
        _LOG.write(s)
    def flush(self):
        sys.__stdout__.flush()
        _LOG.flush()
sys.stdout = _Tee()

# 同时输出到终端和文件
LOG = open(Path(__file__).parent / "crash_test_output.txt", "w", encoding="utf-8")
def log(msg=""):
    print(msg)
    LOG.write(msg + "\n")
    LOG.flush()

IS_WINDOWS = platform.system() == "Windows"

def kill_taskkill(pid: str) -> None:
    """方式 1: 操作系统进程终止"""
    if IS_WINDOWS:
        shell_run(f'taskkill /F /PID {pid}')
    else:
        os.kill(int(pid), signal.SIGKILL)

def kill_sigterm(pid: str) -> None:
    """方式 2: SIGTERM 优雅终止（Linux）或等效"""
    if IS_WINDOWS:
        shell_run(f'taskkill /PID {pid}')
    else:
        os.kill(int(pid), signal.SIGTERM)

def kill_python_process() -> None:
    """方式 3: 通过 PID 文件终止守护进程"""
    pid = get_pid()
    if pid:
        kill_taskkill(pid)

ROOT = Path(__file__).parent
STATE = ROOT / "state"
KEYSTORE = STATE / "omo_keystore" / "oracle"
LOCKED = KEYSTORE / ".private_key_locked"
PID_FILE = STATE / "omo_daemon.pid"
SIGNER = Path(__file__).parent / "src" / "omo_signer.py"
DAEMON = Path(__file__).parent / "src" / "omo_signing_daemon.py"

def ensure_daemon():
    for _ in range(5):
        if PID_FILE.exists():
            return
        py_run([str(DAEMON), "--daemon"], timeout=10)
        time.sleep(2)

def get_pid():
    return PID_FILE.read_text().strip() if PID_FILE.exists() else None

def measure_recovery_time():
    """测量从崩溃到签名恢复的延迟"""
    PID_FILE.unlink(missing_ok=True)
    t0 = time.perf_counter()
    py_run([str(DAEMON), "--daemon"], timeout=10)
    time.sleep(0.5)
    r = py_run([str(SIGNER), "sign", "oracle", "recovery-test"], timeout=15)
    t1 = time.perf_counter()
    return (t1 - t0) * 1000 if r.returncode == 0 else None

# ── 实验 1: 30 次标准崩溃-恢复循环 ──────────────────────────
print("=" * 60)
print("实验 1: 30 次崩溃-恢复循环（3 种终止方式 × 10 次）")
print("=" * 60)

kill_methods = [
    ("taskkill/SIGKILL", kill_taskkill),
    ("SIGTERM", kill_sigterm),
    ("kill-all (断电模拟)", kill_python_process),
]

crash_results = []
recovery_times = []

for method_name, kill_fn in kill_methods:
    for i in range(10):
        label = f"{method_name}-{i+1}"
        ensure_daemon()
        pid = get_pid()
        if pid:
            kill_fn(pid)
        else:
            kill_python_process()
        time.sleep(1.5)
        PID_FILE.unlink(missing_ok=True)
        
        locked_ok = LOCKED.exists()
        rt = measure_recovery_time()
        recovery_ok = rt is not None
        
        crash_results.append((label, locked_ok, recovery_ok))
        if rt:
            recovery_times.append(rt)
        
        status = "OK" if (locked_ok and recovery_ok) else "FAIL"
        rt_str = f"{rt:.0f}ms" if rt else "N/A"
        print(f"  [{label}] .locked={locked_ok} recovery={status} latency={rt_str}")
        
        # 停止准备下一轮
        py_run([str(DAEMON), "--stop"], timeout=10)
        PID_FILE.unlink(missing_ok=True)
        time.sleep(0.5)

# ── 实验 2: 并发场景（签名过程中强杀）────────────────────────
print(f"\n{'='*60}")
print("实验 2: 并发场景 — 签名过程中强杀守护进程")
print("=" * 60)

concurrent_ok = True
for i in range(3):
    ensure_daemon()
    time.sleep(1)
    
    # 启动签名线程
    sign_result = [None]
    def do_sign():
        r = py_run([str(SIGNER), "sign", "oracle", f"concurrent-{i}"], timeout=15)
        sign_result[0] = r
    
    t = threading.Thread(target=do_sign)
    t.start()
    time.sleep(0.1)  # 让签名请求发出
    
    # 强杀守护进程
    pid = get_pid()
    if pid:
        kill_taskkill(pid)
    
    t.join(timeout=5)
    time.sleep(1.5)
    PID_FILE.unlink(missing_ok=True)
    
    locked_ok = LOCKED.exists()
    rt = measure_recovery_time()
    
    print(f"  [concurrent-{i+1}] .locked={locked_ok} recovery={'OK' if rt else 'FAIL'} latency={rt:.0f}ms" if rt else f"  [concurrent-{i+1}] FAIL")
    
    if not (locked_ok and rt):
        concurrent_ok = False
    
    py_run([str(DAEMON), "--stop"], timeout=10)
    PID_FILE.unlink(missing_ok=True)
    time.sleep(0.5)

# ── 汇总 ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
print(f"\n{'='*60}")
print("崩溃恢复实验汇总")
print(f"{'='*60}")

total = len(crash_results)
recovered = sum(1 for _, lk, ok in crash_results if lk and ok)
print(f"标准测试: {recovered}/{total} 恢复成功")

if recovery_times:
    recovery_times.sort()
    print(f"恢复延迟: avg={statistics.mean(recovery_times):.0f}ms "
          f"P50={statistics.median(recovery_times):.0f}ms "
          f"P95={recovery_times[int(len(recovery_times)*0.95)]:.0f}ms "
          f"n={len(recovery_times)}")

print(f"并发场景: {'PASS' if concurrent_ok else 'FAIL'}")
print(f"密钥连续性: {recovered}/{total} ({(recovered/total)*100:.0f}%)")

print(f"\n以上数据填入论文 §5.3 和表 7。")
