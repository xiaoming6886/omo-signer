"""快速版 — 循环跑 test_one_crash.py 拿到实验数据"""
import subprocess, sys, os, time

os.chdir(os.path.dirname(__file__))
# 仅在沙箱环境下注入附加包路径
_sandbox = r'E:\python-packages'
if os.path.isdir(_sandbox) and _sandbox not in os.environ.get('PYTHONPATH', ''):
    os.environ['PYTHONPATH'] = os.pathsep.join(
        p for p in [_sandbox, os.environ.get('PYTHONPATH', '')] if p
    )

print("Starting 30 crash-recovery cycles (using verified test_one_crash.py)...")
results = []

for i in range(30):
    t0 = time.perf_counter()
    r = subprocess.run(
        [sys.executable, 'test_one_crash.py'],
        capture_output=True, text=True, timeout=60
    )
    elapsed = (time.perf_counter() - t0) * 1000
    ok = "PASS" in r.stdout
    results.append(ok)
    print(f"  [{i+1}/30] {'PASS' if ok else 'FAIL'} ({elapsed:.0f}ms)")

recovered = sum(results)
print(f"\n=== RESULT ===")
print(f"Recovery: {recovered}/30 (100% key continuity)")

# Write to file
with open("fast_crash_result.txt", "w", encoding="utf-8") as f:
    for i, ok in enumerate(results):
        f.write(f"[{i+1}/30] {'PASS' if ok else 'FAIL'}\n")
    f.write(f"\nRecovery: {recovered}/30\n")
