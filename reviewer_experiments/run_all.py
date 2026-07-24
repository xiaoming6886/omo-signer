# -*- coding: utf-8 -*-
"""论文 §5 全部实验一键复现脚本 — 审稿人专用

运行前提：已安装 omo-signer 包，守护进程已启动 (omo-daemon --daemon)
运行命令：python run_all.py
"""

import time, subprocess, statistics, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))

def benchmark(label: str, cmd_suffix: list[str], n: int) -> dict:
    """运行 n 次签名请求，返回统计"""
    times = []
    print(f"\n{'='*60}")
    print(f"  {label}（n={n}）")
    print(f"{'='*60}")
    for i in range(n):
        t0 = time.perf_counter()
        r = run([sys.executable, str(ROOT / "src" / "omo_signer.py"), "sign", "oracle", "benchmark"] + cmd_suffix)
        t1 = time.perf_counter()
        if r.returncode == 0:
            times.append((t1 - t0) * 1000)
        if (i + 1) % max(1, n // 5) == 0:
            print(f"  [{i+1}/{n}] running avg={statistics.mean(times):.1f}ms" if times else f"  [{i+1}/{n}] ...")
    if not times:
        print("  ERROR: 所有请求失败")
        return {}
    times.sort()
    result = {"avg": round(statistics.mean(times), 1), "P50": round(statistics.median(times), 1),
              "P95": round(times[int(len(times)*0.95)], 1), "n": len(times)}
    print(f"  结果: avg={result['avg']}ms P50={result['P50']}ms P95={result['P95']}ms")
    return result

if __name__ == "__main__":
    print("OMO Signer — 实验复现脚本")
    print(f"论文：面向 LLM 多智能体通信的签名认证架构")
    print(f"对应：§5.2 签名性能 / §5.6 算法独立性\n")

    # 验证守护进程在运行
    r = run([sys.executable, str(ROOT / "src" / "omo_signer.py"), "ping"])
    if r.returncode != 0:
        print("错误: 守护进程未运行。请先执行: omo-daemon --daemon")
        sys.exit(1)
    print("守护进程状态: OK\n")

    results = {}
    results["Ed25519"] = benchmark("Ed25519", [], n=100)
    results["SM2"]     = benchmark("SM2", ["--sm2"], n=20)
    results["ECDSA"]   = benchmark("ECDSA", ["--ecdsa"], n=50)

    print(f"\n{'='*60}")
    print("  全部完成。结果汇总：")
    for algo, r in results.items():
        if r:
            print(f"  {algo}: avg={r['avg']}ms P50={r['P50']}ms P95={r['P95']}ms n={r['n']}")
    print(f"{'='*60}")
    print("\n注：因硬件差异，结果与论文报告值（Ed25519 84.8ms, SM2 92.5ms, ECDSA 81.9ms）可能有 ±10ms 波动，属正常范围。")
