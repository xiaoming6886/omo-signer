# -*- coding: utf-8 -*-
"""OMO Signer 性能基准测试 — 论文 §5.2 数据生成脚本

前提：守护进程已启动（python src/omo_signing_daemon.py --daemon）
输出：Ed25519、SM2、ECDSA 三种算法的端到端签名延迟统计
"""

import time, subprocess, statistics, sys, os

def benchmark(agent: str, algo_flag: list[str], label: str, n: int = 100):
    """运行 n 次独立签名请求，返回延迟统计（ms）"""
    times = []
    print(f"\n{'='*60}")
    print(f"  {label}（{n} 次采样）")
    print(f"{'='*60}")
    
    for i in range(n):
        t0 = time.perf_counter()
        r = subprocess.run(
            [sys.executable, 'src/omo_signer.py', 'sign', agent, 'benchmark message'] + algo_flag,
            capture_output=True, text=True, timeout=30
        )
        t1 = time.perf_counter()
        if r.returncode == 0:
            elapsed = (t1 - t0) * 1000
            times.append(elapsed)
            if (i + 1) % 20 == 0:
                print(f"  [{i+1}/{n}] avg={statistics.mean(times):.1f}ms")
        else:
            print(f"  [{i+1}/{n}] FAILED: {r.stderr.strip()[:80]}")
    
    if not times:
        print(f"  ERROR: 所有请求失败，请检查守护进程是否已启动")
        return
    
    times.sort()
    print(f"\n  结果: avg={statistics.mean(times):.1f}ms "
          f"P50={statistics.median(times):.1f}ms "
          f"P95={times[int(len(times)*0.95)]:.1f}ms "
          f"n={len(times)}")
    return times

if __name__ == '__main__':
    agent = sys.argv[1] if len(sys.argv) > 1 else 'oracle'
    
    benchmark(agent, [], 'Ed25519', n=100)
    benchmark(agent, ['--sm2'], 'SM2', n=50)
    benchmark(agent, ['--ecdsa'], 'ECDSA', n=50)
    
    print(f"\n{'='*60}")
    print("  全部完成。将以上数据填入论文 §5.2 和 §5.6")
    print(f"{'='*60}")
