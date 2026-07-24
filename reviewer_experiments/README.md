# 审稿人实验复现指南

本目录包含论文《面向 LLM 多智能体通信的签名认证架构》中所有实验的可复现代码。
论文投稿《网络与信息安全学报》（CCF-B），审稿中。

## 环境要求

- Python 3.10+
- 操作系统：Windows / Linux / macOS
- 硬件：无特殊要求（论文数据在 i7-14650HX / 16GB RAM 上采集）

## 快速开始（3 步复现全部实验）

```bash
# 步骤 1：安装项目
cd ..  # 回到 omo-signer 根目录
pip install -e .

# 步骤 2：生成测试密钥并启动守护进程
omo-signer generate oracle
omo-signer generate oracle --sm2
omo-signer generate oracle --ecdsa
omo-daemon --daemon

# 步骤 3：运行实验
cd reviewer_experiments
python run_all.py
```

## 实验清单（论文 §5 对应）

| 实验 | 脚本 | 论文位置 | 预期输出 |
|------|------|---------|---------|
| 签名性能 | `run_all.py` (自动) | §5.2 | Ed25519 avg≈85ms, SM2 avg≈93ms, ECDSA avg≈82ms |
| 算法独立性 | `run_all.py` (自动) | §5.6 | 三种算法延迟处于相同量级 |
| 崩溃恢复 | `crash_test.py` | §5.3 | 43/43 密钥连续性 |
| 消融实验 | `ablation_test.py` | §5.4 | 五配置安全退化数据 |
| 单元测试 | `cd .. && python -m pytest tests/ -v` | §5.5 | 26 tests, 25 passed, 1 skipped |

## 注意事项

1. 性能数据因硬件差异可能与论文报告值有 ±10ms 波动，属于正常范围
2. 守护进程需在实验期间保持运行（`omo-daemon --daemon`）
3. 实验结束后可通过 `omo-daemon --stop` 优雅关闭

## 论文-代码对照

| 论文声称 | 代码验证 |
|---------|---------|
| Ed25519 84.8ms, n=100 | `run_all.py` 中 `benchmark_ed25519()` |
| SM2 92.5ms | `run_all.py` 中 `benchmark_sm2()` |
| ECDSA 81.9ms, n=50 | `run_all.py` 中 `benchmark_ecdsa()` |
| 5/5 崩溃恢复 | `crash_test.py` 5 次独立循环 |
| 消融五配置 | `ablation_test.py` 运行 (c)(d) 实际测试 |
| 26 单元测试 | `pytest tests/ -v` |
