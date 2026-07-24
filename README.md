# OMO Signer — LLM 多智能体通信的独立签名基础设施

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![CI](https://github.com/xiaoming6886/omo-signer/actions/workflows/test.yml/badge.svg)](https://github.com/xiaoming6886/omo-signer/actions/workflows/test.yml)

OMO Signer 是一个面向 LLM 多智能体编排场景的**生产级密码学签名系统**。它将智能体间消息的身份声明从可伪造的纯文本文本变为密码学可验证的签名操作，同时保持对编排框架和密码算法的双重独立。

---

## 核心设计原则

| 原则 | 说明 |
|------|------|
| **框架独立** | 以标准 TCP 协议暴露签名能力，任何能建立 TCP 连接的进程均可使用，不依赖特定编排框架 |
| **算法独立** | 守护进程内签名接口统一抽象，Ed25519、SM2、ECDSA 在同一架构下共存 |
| **纯内存密钥托管** | 启动时从文件系统移除私钥（`.private_key_locked`），运行期间密钥仅存于进程内存 |
| **原子崩溃恢复** | 强制终止后密钥文件自动留存，重启后自动恢复，保证密钥连续性 |
| **哈希链审计日志** | 每条日志条目通过 SHA-256 链接至前一条目，任何篡改导致链断裂可检测 |
| **恒定时间令牌比较** | 使用 `hmac.compare_digest()` 抵抗时序侧信道攻击 |
| **Nonce 防重放** | 每次签名请求附带 128 位随机 nonce，守护进程拒绝重复 nonce，阻止重放攻击 |

## 系统架构

```
┌──────────────────────────────────────────────────────────┐
│              执行智能体-1 -2 -3  │ 编排器 │ 审查智能体-1 -2 -3 │
│                       │           │          │             │
│                       └─────┬─────┘──────────┘             │
│                             ▼                              │
│                   ┌─────────────────┐                      │
│                   │   签名客户端      │  omo_signer.py       │
│                   └────────┬────────┘                      │
│                            │ TCP (长度前缀 JSON 帧协议)      │
│                   ┌────────▼────────┐                      │
│                   │  签名守护进程     │  omo_signing_daemon  │
│                   │  (内存密钥托管)   │                      │
│                   └────────┬────────┘                      │
│                            │                               │
│                   ┌────────▼────────┐                      │
│                   │    密钥存储      │  磁盘 (NORMAL/LOCKED) │
│                   └─────────────────┘                      │
└──────────────────────────────────────────────────────────┘
```

## 快速开始

```bash
# 安装
pip install git+https://github.com/xiaoming6886/omo-signer.git

# 或本地开发安装
git clone https://github.com/xiaoming6886/omo-signer.git
cd omo-signer && pip install -e .

# 生成密钥
omo-signer generate oracle
omo-signer generate oracle --sm2
omo-signer generate oracle --ecdsa

# 启动守护进程
omo-daemon --daemon

# 签名
omo-signer sign oracle "待签名消息"
omo-signer sign oracle "待签名消息" --sm2
omo-signer sign oracle "待签名消息" --ecdsa

# 验证
omo-signer verify oracle "待签名消息" <签名>

# 帮助
omo-signer --help
omo-signer sign --help
```

## 性能测试与验证

以下测试均可在本仓库中执行。前提：已启动守护进程。

```bash
# 签名性能测试（Ed25519/SM2/ECDSA 延迟分布）
python experiments.py

# 消融实验（五配置逐项测试）
python ablation_test.py

# 崩溃恢复测试（强杀-重启循环）
python crash_test.py

# 跨框架集成演示（LangGraph）
python examples/langgraph_demo.py

# 单元测试（28 个用例，8 个测试类）
python -m pytest tests/ -v
```

在同一软硬件配置下运行应得到一致的结果。完整设计分析见配套论文《面向 LLM 多智能体通信的签名认证架构》（《网络与信息安全学报》，2026）。

## 生产部署

### Docker（推荐）

```bash
# 构建并启动
docker compose up -d

# 检查状态
docker exec omo-signer omo-signer ping

# 生成密钥
docker exec omo-signer omo-signer generate oracle
docker exec omo-signer omo-signer generate oracle --sm2

# 签名
docker exec omo-signer omo-signer sign oracle "hello world"
```

### 手动部署

```powershell
scripts\setup.bat
```

该脚本将自动安装依赖、为所有智能体生成三算法密钥对并启动守护进程。

### 手动部署（跨平台）

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 为每个智能体生成密钥（至少生成一个）
python src/omo_signer.py generate <agent-name>
python src/omo_signer.py generate <agent-name> --sm2
python src/omo_signer.py generate <agent-name> --ecdsa

# 3. 将守护进程注册为系统服务（可选）
# Windows: 使用 NSSM 或 sc.exe
# Linux: 使用 systemd 单元文件

# 4. 在编排框架中集成
# 任何能执行子进程并建立 TCP 连接的框架均可使用
# 示例：在 agent 的消息发送代码中插入
#   subprocess.run(["python", "omo_signer.py", "sign", agent_name, message])
```

### 集成到现有编排框架

OMO Signer 对编排框架的唯一要求是能够执行子进程。以下以 OpenCode 为例：

```python
import subprocess, json

def sign_agent_output(agent_name: str, message: str) -> dict:
    """在 agent 输出中附加签名"""
    result = subprocess.run(
        ["python", "src/omo_signer.py", "sign", agent_name, message],
        capture_output=True, text=True, timeout=15
    )
    signature = result.stdout.strip()
    return {"agent": agent_name, "message": message, "signature": signature}

def verify_agent_output(payload: dict) -> bool:
    """验证接收到的 agent 输出"""
    result = subprocess.run(
        ["python", "src/omo_signer.py", "verify",
         payload["agent"], payload["message"], payload["signature"]],
        capture_output=True, text=True
    )
    return result.returncode == 0
```

LangGraph 集成示例见 `examples/langgraph_demo.py`。

## 贡献

欢迎提交 Issue 和 Pull Request。在提交 PR 前请确保：

1. 所有现有测试通过：`python -m pytest tests/ -v`
2. 新功能包含对应的单元测试
3. 代码风格与现有代码保持一致

安全问题请通过私下渠道报告，勿在公开 Issue 中披露。

## 项目结构

```
omo-signer/
├── src/
│   ├── omo_signer.py             命令行签名客户端
│   ├── omo_signing_daemon.py     TCP 密钥托管守护进程
│   └── signing_provider.py       算法签名抽象接口（SigningProvider）
├── tests/
│   └── test_omo_signer.py        28 个单元测试（8 个测试类）
├── experiments.py                签名性能基准测试
├── ablation_test.py              消融实验脚本
├── crash_test.py                 崩溃恢复测试脚本
├── examples/
│   └── langgraph_demo.py         LangGraph 跨框架集成演示
├── scripts/
│   └── setup.bat                 一键部署脚本（Windows）
├── config/
│   └── omo-signer.yaml           配置模板
├── requirements.txt
└── README.md
```

## 安全模型

### 第一层：密码学保证
- 消息伪造 → Ed25519/SM2/ECDSA 不可伪造性
- 消息篡改 → 任意比特修改导致验签失败
- 密钥文件隐藏 → `.private_key_locked` 重命名保护

### 第二层：审计检测
- 未授权签名 → 哈希链审计日志可追溯
- 日志篡改 → 链断裂可检测
- 令牌滥用 → 每次操作记录时间戳与身份

### 第三层：操作系统层面的固有局限
- 同用户进程可读取守护进程内存（需 HSM/TEE 硬件防护）
- 同用户进程可修改源代码或删除审计文件

## 依赖

- Python 3.10+
- [PyNaCl](https://pynacl.readthedocs.io/) ≥ 1.5.0（Ed25519）
- [gmssl](https://github.com/duanhongyi/gmssl) ≥ 3.2.0（SM2）
- [ecdsa](https://github.com/tlsfuzn/python-ecdsa) ≥ 0.19.0（ECDSA）

## 引用

```bibtex
@article{hao2026omo,
  title   = {面向 LLM 多智能体通信的签名认证架构},
  author  = {郝禹铭},
  journal = {网络与信息安全学报},
  year    = {2026},
  note    = {审稿中}
}
```

## 许可证

MIT License. 详见 [LICENSE](LICENSE)。
