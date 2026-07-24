# -*- coding: utf-8 -*-
"""项目公共工具 — 中文路径安全 subprocess 调用

用法: from utils import py_run, shell_run
      py_run(["src/omo_signer.py", "sign", "oracle", "msg"])  # Python 脚本
      shell_run("taskkill /F /PID 12345")                     # 系统命令（仅英文参数）
"""
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).parent

def py_run(args: list[str], timeout: int = 30, cwd: str | Path | None = None):
    """运行 Python 脚本，自动处理中文路径（shell=False）"""
    if cwd is None:
        cwd = ROOT
    return subprocess.run(
        [sys.executable] + args,
        capture_output=True, text=True, timeout=timeout,
        cwd=str(cwd)
    )

def shell_run(cmd: str, timeout: int = 10):
    """运行系统命令 — 仅用于不含中文路径的简单命令"""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
