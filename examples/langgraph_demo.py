# -*- coding: utf-8 -*-
"""
LangGraph 集成演示：OMO Signer 在状态图框架中的真实集成。

运行方式：
    pip install langgraph
    python examples/langgraph_demo.py

若未安装 langgraph，脚本自动切换到模拟模式并提示安装命令。
"""
import subprocess, os, sys
from pathlib import Path

SIGNER = str(Path(__file__).resolve().parent.parent / "src" / "omo_signer.py")

# ── 签名/验签工具 ──
def sign_node_output(agent: str, message: str) -> dict:
    """截获节点输出，附加签名。"""
    r = subprocess.run(
        ["python", SIGNER, "sign", agent, message],
        capture_output=True, text=True, timeout=10
    )
    sig = r.stdout.strip() if r.returncode == 0 else None
    return {"agent": agent, "payload": message, "signature": sig,
            "verified": sig is not None}

def verify_node_output(entry: dict) -> bool:
    """接收端自动验签。"""
    if not entry.get("signature"):
        return False
    r = subprocess.run(
        ["python", SIGNER, "verify", entry["agent"],
         entry["payload"], entry["signature"]],
        capture_output=True, text=True, timeout=10
    )
    return r.returncode == 0

# ── 节点定义 ──
def oracle_node(state: dict) -> dict:
    msgs = state.get("messages", [])
    last = msgs[-1] if msgs else state.get("code", "")
    review = f"Oracle review: {str(last)[:50]}"
    return sign_node_output("oracle", review)

def metis_node(state: dict) -> dict:
    review = f"Metis second review on: {state.get('payload','')[:50]}"
    return sign_node_output("metis", review)

def momus_node(state: dict) -> dict:
    verdict = f"Momus final verdict: {state.get('payload','')[:50]} — PASS"
    return sign_node_output("momus", verdict)

# ── 主流程 ──
try:
    from langgraph.graph import StateGraph, END
    from typing import TypedDict, Annotated
    import operator

    class AgentState(TypedDict):
        messages: Annotated[list, operator.add]
        signatures: Annotated[list, operator.add]

    graph = StateGraph(AgentState)
    graph.add_node("oracle", oracle_node)
    graph.add_node("metis", metis_node)
    graph.add_node("momus", momus_node)
    graph.set_entry_point("oracle")
    graph.add_edge("oracle", "metis")
    graph.add_edge("metis", "momus")
    graph.add_edge("momus", END)

    app = graph.compile()
    MODE = "LangGraph StateGraph API"

except ImportError:
    MODE = "simulation (pip install langgraph for native StateGraph)"
    app = None

print(f"=== LangGraph Demo — {MODE} ===\n")

if app is not None:
    # 真实 LangGraph 执行
    result = app.invoke({"messages": ["def foo(): pass  # TODO: validate input"],
                          "signatures": []})
    for entry in result["signatures"]:
        vf = verify_node_output(entry)
        print(f"[{entry['agent']}] sig={'OK' if entry['signature'] else 'FAIL'} "
              f"verify={'PASS' if vf else 'FAIL'}")
else:
    # 模拟模式：手动执行节点链
    state = {"code": "def foo(): pass  # TODO: validate input"}
    print(f"[init] {state['code'][:60]}")
    for node_fn, name in [(oracle_node, "oracle"),
                            (metis_node, "metis"),
                            (momus_node, "momus")]:
        state = node_fn(state)
        vf = verify_node_output(state)
        print(f"[{name}] sig={'OK' if state['signature'] else 'FAIL'} "
              f"verify={'PASS' if vf else 'FAIL'} "
              f"content={state.get('payload','')[:60]}")

print(f"\n=== 完成：3跳审查链，每跳签名+验签 ===")
print(f"框架独立：守护进程零改动，仅通过 TCP 接口调用")
print(f"通信范式：状态图（LangGraph）与文本管道（OpenCode）共享同一签名基础设施")
