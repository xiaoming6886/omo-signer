#!/usr/bin/env python3
"""
OMO Signer — 面向 LLM 多智能体通信的独立签名基础设施。

与 omo_signing_daemon.py 通过 TCP (默认 127.0.0.1:45987) 通信。
私钥材料永不离开守护进程。

用法:
  omo-signer generate <agent>           生成 Ed25519 密钥对
  omo-signer generate <agent> --sm2     生成 SM2 密钥对
  omo-signer generate <agent> --ecdsa   生成 ECDSA 密钥对
  omo-signer sign <agent> <message>     Ed25519 签名 (默认)
  omo-signer sign <agent> <message> --sm2    SM2 签名
  omo-signer sign <agent> <message> --ecdsa  ECDSA 签名
  omo-signer verify <agent> <message> <signature>            验证签名 (默认 Ed25519)
  omo-signer verify <agent> <message> <signature> --sm2      验证 SM2 签名
  omo-signer verify <agent> <message> <signature> --ecdsa    验证 ECDSA 签名
  omo-signer list                       列出所有智能体
  omo-signer ping                       守护进程健康检查
"""

__version__ = "1.0.0"

import sys, os, json, secrets, hashlib, socket, hmac, argparse
from pathlib import Path

# ── 算法签名提供者 ──────────────────────────────────────────
from signing_provider import (
    SigningProvider, register_defaults, get_provider
)

register_defaults()

# ── 跨平台路径 ────────────────────────────────────────────
def _keystore_path() -> Path:
    """返回密钥库路径，自动处理跨平台和沙箱回退"""
    primary = Path.home() / ".local" / "state" / "omo_keystore"
    try:
        primary.mkdir(parents=True, exist_ok=True)
        return primary
    except (PermissionError, OSError):
        fallback = Path(__file__).resolve().parent.parent / "state" / "omo_keystore"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

KEYSTORE = _keystore_path()
HOST = os.environ.get("OMO_SIGNER_HOST", "127.0.0.1")
PORT = int(os.environ.get("OMO_SIGNER_PORT", "45987"))
MAX_MESSAGE_SIZE = 10 * 1024 * 1024

# ── TCP 通信 ─────────────────────────────────────────────
def _daemon_request(op: str, **kwargs) -> dict:
    """向守护进程发送 JSON 请求"""
    payload = json.dumps({"action": op, **kwargs}, ensure_ascii=False).encode()
    header = len(payload).to_bytes(4, "big")
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as s:
            s.sendall(header + payload)
            length = int.from_bytes(_recv_exact(s, 4), "big")
            if length > MAX_MESSAGE_SIZE:
                raise ValueError(f"Response too large: {length} > {MAX_MESSAGE_SIZE}")
            return json.loads(_recv_exact(s, length))
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"Error: Cannot connect to daemon ({HOST}:{PORT}). Start it with: omo-daemon", file=sys.stderr)
        sys.exit(1)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接断开")
        buf.extend(chunk)
    return bytes(buf)

# ── 密钥生成 ─────────────────────────────────────────────
def _ensure_token(key_dir: Path) -> None:
    """若 token 不存在则创建（跨算法共享）"""
    token_file = key_dir / "token"
    if not token_file.exists():
        token_file.write_text(secrets.token_hex(32), encoding="ascii")

def generate(agent: str, algo: str, force: bool = False) -> None:
    """生成密钥对 — 通过 SigningProvider 接口，算法无关。"""
    prov = get_provider(algo)
    key_dir = KEYSTORE / agent
    key_dir.mkdir(parents=True, exist_ok=True)

    sk_file = key_dir / prov.private_key_filename
    if sk_file.exists() and not force:
        print(f"Error: {agent} already has {algo} key. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    if force and sk_file.exists():
        # Remove existing key files before generating
        for fname in [prov.private_key_filename, prov.public_key_filename, prov.locked_filename]:
            f = key_dir / fname
            if f.exists():
                f.unlink()

    prov.generate(key_dir)
    _ensure_token(key_dir)
    print(f"Generated {agent} ({algo})")

# ── 签名与验证 ───────────────────────────────────────────
def sign(agent: str, message: str, algo: str) -> None:
    prov = get_provider(algo)
    token_path = KEYSTORE / agent / "token"
    token = token_path.read_text(encoding="ascii").strip() if token_path.exists() else ""
    nonce = secrets.token_hex(16)  # 128-bit 随机 nonce 防重放
    resp = _daemon_request(prov.action_name, agent=agent, message=message, token=token, nonce=nonce)
    if resp.get("status") == "ok":
        print(resp["signature"])
    else:
        print(f"Sign failed: {resp.get('reason', 'unknown error')}", file=sys.stderr)
        sys.exit(1)

def verify(agent: str, message: str, signature: str, algo: str) -> None:
    """本地验证签名 — 通过 SigningProvider 接口，算法无关。"""
    prov = get_provider(algo)
    key_dir = KEYSTORE / agent
    ok, reason = prov.verify(key_dir, message.encode('utf-8'), signature)
    if ok:
        print("VERIFIED")
    else:
        print(f"INVALID ({reason})", file=sys.stderr)
        sys.exit(1)

# ── Python API ────────────────────────────────────────────
class OMOSigner:
    """程序化API — 避免subprocess冷启动开销。

    用法:
        signer = OMOSigner()
        sig = signer.sign("oracle", "hello")       # 走TCP，无subprocess
        ok = signer.verify("oracle", "hello", sig)  # 本地验证
        signer.ping()                               # 检查守护进程状态
    """

    def __init__(self):
        self._keystore = _keystore_path()

    def sign(self, agent: str, message: str, algo: str = "ed25519") -> str:
        """签名，返回hex字符串。"""
        prov = get_provider(algo)
        token = self._read_token(agent)
        nonce = secrets.token_hex(16)
        resp = _daemon_request(prov.action_name, agent=agent, message=message,
                               token=token, nonce=nonce)
        if resp.get("status") != "ok":
            raise RuntimeError(f"Sign failed: {resp.get('reason')}")
        return resp["signature"]

    def verify(self, agent: str, message: str, signature: str, algo: str = "ed25519") -> bool:
        """本地验证签名。"""
        prov = get_provider(algo)
        ok, _ = prov.verify(self._keystore / agent, message.encode('utf-8'), signature)
        return ok

    def generate(self, agent: str, algo: str = "ed25519", force: bool = False) -> None:
        """生成密钥对。"""
        generate(agent, algo, force)

    def ping(self) -> bool:
        """检查守护进程是否运行。"""
        try:
            resp = _daemon_request("ping")
            return resp.get("status") == "ok"
        except SystemExit:
            return False

    def list_agents(self) -> list[str]:
        """列出所有已配置的智能体。"""
        ks = self._keystore
        return [d.name for d in ks.iterdir() if d.is_dir()] if ks.exists() else []

    @staticmethod
    def _read_token(agent: str) -> str:
        token_path = _keystore_path() / agent / "token"
        return token_path.read_text(encoding="ascii").strip() if token_path.exists() else ""

# ── 密钥轮换 ─────────────────────────────────────────────
def rotate(agent: str, algo: str = "ed25519") -> None:
    """轮换密钥：备份旧公钥，生成新密钥对。旧公钥保留用于验证历史签名。"""
    import time
    prov = get_provider(algo)
    key_dir = KEYSTORE / agent

    # 备份旧公钥（追加时间戳版本号）
    pub_file = key_dir / prov.public_key_filename
    if pub_file.exists():
        backup_name = f"{prov.public_key_filename}.{int(time.time())}"
        pub_file.rename(key_dir / backup_name)
        print(f"Backed up old public key: {backup_name}")

    # 生成新密钥（force=True 覆盖旧私钥）
    generate(agent, algo, force=True)
    print(f"Generated new key: {agent} ({algo})")
    print("Tip: Old public key preserved for historical verification. Restart daemon for new key: omo-daemon --stop && omo-daemon --daemon")

# ── CLI ──────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="omo-signer",
        description="OMO Signer — LLM 多智能体通信签名客户端 (v%s)" % __version__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate
    p = sub.add_parser("generate", help="生成密钥对")
    p.add_argument("agent", help="智能体名称")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--sm2", action="store_true", help="生成 SM2 密钥")
    g.add_argument("--ecdsa", action="store_true", help="生成 ECDSA 密钥")
    p.add_argument("--force", action="store_true", help="强制覆盖已有密钥")

    # sign
    p = sub.add_parser("sign", help="签名消息")
    p.add_argument("agent", help="智能体名称")
    p.add_argument("message", nargs="?", help="待签名消息（省略则从 stdin 读取）")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--sm2", action="store_true", help="使用 SM2 签名")
    g.add_argument("--ecdsa", action="store_true", help="使用 ECDSA 签名")
    p.add_argument("--stdin", action="store_true", help="从标准输入读取消息")

    # verify
    p = sub.add_parser("verify", help="验证签名 (默认 Ed25519，--sm2/--ecdsa 切换算法)")
    p.add_argument("agent", help="智能体名称")
    p.add_argument("message", help="原始消息")
    p.add_argument("signature", help="十六进制签名")
    p.add_argument("--sm2", action="store_true", help="验证 SM2 签名")
    p.add_argument("--ecdsa", action="store_true", help="验证 ECDSA 签名")

    # utilities
    sub.add_parser("list", help="列出所有智能体")
    sub.add_parser("ping", help="守护进程健康检查")

    # rotate
    p = sub.add_parser("rotate", help="Rotate key (backup old pubkey, generate new key pair)")
    p.add_argument("agent", help="智能体名称")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--sm2", action="store_true", help="轮换 SM2 密钥")
    g.add_argument("--ecdsa", action="store_true", help="轮换 ECDSA 密钥")

    args = parser.parse_args()

    if args.command == "generate":
        algo = "sm2" if args.sm2 else "ecdsa" if args.ecdsa else "ed25519"
        generate(args.agent, algo, args.force)
    elif args.command == "sign":
        msg = sys.stdin.read().strip() if args.stdin else args.message
        if not msg:
            print("Error: message cannot be empty", file=sys.stderr); sys.exit(1)
        algo = "sm2" if args.sm2 else "ecdsa" if args.ecdsa else "ed25519"
        sign(args.agent, msg, algo)
    elif args.command == "verify":
        algo = "sm2" if args.sm2 else "ecdsa" if args.ecdsa else "ed25519"
        verify(args.agent, args.message, args.signature, algo)
    elif args.command == "list":
        agents = [d.name for d in KEYSTORE.iterdir() if d.is_dir()] if KEYSTORE.exists() else []
        print("\n".join(agents) if agents else "(no agents)")
    elif args.command == "ping":
        try:
            resp = _daemon_request("ping")
            print("daemon online" if resp.get("status") == "ok" else "daemon error")
        except SystemExit:
            pass
    elif args.command == "rotate":
        algo = "sm2" if args.sm2 else "ecdsa" if args.ecdsa else "ed25519"
        rotate(args.agent, algo)

if __name__ == "__main__":
    main()
