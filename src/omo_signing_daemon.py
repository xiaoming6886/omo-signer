#!/usr/bin/env python3
"""
OMO Signing Daemon — TCP 密钥托管服务 (Ed25519 + SM2 + ECDSA)

启动时加载所有智能体的私钥，将其从磁盘重命名隐藏
(private_key -> .private_key_locked, sm2_private_key -> .sm2_private_key_locked,
 ecdsa_private_key -> .ecdsa_private_key_locked)，并仅在进程内存中持有。

协议: 4字节长度前缀 JSON over TCP (默认 127.0.0.1:45987)。

安全特性:
  - hmac.compare_digest() 恒定时间令牌认证
  - 每会话随机关机令牌
  - 启动时密钥完整性验证
  - 通过 .private_key_locked 实现崩溃恢复
  - Windows SO_EXCLUSIVEADDRUSE
  - 哈希链审计日志 (防篡改: 每条记录通过 SHA-256 链接)

用法:
  omo-daemon              前台运行
  omo-daemon --daemon      后台运行
  omo-daemon --stop        优雅关闭
  omo-daemon --status      状态检查

环境变量:
  OMO_SIGNER_PORT          监听端口 (默认 45987)
  OMO_SIGNER_HOST          绑定地址 (默认 127.0.0.1)
"""

__version__ = "1.0.0"

import sys, os, json, time, signal, atexit, hashlib, secrets, socket, threading, hmac, logging
from pathlib import Path
from datetime import datetime
from typing import Any

# ── 算法签名提供者 ──────────────────────────────────────────
from signing_provider import (
    SigningProvider,
    register_provider, register_defaults,
    get_provider_by_action, get_all_providers,
    Ed25519Provider, SM2Provider, ECDSAProvider,
)

# ── 跨平台路径 ────────────────────────────────────────────
def _state_dir() -> Path:
    primary = Path.home() / ".local" / "state"
    try:
        primary.mkdir(parents=True, exist_ok=True)
        return primary
    except (PermissionError, OSError):
        fallback = Path(__file__).resolve().parent.parent / "state"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

STATE_DIR = _state_dir()
KEYSTORE = STATE_DIR / "omo_keystore"
KEYSTORE.mkdir(parents=True, exist_ok=True)

PORT = int(os.environ.get("OMO_SIGNER_PORT", "45987"))
HOST = os.environ.get("OMO_SIGNER_HOST", "127.0.0.1")
AUDIT_LOG = STATE_DIR / "omo_audit.log"
PID_FILE = STATE_DIR / "omo_daemon.pid"
SHUTDOWN_TOKEN_FILE = STATE_DIR / "omo_shutdown_token"
MAX_MESSAGE_SIZE = 10 * 1024 * 1024

# ── 日志配置 ──────────────────────────────────────────────
LOG_FILE = STATE_DIR / "omo_daemon.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("omo-daemon")

# ── 协议：帧通信 ──────────────────────────────────────────

def send_message(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(4, 'big') + data)


def recv_message(sock, timeout=10) -> bytes:
    sock.settimeout(timeout)
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk: raise ConnectionError("Connection closed")
        header += chunk
    length = int.from_bytes(header, 'big')
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max {MAX_MESSAGE_SIZE})")
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(65536, length - len(data)))
        if not chunk: raise ConnectionError(f"Connection closed mid-message")
        data += chunk
    return data


class KeyVault:
    """密钥保管库 — 算法无关的密钥托管。

    内部通过 SigningProvider 接口管理所有算法的密钥，
    添加新算法无需修改本类的 load/save/sign 方法。
    """

    def __init__(self):
        # agent -> {algo_name: {"key": key_obj, "data": raw_data}}
        self._agent_keys: dict[str, dict[str, dict]] = {}
        self.tokens: dict[str, str] = {}
        self._seen_nonces: set[str] = set()
        self._nonce_lock = threading.Lock()
        self._providers = get_all_providers()
        # Rate limiting: sliding window (per-agent, per-minute)
        self._sign_times: dict[str, list[float]] = {}
        self._rate_limit = 100  # max sign requests per agent per minute
        self._rate_lock = threading.Lock()

    def load(self):
        """加载所有密钥：崩溃恢复 → 加载 → 验证完整性 → 锁定。

        通过 SigningProvider 接口处理所有算法，
        添加新算法无需修改本方法。
        """
        if not KEYSTORE.exists():
            print(f"[FATAL] Keystore not found: {KEYSTORE}", file=sys.stderr)
            sys.exit(1)

        providers = self._providers
        agent_dirs = sorted([d for d in KEYSTORE.iterdir() if d.is_dir()])
        if not agent_dirs:
            print("[WARN] Keystore is empty — generate keys with: omo-signer generate <agent>")
            return

        # ── Phase 1: Crash recovery (all algorithms) ──
        recovered = 0
        for d in agent_dirs:
            for algo, prov in providers.items():
                locked = d / prov.locked_filename
                normal = d / prov.private_key_filename
                if locked.exists() and not normal.exists():
                    locked.rename(normal)
                    recovered += 1
                    print(f"[RECOVER] {algo} key for '{d.name}'")
        if recovered:
            print(f"[RECOVER] Restored {recovered} keys from previous crash")

        # ── Phase 2: Load keys and verify integrity ──
        total = 0
        for d in agent_dirs:
            agent = d.name

            # Load token (shared across algorithms for this agent)
            tf = d / "token"
            if tf.exists():
                self.tokens[agent] = tf.read_text(encoding='utf-8').strip()

            for algo, prov in providers.items():
                kf = d / prov.private_key_filename
                if not kf.exists():
                    continue
                try:
                    key_obj = prov.load_key(key_dir=d)
                    prov.verify_integrity(key_dir=d, key_obj=key_obj)
                    key_data = prov.load_key_data(key_dir=d)
                    self._agent_keys.setdefault(agent, {})[algo] = {
                        "key": key_obj, "data": key_data
                    }
                    total += 1
                except Exception as e:
                    print(f"[FATAL] Failed to load {algo} key for '{agent}': {e}", file=sys.stderr)
                    sys.exit(1)

        algo_summary = ", ".join(
            f"{sum(1 for a in self._agent_keys.values() if algo in a)} {algo}"
            for algo in providers
        )
        print(f"[INIT] Loaded {algo_summary} keys")
        logger.info(f"Loaded {algo_summary} keys")

        if total == 0:
            print("[WARN] No keys loaded. Generate keys with: omo-signer generate <agent>", file=sys.stderr)
            logger.warning("Starting with empty key vault — keys can be generated at runtime")

        # ── Phase 3: Lock keys (rename to .locked) ──
        locked_count = 0
        for d in agent_dirs:
            for prov in providers.values():
                kf = d / prov.private_key_filename
                locked = d / prov.locked_filename
                if not kf.exists():
                    continue
                if locked.exists():
                    # Handle conflict: same content = stale duplicate, different = fatal
                    if kf.read_bytes() == locked.read_bytes():
                        locked.unlink()
                    else:
                        print(f"[FATAL] Key conflict for '{d.name}' ({prov.algorithm}): "
                              f"locked file differs from loaded key", file=sys.stderr)
                        sys.exit(1)
                kf.rename(locked)
                locked_count += 1
        print(f"[SECURE] {locked_count} keys locked")

    def save(self):
        """保存所有密钥：写回磁盘 → 删除锁定文件。

        通过 SigningProvider 接口处理所有算法，
        添加新算法无需修改本方法。
        """
        restored = 0
        for agent, algos in self._agent_keys.items():
            for algo, entry in algos.items():
                prov = self._providers.get(algo)
                if not prov:
                    continue
                # Write key data back to disk
                prov.save_key(key_dir=KEYSTORE / agent, key_data=entry["data"])
                # Remove lock file
                locked = KEYSTORE / agent / prov.locked_filename
                if locked.exists():
                    locked.unlink()
                restored += 1
        if restored:
            summary = ", ".join(
                f"{sum(1 for a in self._agent_keys.values() if algo in a)} {algo}"
                for algo in self._providers
            )
            print(f"[SAVE] {summary} keys restored")

    def _check_nonce(self, nonce: str | None) -> bool:
        """检查 nonce 是否已使用，线程安全。返回 True 表示通过"""
        if nonce is None:
            return False  # 拒绝无 nonce 的请求
        with self._nonce_lock:
            if nonce in self._seen_nonces:
                return False  # 重放攻击
            self._seen_nonces.add(nonce)
            return True

    def _check_rate(self, agent: str) -> bool:
        """滑动窗口限流：每分钟最多 self._rate_limit 次签名。"""
        import time
        now = time.time()
        with self._rate_lock:
            times = self._sign_times.get(agent, [])
            times = [t for t in times if now - t < 60]
            if len(times) >= self._rate_limit:
                return False
            times.append(now)
            self._sign_times[agent] = times
            return True

    def sign(self, agent: str, message: str, algo: str, token: str | None = None, nonce: str | None = None) -> tuple[bool, str, dict[str, Any]]:
        """统一签名入口。按 algorithm 名称分派到对应 SigningProvider。

        添加新算法无需修改本方法——新的 provider 注册后自动生效。
        """
        # Rate limit check
        if not self._check_rate(agent):
            return False, "Rate limit exceeded", {"agent": agent, "rate_limited": True}

        # Nonce anti-replay
        if not self._check_nonce(nonce):
            return False, "Replay detected", {"agent": agent, "replay": True, "algorithm": algo}

        # Token authentication
        expected = self.tokens.get(agent)
        if not expected or not hmac.compare_digest(token or "", expected):
            return False, "Invalid token", {"agent": agent, "token_valid": False, "algorithm": algo}

        # Look up provider and key
        prov = self._providers.get(algo)
        if not prov:
            return False, f"Unknown algorithm: {algo}", {}
        agent_data = self._agent_keys.get(agent, {})
        entry = agent_data.get(algo)
        if not entry:
            return False, f"No {algo} key for '{agent}'", {"algorithm": algo}

        try:
            key_obj = entry["key"]
            msg_bytes = message.encode('utf-8')
            sig = prov.sign(key_obj, msg_bytes)
            # Hex encode for JSON serialization
            if isinstance(sig, bytes):
                sig_hex = sig.hex()
            else:
                sig_hex = str(sig)
            info = {
                "agent": agent,
                "token_valid": True,
                "algorithm": algo,
                "message_hash": hashlib.sha256(msg_bytes).hexdigest()[:16]
            }
            return True, sig_hex, info
        except Exception as e:
            logger.error(f"{algo} signing error for '{agent}': {e}")
            return False, "Signing operation failed", {"algorithm": algo}

    def verify(self, agent: str, message: str, signature_hex: str, algo: str = "ed25519") -> tuple[bool, str]:
        """验证签名。默认 Ed25519；可通过 algo 参数指定算法。"""
        prov = self._providers.get(algo)
        if not prov:
            return False, f"Unknown algorithm: {algo}"
        try:
            key_dir = KEYSTORE / agent
            return prov.verify(key_dir, message.encode('utf-8'), signature_hex)
        except FileNotFoundError:
            return False, f"Public key not found for '{agent}'"
        except Exception as e:
            return False, f"Verification failed: {e}"


_audit_lock = threading.Lock()
_chain_state = {"last_line": None}  # stores the raw JSON line of the previous log entry


def _compute_prev_hash():
    """Compute prev_hash from the last log entry. Genesis if first entry."""
    if _chain_state["last_line"] is None:
        try:
            if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > 0:
                with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if lines:
                        _chain_state["last_line"] = lines[-1].strip()
        except (OSError, IOError):
            pass
    if _chain_state["last_line"] is None:
        return hashlib.sha256(b"GENESIS").hexdigest()
    return hashlib.sha256(_chain_state["last_line"].encode('utf-8')).hexdigest()


def audit_log(entry):
    with _audit_lock:
        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            entry["prev_hash"] = _compute_prev_hash()
            line = json.dumps(entry, ensure_ascii=False)
            with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
                f.write(line + "\n")
            _chain_state["last_line"] = line
        except (OSError, IOError):
            pass


def verify_audit_chain():
    """Verify hash-chain integrity of the audit log. Returns (valid, details)."""
    if not AUDIT_LOG.exists() or AUDIT_LOG.stat().st_size == 0:
        return True, "empty log"
    try:
        with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
    except (OSError, IOError):
        return False, "cannot read log"
    if not lines:
        return True, "empty log"
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, f"line {i+1}: invalid JSON"
        if i == 0:
            genesis = hashlib.sha256(b"GENESIS").hexdigest()
            if entry.get("prev_hash", "") != genesis:
                return False, f"genesis entry: prev_hash mismatch (expected {genesis[:16]}..., got {entry.get('prev_hash','')[:16]}...)"
        else:
            expected = hashlib.sha256(lines[i-1].encode('utf-8')).hexdigest()
            if entry.get("prev_hash", "") != expected:
                return False, f"entry {i+1}: hash chain broken (expected {expected[:16]}..., got {entry.get('prev_hash','')[:16]}...)"
    return True, f"{len(lines)} entries verified"


def handle_client(conn, vault, shutdown_token, shutdown_event):
    try:
        data = recv_message(conn, timeout=30)
        req = json.loads(data.decode('utf-8'))
        action = req.get("action", "")
        resp = {"status": "error", "reason": "unknown action"}

        # Unified sign dispatch: any action matching a provider is routed through vault.sign()
        provider = get_provider_by_action(action)
        if provider is not None:
            ok, result, info = vault.sign(
                req.get("agent",""), req.get("message",""),
                algo=provider.algorithm, token=req.get("token",""), nonce=req.get("nonce"))
            info.update({"action": action, "timestamp": datetime.now().isoformat()})
            audit_log(info)
            resp = {"status": "ok", "signature": result} if ok else {"status": "denied", "reason": result}

        elif action == "verify":
            algo = req.get("algorithm", "ed25519")
            ok, result = vault.verify(req.get("agent",""), req.get("message",""), req.get("signature",""), algo)
            audit_log({"action": "verify", "agent": req.get("agent",""), "algorithm": algo,
                       "timestamp": datetime.now().isoformat(), "result": "VERIFIED" if ok else "FAILED"})
            resp = {"status": "ok", "verified": ok, "reason": result} if not ok else {"status": "ok", "verified": True}

        elif action == "ping":
            agents = list(vault._agent_keys.keys())
            resp = {"status": "ok", "agents": agents}

        elif action == "shutdown":
            if not hmac.compare_digest(req.get("token", ""), shutdown_token):
                resp = {"status": "denied", "reason": "Invalid shutdown token"}
            else:
                resp = {"status": "ok", "message": "shutting down"}
                send_message(conn, json.dumps(resp, ensure_ascii=False).encode('utf-8'))
                conn.close()
                # Note: vault.save() is handled by atexit cleanup() — do NOT call it here
                PID_FILE.unlink(missing_ok=True)
                SHUTDOWN_TOKEN_FILE.unlink(missing_ok=True)
                shutdown_event.set()
                return

        send_message(conn, json.dumps(resp, ensure_ascii=False).encode('utf-8'))

    except json.JSONDecodeError:
        try: send_message(conn, b'{"status":"error","reason":"JSON parse error"}')
        except (OSError, BrokenPipeError): pass
    except Exception as e:
        audit_log({"error": str(e), "timestamp": datetime.now().isoformat()})
        try: send_message(conn, json.dumps({"status":"error","reason":"internal error"}).encode('utf-8'))
        except (OSError, BrokenPipeError): pass
    finally:
        try: conn.close()
        except Exception: pass


def run_server(vault):
    shutdown_token = secrets.token_hex(32)
    SHUTDOWN_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    SHUTDOWN_TOKEN_FILE.write_text(shutdown_token)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == 'win32':
        server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(128)

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(PID_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    except FileExistsError:
        existing = PID_FILE.read_text().strip() if PID_FILE.exists() else "unknown"
        print(f"[FATAL] PID file already exists (PID {existing}).", file=sys.stderr)
        sys.exit(1)

    print(f"[RUN] Listening on {HOST}:{PORT}")
    print(f"[RUN] Agents: {list(vault._agent_keys.keys())}")
    logger.info(f"Server started on {HOST}:{PORT} with {len(vault._agent_keys)} agents")

    shutdown_event = threading.Event()

    def cleanup():
        try: vault.save()
        except (OSError, IOError): pass
        try: PID_FILE.unlink(missing_ok=True)
        except (OSError, IOError): pass
        try: SHUTDOWN_TOKEN_FILE.unlink(missing_ok=True)
        except (OSError, IOError): pass
    atexit.register(cleanup)

    server.settimeout(1.0)
    while not shutdown_event.is_set():
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, vault, shutdown_token, shutdown_event), daemon=True).start()
        except socket.timeout:
            continue
        except (OSError, IOError) as e:
            print(f"[ERROR] Accept failed: {e}", file=sys.stderr)
            logger.error(f"Accept failed: {e}")
            time.sleep(0.5)

    print("[STOP] Draining connections...")
    server.close()
    for t in threading.enumerate():
        if t is not threading.current_thread() and t.is_alive() and t.daemon:
            t.join(timeout=3.0)
    print("[STOP] Shutdown complete")
    logger.info("Server shut down gracefully")
    sys.exit(0)


def start_daemon():
    import subprocess
    if PID_FILE.exists():
        try:
            os.kill(int(PID_FILE.read_text().strip()), 0)
            print("[WARN] Daemon already running"); sys.exit(1)
        except (OSError, ValueError):
            PID_FILE.unlink(missing_ok=True)
    log_dir = STATE_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    log_out = open(str(log_dir / "omo_daemon.log"), 'a')
    log_err = open(str(log_dir / "omo_daemon_err.log"), 'a')
    DETACHED = 0x00000008 if sys.platform == 'win32' else 0
    subprocess.Popen([sys.executable, __file__], creationflags=DETACHED,
                     stdout=log_out, stderr=log_err)
    # Close file handles in parent process — child inherits its own copies
    log_out.close()
    log_err.close()
    time.sleep(1.5)
    if PID_FILE.exists():
        print(f"[OK] Daemon started (PID: {PID_FILE.read_text().strip()})")
    else:
        print("[WARN] Daemon may have failed to start. Check logs.")


def stop_daemon():
    if not PID_FILE.exists():
        print("[INFO] Not running"); return
    pid = int(PID_FILE.read_text().strip())
    token = SHUTDOWN_TOKEN_FILE.read_text(encoding='utf-8').strip() if SHUTDOWN_TOKEN_FILE.exists() else ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(5)
        try:
            s.connect((HOST, PORT))
            req = json.dumps({"action": "shutdown", "token": token}).encode('utf-8')
            send_message(s, req)
            resp = recv_message(s, timeout=5)
            s.close()
            print("[OK] Daemon shutdown gracefully (keys saved)")
        finally:
            try: s.close()
            except Exception: pass
        PID_FILE.unlink(missing_ok=True)
    except (OSError, ConnectionRefusedError, ConnectionResetError):
        try:
            os.kill(pid, signal.SIGTERM)
            PID_FILE.unlink(missing_ok=True)
            SHUTDOWN_TOKEN_FILE.unlink(missing_ok=True)
            print(f"[OK] Force-killed PID {pid}")
        except (OSError, ProcessLookupError):
            print("[WARN] Process not found")
            PID_FILE.unlink(missing_ok=True)


def status_daemon():
    if not PID_FILE.exists():
        print("OFFLINE"); return
    try:
        pid = int(PID_FILE.read_text().strip()); os.kill(pid, 0)
    except (OSError, ValueError):
        print("[STALE] PID file exists but process not found"); return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
        try:
            s.connect((HOST, PORT))
            send_message(s, b'{"action":"ping"}')
            resp = json.loads(recv_message(s, timeout=3).decode('utf-8'))
            print(f"ONLINE | PID={pid} | Agents={len(resp.get('agents',[]))}")
        finally:
            try: s.close()
            except Exception: pass
    except (OSError, ConnectionRefusedError, ConnectionResetError, ValueError, ConnectionError):
        print(f"[STALE] PID={pid} exists but unreachable")


def main() -> None:
    """CLI 入口点 (兼容 omo-daemon 命令)"""
    register_defaults()
    if not get_all_providers():
        print("[FATAL] No signing providers available. Install at least one: PyNaCl, gmssl, or ecdsa", file=sys.stderr)
        sys.exit(1)
    if "--daemon" in sys.argv:
        start_daemon()
    elif "--stop" in sys.argv:
        stop_daemon()
    elif "--status" in sys.argv:
        status_daemon()
    else:
        vault = KeyVault()
        vault.load()
        valid, detail = verify_audit_chain()
        if not valid:
            print(f"[WARN] 审计链验证失败: {detail}", file=sys.stderr)
        else:
            print(f"[AUDIT] 链完整性: {detail}")
        run_server(vault)

if __name__ == "__main__":
    main()
