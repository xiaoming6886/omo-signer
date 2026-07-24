#!/usr/bin/env python3
"""
Signing Provider — 算法签名抽象接口

每一种密码算法封装为一个 SigningProvider 子类。
向 OMO Signer 添加新算法仅需：
  1. 继承 SigningProvider，实现全部抽象方法
  2. 在 KeyVault._register_default_providers() 中注册一行

守护进程的 load/save/handle_client 核心循环无需任何修改。
"""

import sys
from abc import ABC, abstractmethod
import secrets
from pathlib import Path
from typing import Any

# ── 抽象接口 ──────────────────────────────────────────────

class SigningProvider(ABC):
    """签名算法提供者。

    Subclass this to add a new signature algorithm to OMO Signer.
    Must implement ALL abstract methods and properties below.

    Contract:
      - load_key / save_key / generate are idempotent (safe to call multiple times)
      - verify_integrity raises on mismatch (no silent failure)
      - sign returns raw bytes (caller handles encoding)
    """

    # === 标识 ===

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """算法短名，如 'ed25519'、'sm2'、'ecdsa'。
        daemon 的 action dispatch 用此名称区分操作。"""
        ...

    # === 密钥文件命名 ===

    @property
    @abstractmethod
    def private_key_filename(self) -> str:
        """私钥文件名，如 'private_key'、'sm2_private_key'"""
        ...

    @property
    @abstractmethod
    def locked_filename(self) -> str:
        """锁定文件名，如 '.private_key_locked'、'.sm2_private_key_locked'"""
        ...

    @property
    @abstractmethod
    def public_key_filename(self) -> str:
        """公钥文件名，如 'public_key'、'sm2_public_key'"""
        ...

    @property
    @abstractmethod
    def action_name(self) -> str:
        """守护进程 TCP 协议中的 action 名称，如 'sign'、'sign_sm2'、'sign_ecdsa'"""
        ...

    @property
    @abstractmethod
    def cli_flag(self) -> str:
        """CLI 标志名，如 '--sm2'、'--ecdsa'"""
        ...

    # === 密钥生命周期 ===

    @abstractmethod
    def generate(self, key_dir: Path) -> None:
        """生成密钥对，写入 key_dir。
        副作用：创建 private_key 和 public_key 文件。
        已有密钥时抛 FileExistsError，由调用方处理 --force 逻辑。"""
        ...

    @abstractmethod
    def load_key(self, key_dir: Path) -> Any:
        """从 key_dir 加载私钥，返回算法特定的密钥对象（SigningKey / str / ...）。
        若文件不存在或损坏则抛异常。"""
        ...

    @abstractmethod
    def load_key_data(self, key_dir: Path) -> Any:
        """读取私钥的原始数据（用于 save 恢复）。
        返回 bytes 或 str，必须可被 save_key 消费。"""
        ...

    @abstractmethod
    def save_key(self, key_dir: Path, key_data: Any) -> None:
        """将 key_data 写回 key_dir 的私钥文件。key_data 来自 load_key_data 或 generate。
        用于守护进程优雅关闭时保存密钥。"""
        ...

    @abstractmethod
    def verify_integrity(self, key_dir: Path, key_obj: Any) -> None:
        """验证 key_obj 与存储的公钥匹配。不匹配则抛 ValueError。
        用于守护进程启动时检测密钥损坏。"""
        ...

    # === 签名与验证 ===

    @abstractmethod
    def sign(self, key_obj: Any, message: bytes) -> bytes:
        """使用 key_obj 对 message 签名，返回签名字节。"""
        ...

    @abstractmethod
    def verify(self, key_dir: Path, message: bytes, signature_hex: str) -> tuple[bool, str]:
        """使用 key_dir 中的公钥验证签名。
        返回 (valid: bool, reason: str)。"""
        ...


# ── Ed25519 (PyNaCl) ──────────────────────────────────────

class Ed25519Provider(SigningProvider):
    algorithm = "ed25519"
    private_key_filename = "private_key"
    locked_filename = ".private_key_locked"
    public_key_filename = "public_key"
    action_name = "sign"
    cli_flag = ""

    def generate(self, key_dir: Path) -> None:
        from nacl.signing import SigningKey
        from nacl.encoding import HexEncoder

        sk_file = key_dir / self.private_key_filename
        pk_file = key_dir / self.public_key_filename
        if sk_file.exists():
            raise FileExistsError(f"Ed25519 key already exists for {key_dir.name}")
        sk = SigningKey.generate()
        sk_file.write_bytes(bytes(sk))
        pk_file.write_text(sk.verify_key.encode(HexEncoder).decode(), encoding="ascii")

    def load_key(self, key_dir: Path) -> Any:
        from nacl.signing import SigningKey
        kf = key_dir / self.private_key_filename
        if not kf.exists():
            raise FileNotFoundError(f"Ed25519 private key not found: {kf}")
        return SigningKey(kf.read_bytes())

    def load_key_data(self, key_dir: Path) -> Any:
        return (key_dir / self.private_key_filename).read_bytes()

    def save_key(self, key_dir: Path, key_data: Any) -> None:
        (key_dir / self.private_key_filename).write_bytes(key_data)

    def verify_integrity(self, key_dir: Path, key_obj: Any) -> None:
        from nacl.encoding import HexEncoder
        pub_file = key_dir / self.public_key_filename
        if not pub_file.exists():
            return  # tolerate missing public key — warn in caller
        expected = pub_file.read_text(encoding="utf-8").strip()
        actual = key_obj.verify_key.encode(encoder=HexEncoder).decode()
        if expected != actual:
            raise ValueError(
                f"Ed25519 key mismatch for '{key_dir.name}': "
                f"expected pubkey {expected[:16]}..., got {actual[:16]}..."
            )

    def sign(self, key_obj: Any, message: bytes) -> bytes:
        return key_obj.sign(message).signature

    def verify(self, key_dir: Path, message: bytes, signature_hex: str) -> tuple[bool, str]:
        from nacl.signing import VerifyKey
        from nacl.encoding import HexEncoder
        pub_file = key_dir / self.public_key_filename
        if not pub_file.exists():
            return False, "Public key not found"
        try:
            vk = VerifyKey(pub_file.read_text(encoding="utf-8").strip(), encoder=HexEncoder)
            sig_bytes = bytes.fromhex(signature_hex)
            vk.verify(message, sig_bytes)
            return True, "VERIFIED"
        except Exception:
            return False, "Signature verification failed"


# ── SM2 (gmssl) ───────────────────────────────────────────

class SM2Provider(SigningProvider):
    algorithm = "sm2"
    private_key_filename = "sm2_private_key"
    locked_filename = ".sm2_private_key_locked"
    public_key_filename = "sm2_public_key"
    action_name = "sign_sm2"
    cli_flag = "--sm2"

    def generate(self, key_dir: Path) -> None:
        from gmssl import sm2 as gmssl_sm2, func as gmssl_func

        sk_file = key_dir / self.private_key_filename
        pk_file = key_dir / self.public_key_filename
        if sk_file.exists():
            raise FileExistsError(f"SM2 key already exists for {key_dir.name}")
        sk_hex = gmssl_func.random_hex(64)
        # Derive public key: P = d * G (gmssl _kg returns hex string of x+y)
        sm2 = gmssl_sm2.CryptSM2(public_key="", private_key=sk_hex)
        G = sm2.ecc_table['g']
        pk_hex = sm2._kg(int(sk_hex, 16), G).zfill(128)
        sk_file.write_text(sk_hex, encoding="ascii")
        pk_file.write_text(pk_hex, encoding="ascii")

    def load_key(self, key_dir: Path) -> Any:
        kf = key_dir / self.private_key_filename
        if not kf.exists():
            raise FileNotFoundError(f"SM2 private key not found: {kf}")
        return kf.read_text(encoding="utf-8").strip()

    def load_key_data(self, key_dir: Path) -> Any:
        return (key_dir / self.private_key_filename).read_text(encoding="utf-8").strip()

    def save_key(self, key_dir: Path, key_data: Any) -> None:
        (key_dir / self.private_key_filename).write_text(str(key_data), encoding="utf-8")

    def verify_integrity(self, key_dir: Path, key_obj: Any) -> None:
        from gmssl import sm2 as gmssl_sm2
        pub_file = key_dir / self.public_key_filename
        if not pub_file.exists():
            return
        expected = pub_file.read_text(encoding="utf-8").strip()
        # Derive public key from private key: P = d * G
        sm2 = gmssl_sm2.CryptSM2(public_key="", private_key=key_obj)
        G = sm2.ecc_table['g']
        actual = sm2._kg(int(key_obj, 16), G).zfill(128)
        if expected != actual:
            raise ValueError(
                f"SM2 key mismatch for '{key_dir.name}': "
                f"expected pubkey {expected[:16]}..., got {actual[:16]}..."
            )

    def sign(self, key_obj: Any, message: bytes) -> bytes:
        from gmssl import sm2 as gmssl_sm2
        sm2_crypt = gmssl_sm2.CryptSM2(private_key=key_obj, public_key="")
        k_hex = secrets.token_hex(32)
        sig_hex = sm2_crypt.sign(message, k_hex)
        return bytes.fromhex(sig_hex)  # raw bytes — daemon will .hex() to get correct hex string

    def verify(self, key_dir: Path, message: bytes, signature_hex: str) -> tuple[bool, str]:
        from gmssl import sm2 as gmssl_sm2
        pub_file = key_dir / self.public_key_filename
        if not pub_file.exists():
            return False, "Public key not found"
        try:
            pk_data = pub_file.read_text(encoding="utf-8").strip()
            # gmssl expects "04" + x + y format
            sm2_crypt = gmssl_sm2.CryptSM2(public_key="04" + pk_data, private_key="")
            valid = sm2_crypt.verify(signature_hex.encode(), message)
            return (True, "VERIFIED") if valid else (False, "SM2 verification failed")
        except Exception as e:
            return False, f"SM2 verification error: {e}"


# ── ECDSA (ecdsa, NIST P-256) ────────────────────────────

class ECDSAProvider(SigningProvider):
    algorithm = "ecdsa"
    private_key_filename = "ecdsa_private_key"
    locked_filename = ".ecdsa_private_key_locked"
    public_key_filename = "ecdsa_public_key"
    action_name = "sign_ecdsa"
    cli_flag = "--ecdsa"

    def generate(self, key_dir: Path) -> None:
        from ecdsa import SigningKey, NIST256p

        sk_file = key_dir / self.private_key_filename
        pk_file = key_dir / self.public_key_filename
        if sk_file.exists():
            raise FileExistsError(f"ECDSA key already exists for {key_dir.name}")
        sk = SigningKey.generate(curve=NIST256p)
        sk_file.write_text(sk.to_pem().decode(), encoding="utf-8")
        pk_file.write_text(sk.verifying_key.to_pem().decode(), encoding="utf-8")

    def load_key(self, key_dir: Path) -> Any:
        from ecdsa import SigningKey
        kf = key_dir / self.private_key_filename
        if not kf.exists():
            raise FileNotFoundError(f"ECDSA private key not found: {kf}")
        return SigningKey.from_pem(kf.read_text(encoding="utf-8"))

    def load_key_data(self, key_dir: Path) -> Any:
        return (key_dir / self.private_key_filename).read_text(encoding="utf-8")

    def save_key(self, key_dir: Path, key_data: Any) -> None:
        (key_dir / self.private_key_filename).write_text(str(key_data), encoding="utf-8")

    def verify_integrity(self, key_dir: Path, key_obj: Any) -> None:
        pub_file = key_dir / self.public_key_filename
        if not pub_file.exists():
            return
        expected = pub_file.read_text(encoding="utf-8").strip()
        actual = key_obj.verifying_key.to_pem().decode().strip()
        if expected != actual:
            raise ValueError(
                f"ECDSA key mismatch for '{key_dir.name}': "
                f"expected pubkey {expected[:16]}..., got {actual[:16]}..."
            )

    def sign(self, key_obj: Any, message: bytes) -> bytes:
        return key_obj.sign(message)

    def verify(self, key_dir: Path, message: bytes, signature_hex: str) -> tuple[bool, str]:
        from ecdsa import VerifyingKey
        pub_file = key_dir / self.public_key_filename
        if not pub_file.exists():
            return False, "Public key not found"
        try:
            vk = VerifyingKey.from_pem(pub_file.read_text(encoding="utf-8").strip())
            if vk.verify(bytes.fromhex(signature_hex), message):
                return True, "VERIFIED"
            return False, "ECDSA verification failed"
        except Exception as e:
            return False, f"ECDSA verification error: {e}"


# ── Provider registry ─────────────────────────────────────

_DEFAULT_PROVIDERS: dict[str, SigningProvider] = {}

def register_provider(provider: SigningProvider) -> None:
    """注册签名算法提供者。守护进程启动时调用。"""
    _DEFAULT_PROVIDERS[provider.algorithm] = provider

def get_provider(algorithm: str) -> SigningProvider:
    """按算法名获取提供者。"""
    p = _DEFAULT_PROVIDERS.get(algorithm)
    if p is None:
        raise ValueError(f"Unknown signing algorithm: {algorithm}. Registered: {list(_DEFAULT_PROVIDERS.keys())}")
    return p

def get_all_providers() -> dict[str, SigningProvider]:
    """获取所有已注册的提供者。"""
    return dict(_DEFAULT_PROVIDERS)

def get_provider_by_action(action: str) -> SigningProvider | None:
    """按 TCP action 名称查找提供者。"""
    for p in _DEFAULT_PROVIDERS.values():
        if p.action_name == action:
            return p
    return None

def register_defaults() -> None:
    """注册所有内置算法提供者。守护进程启动时和客户端导入时调用。

    Provider 构造不做 import（import 在方法内部 lazy 执行），
    因此此处无需 try/except。如果依赖库未安装，错误在首次使用该方法时抛出。
    """
    register_provider(Ed25519Provider())
    register_provider(SM2Provider())
    register_provider(ECDSAProvider())
