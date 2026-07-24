# Changelog

All notable changes to OMO Signer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-24

### Added
- SigningProvider abstract interface for algorithm-independent key management
- Ed25519Provider, SM2Provider, ECDSAProvider implementations
- Unified KeyVault with provider-based load/save/sign — adding a new algorithm
  requires zero changes to daemon core logic
- SM2 public key derivation via elliptic curve point multiplication (P = d * G)
- SM2 and ECDSA key integrity verification on daemon startup
- SM2 and ECDSA sign-verify roundtrip unit tests
- 4-byte length-prefix JSON TCP frame protocol
- 128-bit nonce anti-replay protection (thread-safe)
- 256-bit token authentication with constant-time comparison (hmac.compare_digest)
- Hash-chain audit log with SHA-256 linkage and startup integrity verification
- Atomic crash recovery via .private_key_locked rename pattern
- Cross-platform path handling with permission fallback
- Docker and Docker Compose deployment support
- GitHub Actions CI on Windows/Linux/macOS × Python 3.10/3.11/3.12
- Crash recovery CI on three platforms

### Fixed
- SM2 public key generation: gmssl CryptSM2 does not auto-derive public key
  from private key — now uses _kg(d, G) for proper derivation
- SM2 verify: gmssl expects "04" + x + y format for public key
- Unicode output on GBK consoles (replaced ✓/✗ with ASCII)
- File handle leak in start_daemon() (log_out/log_err never closed)
- Unified handle_client sign dispatch via get_provider_by_action()
