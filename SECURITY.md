# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Please report security issues privately to **hym17613236886@163.com** with the
subject line `[SECURITY] omo-signer`.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 48 hours. If the vulnerability is confirmed,
a fix will be released within 7 days.

## Security Model

OMO Signer is designed for **single-user workstation** deployment. The security
model has three layers:

### Layer 1: Cryptographic Guarantees
- Message forgery prevented by Ed25519/SM2/ECDSA signature verification
- Message tampering detected by cryptographic hash verification
- Key files hidden via rename to `.private_key_locked`

### Layer 2: Audit Detection
- Hash-chain audit log with SHA-256 linkage
- Unauthorized signing attempts recorded with timestamp and agent identity
- Chain integrity verified on each daemon startup

### Layer 3: Known Limitations (OS-level)
- Same-user processes can read daemon memory (requires HSM/TEE for mitigation)
- Same-user processes can delete audit log or modify daemon source code
- These are inherent to single-user OS architecture, not design flaws

## Nonces and Crash Recovery

The nonce anti-replay set is stored in process memory. If the daemon crashes
and restarts, previously used nonces can be replayed. This is a known limitation
of the memory-only design. Mitigation: monitor daemon uptime and rotate keys
after unexpected restarts.

## Token Storage

Authentication tokens are stored as plaintext files in the keystore directory
(`~/.local/state/omo_keystore/<agent>/token`). Tokens are 256-bit random values.
File permissions should be restricted to the owning user. On multi-user systems,
consider using OS keyring integration or HSM-backed key storage.
