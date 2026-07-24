# Contributing to OMO Signer

Thank you for your interest in contributing! This document outlines the process.

## Development Setup

```bash
git clone https://github.com/xiaoming6886/omo-signer.git
cd omo-signer
pip install -e ".[dev]"
```

## Running Tests

```bash
# Generate test keys (one-time)
omo-signer generate oracle
omo-signer generate oracle --sm2
omo-signer generate oracle --ecdsa

# Start daemon
omo-daemon --daemon

# Run tests
python -m pytest tests/ -v

# Stop daemon
omo-daemon --stop
```

## Adding a New Signature Algorithm

OMO Signer uses a provider-based architecture. Adding a new algorithm (e.g., Dilithium)
requires:

1. **Create a provider class** in `src/signing_provider.py`:

```python
class DilithiumProvider(SigningProvider):
    algorithm = "dilithium"
    private_key_filename = "dilithium_private_key"
    locked_filename = ".dilithium_private_key_locked"
    public_key_filename = "dilithium_public_key"
    action_name = "sign_dilithium"
    cli_flag = "--dilithium"

    # Implement all abstract methods:
    def generate(self, key_dir): ...
    def load_key(self, key_dir): ...
    def load_key_data(self, key_dir): ...
    def save_key(self, key_dir, key_data): ...
    def verify_integrity(self, key_dir, key_obj): ...
    def sign(self, key_obj, message): ...
    def verify(self, key_dir, message, signature_hex): ...
```

2. **Register the provider** in `register_defaults()`:

```python
register_provider(DilithiumProvider())
```

3. **Add CLI flag** in `omo_signer.py` if needed.

No changes to the daemon's `load()`, `save()`, `sign()`, or `handle_client()` are required.

## Pull Request Checklist

- [ ] All existing tests pass: `python -m pytest tests/ -v`
- [ ] New features include corresponding unit tests
- [ ] Code style is consistent with existing codebase
- [ ] No hardcoded paths or environment-specific assumptions
- [ ] CHANGELOG.md updated

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.** Please report
security issues privately to hym17613236886@163.com.
