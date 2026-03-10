# SIS 2 CLI Version

Removed Tkinter, just CLI

## Files
- `main.py` - CLI menu
- `crypto_core.py` - SHA-256, HMAC, PBKDF2, HKDF, password storage, integrity checker, tests, benchmarks

## Run
```bash
python3 main.py for MACOS
```

## Features
1. SHA-256 hash for text
2. SHA-256 hash for files
3. HMAC-SHA256 generation and verification
4. PBKDF2-HMAC-SHA256 key derivation
5. HKDF extract/expand
6. Password storage with salt + PBKDF2
7. File integrity manifest create/verify
8. Avalanche effect demo
9. Self-tests and benchmarks

## Notes
- Educational implementation only
- No crypto libraries are used for SHA-256/HMAC/PBKDF2/HKDF
- Standard libraries are used only for file I/O, JSON, timing, and OS utilities
