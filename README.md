# Hashing/Encryption Demonstrator

A simple Python CLI tool that demonstrates the fundamental difference between **hashing** (one-way) and **symmetric encryption** (reversible) — a core concept in cybersecurity and cryptography.

---

## Features

- **Hashing Demo**: Computes MD5 and SHA-256 hashes of any input string
- **Symmetric Encryption Demo**: Encrypts and decrypts text using Fernet (AES-128 in CBC mode via `cryptography` library)
- **Educational Output**: Clearly labeled sections showing the difference between one-way hashing and reversible encryption
- **Round-Trip Verification**: Proves decrypted text matches the original input

---

## Prerequisites

- Python 3.7+
- `cryptography` library

Install the dependency:
```bash
pip install cryptography
```

---

## Usage

Run the script directly:
```bash
python main.py
```

Then enter any text when prompted:
```
Enter text to hash/encrypt: hello
```

### Sample Output
```
==================================================
HASHING (One-Way, Deterministic)
==================================================
MD5 Hash:     5d41402abc4b2a76b9719d911017c592
SHA-256 Hash: 2cf24dba5f0b30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

==================================================
SYMMETRIC ENCRYPTION (Reversible)
==================================================
Key:        gAAAAABk7...
Encrypted:  gAAAAABk7...
Decrypted:  hello
Match:      True
```

---

## Key Concepts Demonstrated

| Concept | Hashing | Symmetric Encryption |
|---------|---------|----------------------|
| Direction | One-way (irreversible) | Two-way (reversible) |
| Key Required | No | Yes (same key for encrypt/decrypt) |
| Output Length | Fixed (MD5=32 chars, SHA-256=64 chars) | Variable (depends on input) |
| Deterministic | Yes (same input → same output) | No (Fernet adds a nonce/timestamp) |
| Use Case | Integrity checks, passwords | Data confidentiality, secure storage |

---

## File Structure

```
.
└── main.py          # Single-file CLI tool
```

---

## Libraries Used

| Library | Purpose |
|---------|---------|
| `hashlib` (built-in) | MD5 and SHA-256 hashing |
| `cryptography.fernet` | Symmetric encryption/decryption |

---

## Notes

- **MD5 is considered cryptographically broken** and should not be used for security purposes. It is included here for educational comparison only.
- The Fernet key is generated fresh on every run. It is displayed in Base64-encoded format.
- The encrypted output is non-deterministic: encrypting the same text twice produces different tokens due to the embedded timestamp.

---

## License

This project is for educational purposes.