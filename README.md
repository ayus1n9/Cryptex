# 🔐 Cryptex

> *A comprehensive Python cryptography toolkit demonstrating fundamental security concepts through hands-on implementations.* 🚀

Built as a progressive, week-long educational project covering hashing, encryption, password security, digital signatures, and file operations — now with a **GUI**, **unit tests**, and **CI/CD**! ✨

---

## 🎯 Overview

**Cryptex** is a CLI + GUI-based cryptography laboratory that bridges the gap between theory and practice. It demonstrates the critical differences between:

- 🔒 **Hashing** (one-way) vs. **Encryption** (reversible)
- 🔑 **Symmetric** (single key) vs. **Asymmetric** (public/private key pair) encryption
- ⚡ **Fast hashes** (MD5/SHA-256) vs. **Password hashes** (bcrypt with salts)
- 🛡️ **Integrity** (HMAC) vs. **Authenticity + Non-repudiation** (Digital Signatures)

---

## ✨ Features

### 📅 Day 1 — Hashing & Symmetric Encryption
- Compute **MD5** 🔴 and **SHA-256** 🟢 hashes of any text
- **Fernet symmetric encryption/decryption** with auto-generated keys
- Side-by-side comparison showing one-way hashing vs. reversible encryption

### 📅 Day 2 — Asymmetric Encryption (RSA) 🔑
- **RSA-2048 key pair** generation
- Encrypt with **public key** 📢, decrypt with **private key** 🔐
- **OAEP padding** demonstration (randomized encryption)
- Direct comparison with symmetric encryption

### 📅 Day 3 — Password Hashing 🧂
- **bcrypt** password hashing with automatic salt generation
- Demonstrates why identical passwords produce **different hashes** 🎲
- Verification with correct and incorrect passwords ✅❌
- Educational comparison: **MD5 vs. bcrypt** for password storage

### 📅 Day 4 — HMAC & Digital Signatures 🖊️
- **HMAC-SHA256** generation and verification with secret keys
- **Timing-safe comparison** using `hmac.compare_digest()` ⏱️
- **RSA digital signatures** with PSS padding
- **Tamper detection**: verify original message vs. modified message 🔍

### 📅 Day 5 — File Operations 📁
- **Memory-efficient file hashing** (chunked reading for large files)
- **File encryption/decryption** using Fernet
- **Batch folder hashing** with JSON export 📊
- Handles edge cases: empty files, permission errors, missing files

### 📅 Day 6 — CLI & Performance Benchmarking ⚡
- Full `argparse` interface for non-interactive usage
- Performance benchmarking: MD5 vs. SHA-256 vs. bcrypt vs. RSA vs. Fernet
- Timing comparisons across thousands of iterations 🏁

### 📅 Day 7 — GUI & Testing 🖥️🧪
- **Tkinter GUI** for interactive demonstrations
- **Comprehensive unit tests** (`unittest`)
- **GitHub Actions CI/CD** pipeline with automated testing ✅

---

## 🛠️ Tech Stack

| Library | Purpose |
|---------|---------|
| `hashlib` (built-in) | MD5, SHA-256 hashing 🔢 |
| `cryptography` | Fernet (AES-128), RSA (OAEP/PSS), digital signatures 🔐 |
| `bcrypt` | Secure password hashing with salts 🧂 |
| `hmac` (built-in) | Message authentication codes 🛡️ |
| `tkinter` (built-in) | GUI interface 🖥️ |
| `unittest` (built-in) | Automated testing 🧪 |
| `argparse` (built-in) | Command-line interface ⌨️ |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cryptex.git
cd cryptex

# Create virtual environment (recommended) 🐍
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Install dependencies 📦
pip install -r requirements.txt
```

---

## 🎮 Usage

### 🖥️ GUI Mode (Recommended for Beginners)
```bash
python gui.py
```
A window pops up! Type text, click buttons, see results instantly. ✨

### ⌨️ Interactive CLI Mode
```bash
python main.py
```

### 🏎️ CLI Mode (Power Users)
```bash
# Run all text demos
python main.py --text "hello"

# Hash a file
python main.py --file document.pdf --hash sha256

# Encrypt/decrypt files
python main.py --encrypt secret.txt --output secret.enc
python main.py --decrypt secret.enc --output secret.txt --key "gAAAAAB..."

# Batch hash folder
python main.py --folder ./downloads

# Performance benchmark
python main.py --benchmark --iterations 1000
```

---

## 🧪 Running Tests

```bash
# Run all tests
python -m unittest discover -v

# Run specific test file
python -m unittest test_crypto.py -v
```

All 12 tests should pass with flying colors! ✅

---

## 📂 Project Structure

```
cryptex/
├── 🔐 crypto.py              # Crypto engine (all algorithms)
├── ⌨️ main.py                # CLI entry point & interactive menu
├── 🖥️ gui.py                 # Tkinter graphical interface
├── 🧪 test_crypto.py         # Unit tests
├── 📦 requirements.txt       # Python dependencies
├── 📋 README.md              # You are here! 👋
└── 🔄 .github/
    └── workflows/
        └── ci.yml            # GitHub Actions CI/CD
```

---

## 🎓 Key Concepts Demonstrated

| Concept | Demonstration | Tool/Algorithm |
|---------|---------------|----------------|
| One-way hashing | Same input → same output, irreversible | MD5, SHA-256 🔢 |
| Reversible encryption | Encrypt → decrypt = original | Fernet (AES-128-CBC) 🔓 |
| Symmetric encryption | Same key for encrypt & decrypt | Fernet 🔑 |
| Asymmetric encryption | Public key encrypt, private key decrypt | RSA-2048 (OAEP) 🔐 |
| Password security | Salting prevents rainbow tables | bcrypt 🧂 |
| Message integrity | Hash + secret key = HMAC | HMAC-SHA256 🛡️ |
| Non-repudiation | Only private key holder can sign | RSA-PSS 🖊️ |
| Tamper detection | Modified message fails verification | Digital signatures 🔍 |

---

## ⚠️ Security Notes

- 🔴 **MD5 is cryptographically broken** and included solely for educational comparison. Do not use MD5 for security purposes.
- 🔑 **RSA-2048** is the industry-standard minimum key size. Production systems may require 3072+ bits.
- 🗝️ **Fernet keys** are generated per session in the demo. In production, store keys in a secure key management system.
- 🐢 **bcrypt cost factor** defaults to 12. Adjust based on your server's performance requirements.

---

## 🎓 Learning Outcomes

This project reinforces core concepts from:
- 📘 **CompTIA Security+ Domain 1** (Cryptographic Concepts)
- 📗 **CISSP** cryptography fundamentals
- 💻 General cybersecurity education on secure coding practices

---

## 🗺️ Roadmap

- [x] Day 1: Hashing & Symmetric Encryption 🔢
- [x] Day 2: Asymmetric Encryption (RSA) 🔑
- [x] Day 3: Password Hashing (bcrypt) 🧂
- [x] Day 4: HMAC & Digital Signatures 🖊️
- [x] Day 5: File Operations & Batch Processing 📁
- [x] Day 6: argparse CLI & Performance Benchmarking ⚡
- [x] Day 7: Tkinter GUI & Unit Testing 🖥️🧪

---

## 📜 License

This project is for **educational purposes** 🎓.

---

## 🙌 Acknowledgments

Built with ❤️ and lots of ☕ over 7 days of progressive learning.

---

<p align="center">🔐 <strong>Happy Cryptographing!</strong> 🚀</p>
