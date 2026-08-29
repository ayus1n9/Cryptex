import argparse
import sys
import os
from cryptography.fernet import Fernet
from crypto import (
    demonstrate_hashing,
    demonstrate_symmetric_encryption,
    demonstrate_asymmetric_encryption,
    demonstrate_password_hashing,
    demonstrate_hmac,
    demonstrate_digital_signature,
    hash_file,
    encrypt_file,
    decrypt_file,
    batch_hash_folder,
    benchmark_crypto
)


def display_text_demos(text):
    """Run all text-based cryptographic demonstrations."""
    print("\n" + "=" * 60)
    print("HASHING (One-Way, Deterministic)")
    print("=" * 60)
    md5_hash, sha256_hash = demonstrate_hashing(text)
    print(f"MD5 Hash:     {md5_hash}")
    print(f"SHA-256 Hash: {sha256_hash}")

    print("\n" + "=" * 60)
    print("SYMMETRIC ENCRYPTION (Fernet - Reversible)")
    print("=" * 60)
    key, encrypted_text, decrypted_text = demonstrate_symmetric_encryption(text)
    print(f"Key:        {key.decode()}")
    print(f"Encrypted:  {encrypted_text.decode()}")
    print(f"Decrypted:  {decrypted_text}")
    print(f"Match:      {decrypted_text == text}")

    print("\n" + "=" * 60)
    print("ASYMMETRIC ENCRYPTION (RSA - Two-Key)")
    print("=" * 60)
    key_size, rsa_encrypted, rsa_decrypted = demonstrate_asymmetric_encryption(text)
    print(f"RSA Key Size: {key_size} bits")
    print(f"Encrypted:    {rsa_encrypted.hex()[:64]}...")
    print(f"Decrypted:    {rsa_decrypted}")
    print(f"Match:        {rsa_decrypted == text}")

    print("\n" + "=" * 60)
    print("WHY MD5 FAILS FOR PASSWORDS")
    print("=" * 60)
    import hashlib
    md5_1 = hashlib.md5(text.encode()).hexdigest()
    md5_2 = hashlib.md5(text.encode()).hexdigest()
    print(f"MD5(\'{text}\'): {md5_1}")
    print(f"MD5(\'{text}\'): {md5_2}")
    print(f"Identical?:    {md5_1 == md5_2}  <-- Attackers can pre-compute this!")

    print("\n" + "=" * 60)
    print("PASSWORD HASHING (bcrypt - Salted)")
    print("=" * 60)
    hash1, hash2, is_correct, is_wrong = demonstrate_password_hashing(text)
    print(f"Hash 1:         {hash1}")
    print(f"Hash 2:         {hash2}")
    print(f"Identical?:     {hash1 == hash2}  <-- Salted, safe from rainbow tables!")
    print(f"Verify correct: {is_correct}")
    print(f"Verify wrong:   {is_wrong}")

    print("\n" + "=" * 60)
    print("HMAC (Integrity + Authenticity)")
    print("=" * 60)
    generated_hmac, valid_check, invalid_check, secret_key = demonstrate_hmac(text)
    print(f"Secret Key:     {secret_key}")
    print(f"HMAC:           {generated_hmac}")
    print(f"Verify correct: {valid_check}")
    print(f"Verify wrong:   {invalid_check}")

    print("\n" + "=" * 60)
    print("DIGITAL SIGNATURES (Non-Repudiation)")
    print("=" * 60)
    signature, valid_verify, tampered_verify = demonstrate_digital_signature(text)
    print(f"Signature:       {signature.hex()[:64]}...")
    print(f"Verify original: {valid_verify}")
    print(f"Verify tampered: {tampered_verify}")
    print("=" * 60)


def print_benchmark_table(results, iterations):
    """Format and print benchmark results."""
    print("\n" + "=" * 60)
    print(f"PERFORMANCE BENCHMARK ({iterations:,} iterations)")
    print("=" * 60)
    print(f"{'Algorithm':<20} {'Total Time':>15} {'Per Operation':>20}")
    print("-" * 60)

    for name, data in results.items():
        total = data["total"]
        per_op = data["per_op"]
        print(f"{name:<20} {total:>14.4f}s {per_op:>19.8f}s")

    print("=" * 60)
    print("\nNOTES:")
    print("  - bcrypt is intentionally slow (good for passwords)")
    print("  - RSA encrypt/sign is slow; decrypt/verify is faster")
    print("  - Fernet (AES) is fast - ideal for bulk data encryption")
    print("=" * 60)


def menu():
    """Display the main menu."""
    print("\n" + "=" * 60)
    print("CRYPTEX - CRYPTOGRAPHY TOOLKIT")
    print("=" * 60)
    print("1. Text Demonstrations (Hashing, Encryption, Signatures)")
    print("2. Hash a File")
    print("3. Encrypt a File")
    print("4. Decrypt a File")
    print("5. Batch Hash a Folder")
    print("6. Performance Benchmark")
    print("7. Exit")
    print("=" * 60)


def interactive_mode():
    """Run the interactive menu loop."""
    try:
        while True:
            menu()
            choice = input("Select an option (1-7): ").strip()

            if choice == "1":
                text = input("\nEnter text to hash/encrypt: ")
                display_text_demos(text)

            elif choice == "2":
                filepath = input("\nEnter file path: ").strip()
                algo = input("Algorithm (md5/sha256): ").strip().lower()
                if algo not in ("md5", "sha256"):
                    print("Invalid algorithm. Defaulting to sha256.")
                    algo = "sha256"
                if not os.path.exists(filepath):
                    print("Error: File not found.")
                    continue
                try:
                    result = hash_file(filepath, algo)
                    print(f"\n{algo.upper()} Hash: {result}")
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == "3":
                input_path = input("\nEnter file to encrypt: ").strip()
                output_path = input("Enter output file path: ").strip()
                if not os.path.exists(input_path):
                    print("Error: File not found.")
                    continue
                key = Fernet.generate_key()
                try:
                    bytes_written, encrypted_data = encrypt_file(input_path, output_path, key)
                    print(f"\nEncrypted successfully.")
                    print(f"Bytes written: {bytes_written}")
                    print(f"Key (save this!): {key.decode()}")
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == "4":
                input_path = input("\nEnter file to decrypt: ").strip()
                output_path = input("Enter output file path: ").strip()
                key_str = input("Enter Fernet key: ").strip()
                if not os.path.exists(input_path):
                    print("Error: File not found.")
                    continue
                try:
                    key = key_str.encode()
                    bytes_written, decrypted_data = decrypt_file(input_path, output_path, key)
                    print(f"\nDecrypted successfully.")
                    print(f"Bytes written: {bytes_written}")
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == "5":
                folder = input("\nEnter folder path: ").strip()
                if not os.path.isdir(folder):
                    print("Error: Folder not found.")
                    continue
                try:
                    results = batch_hash_folder(folder)
                    print(f"\nHashed {len(results)} files.")
                    print("Results saved to: hashes.json")
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == "6":
                iters = input("Iterations (default 100): ").strip()
                iters = int(iters) if iters.isdigit() else 100
                print(f"\nRunning benchmark with {iters} iterations...")
                results = benchmark_crypto(iters)
                print_benchmark_table(results, iters)

            elif choice == "7":
                print("\nGoodbye!")
                break

            else:
                print("\nInvalid option. Please choose 1-7.")
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Goodbye!")


def cli_mode():
    """Run in command-line argument mode."""
    parser = argparse.ArgumentParser(
        description="Cryptex - Cryptography Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --text "hello"
  python main.py --file document.pdf --hash sha256
  python main.py --encrypt secret.txt --output secret.enc
  python main.py --decrypt secret.enc --output secret.txt --key "gAAAAAB..."
  python main.py --folder ./downloads
  python main.py --benchmark --iterations 100
        """
    )

    parser.add_argument("--text", type=str, help="Run all text demonstrations")
    parser.add_argument("--file", type=str, help="File path to hash")
    parser.add_argument("--hash", type=str, choices=["md5", "sha256"], default="sha256",
                        help="Hash algorithm (default: sha256)")
    parser.add_argument("--encrypt", type=str, help="File to encrypt")
    parser.add_argument("--decrypt", type=str, help="File to decrypt")
    parser.add_argument("--output", type=str, help="Output file path")
    parser.add_argument("--key", type=str, help="Fernet key for decryption")
    parser.add_argument("--folder", type=str, help="Folder to batch hash")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmark")
    parser.add_argument("--iterations", type=int, default=100,
                        help="Benchmark iterations (default: 100)")

    args = parser.parse_args()

    if args.text:
        display_text_demos(args.text)

    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}")
            return
        try:
            result = hash_file(args.file, args.hash)
            print(f"{args.hash.upper()} Hash: {result}")
        except Exception as e:
            print(f"Error: {e}")

    elif args.encrypt:
        if not os.path.exists(args.encrypt):
            print(f"Error: File not found: {args.encrypt}")
            return
        if not args.output:
            args.output = args.encrypt + ".enc"
        key = Fernet.generate_key()
        try:
            bytes_written, _ = encrypt_file(args.encrypt, args.output, key)
            print(f"Encrypted {bytes_written} bytes to {args.output}")
            print(f"Key (save this!): {key.decode()}")
        except Exception as e:
            print(f"Error: {e}")

    elif args.decrypt:
        if not os.path.exists(args.decrypt):
            print(f"Error: File not found: {args.decrypt}")
            return
        if not args.output:
            print("Error: --output required for decryption")
            return
        if not args.key:
            print("Error: --key required for decryption")
            return
        try:
            key = args.key.encode()
            bytes_written, _ = decrypt_file(args.decrypt, args.output, key)
            print(f"Decrypted {bytes_written} bytes to {args.output}")
        except Exception as e:
            print(f"Error: {e}")

    elif args.folder:
        if not os.path.isdir(args.folder):
            print(f"Error: Folder not found: {args.folder}")
            return
        try:
            results = batch_hash_folder(args.folder)
            print(f"Hashed {len(results)} files. Results saved to hashes.json")
        except Exception as e:
            print(f"Error: {e}")

    elif args.benchmark:
        print(f"Running benchmark with {args.iterations} iterations...")
        results = benchmark_crypto(args.iterations)
        print_benchmark_table(results, args.iterations)

    else:
        parser.print_help()


def main():
    try:
        if len(sys.argv) > 1:
            cli_mode()
        else:
            interactive_mode()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Goodbye!")
    except EOFError:
        print("\n\nInput closed. Goodbye!")

if __name__ == "__main__":
    main()