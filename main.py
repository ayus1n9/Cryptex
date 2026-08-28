import os
import json
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
    batch_hash_folder
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
    print(f"MD5('{text}'): {md5_1}")
    print(f"MD5('{text}'): {md5_2}")
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
    print(f"Signature:      {signature.hex()[:64]}...")
    print(f"Verify original: {valid_verify}")
    print(f"Verify tampered: {tampered_verify}")
    print("=" * 60)


def menu():
    """Display the main menu."""
    print("\n" + "=" * 60)
    print("CRYPTOGRAPHY TOOLKIT")
    print("=" * 60)
    print("1. Text Demonstrations (Hashing, Encryption, Signatures)")
    print("2. Hash a File")
    print("3. Encrypt a File")
    print("4. Decrypt a File")
    print("5. Batch Hash a Folder")
    print("6. Exit")
    print("=" * 60)


def main():
    while True:
        menu()
        choice = input("Select an option (1-6): ").strip()

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
            print("\nGoodbye!")
            break

        else:
            print("\nInvalid option. Please choose 1-6.")


if __name__ == "__main__":
    main()
