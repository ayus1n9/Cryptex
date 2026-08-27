import hashlib
from crypto import (
    demonstrate_hashing,
    demonstrate_symmetric_encryption,
    demonstrate_asymmetric_encryption,
    demonstrate_password_hashing,
    demonstrate_hmac
)

def main():
    def get_user_input():
        return input("Enter text to hash/encrypt: ")

    def display_results(text):
        md5_hash, sha256_hash = demonstrate_hashing(text)
        key, encrypted_text, decrypted_text = demonstrate_symmetric_encryption(text)

        print("=" * 50)
        print("HASHING")
        print("=" * 50)
        print(f"MD5 Hash: {md5_hash}")
        print(f"SHA256 Hash: {sha256_hash}")

        print("\n")
        print("=" * 50)
        print("SYMMETRIC ENCRYPTION")
        print("=" * 50)
        print(f"Encryption Key: {key.decode()}")
        print(f"Encrypted Text: {encrypted_text.decode()}")
        print(f"Decrypted Text: {decrypted_text}")

        print("\n")
        key_size, rsa_encrypted, rsa_decrypted = demonstrate_asymmetric_encryption(text)
        print("=" * 50)
        print("ASYMMETRIC ENCRYPTION (RSA - Two-Key)")
        print("=" * 50)
        print(f"Encrypted(raw bytes):  {rsa_encrypted}")
        print(f"Encrypted:  {rsa_encrypted.hex()[:64]}")
        print(f"Decrypted:  {rsa_decrypted}")
        print(f"Match:      {rsa_decrypted == text}")
        print(f"RSA Key Size: {key_size} bits")

        print("\n")
        print("=" * 50)
        print("WHY MD5 FAILS FOR PASSWORDS")
        print("=" * 50)
        md5_1 = hashlib.md5(text.encode()).hexdigest()
        md5_2 = hashlib.md5(text.encode()).hexdigest()
        print(f"MD5('{text}'): {md5_1}")
        print(f"MD5('{text}'): {md5_2}")
        print(f"Identical?:    {md5_1 == md5_2}  ← Attackers can pre-compute this!")

        print("\n")
        hash1, hash2, is_correct, is_wrong = demonstrate_password_hashing(text)
        print("=" * 50)
        print("PASSWORD HASHING (bcrypt - Salted)")
        print("=" * 50)
        print(f"Hash 1:     {hash1}")
        print(f"Hash 2:     {hash2}")
        print(f"Identical?: {hash1 == hash2}")
        print(f"Verify correct: {is_correct}")
        print(f"Verify wrong:   {is_wrong}")

        print("\n")
        generated_hmac, valid_check, invalid_check, my_key = demonstrate_hmac(text)
        print("=" * 50)
        print("HMAC (Integrity + Authenticity)")
        print("=" * 50)
        print(f"Message:     {text}")
        print(f"Secret Key:     {my_key}")
        print(f"HMAC: {generated_hmac}")
        print(f"Verify with correct key: {valid_check}")
        print(f"Verify with wrong key:   {invalid_check}")

    display_results(get_user_input())

if __name__ == "__main__":
    main()
