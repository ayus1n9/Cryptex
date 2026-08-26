from crypto import (
    demonstrate_hashing,
    demonstrate_symmetric_encryption,
    demonstrate_asymmetric_encryption
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

        print("=" * 50)
        print("SYMMETRIC ENCRYPTION")
        print("=" * 50)
        print(f"Encryption Key: {key.decode()}")
        print(f"Encrypted Text: {encrypted_text.decode()}")
        print(f"Decrypted Text: {decrypted_text}")

        key_size, rsa_encrypted, rsa_decrypted = demonstrate_asymmetric_encryption(text)
        print("=" * 50)
        print("ASYMMETRIC ENCRYPTION (RSA - Two-Key)")
        print("=" * 50)
        print(f"Encrypted:  {rsa_encrypted}")
        print(f"Decrypted:  {rsa_decrypted}")
        print(f"Match:      {rsa_decrypted == text}")
        print(f"RSA Key Size: {key_size} bits")

    display_results(get_user_input())

if __name__ == "__main__":
    main()

