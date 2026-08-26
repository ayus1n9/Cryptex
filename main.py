from crypto import (
    demonstrate_hashing,
    demonstrate_symmetric_encryption,
)

def main():
    def get_user_input():
        return input("Enter text to hash/encrypt: ")

    def display_results(text):
        md5_hash, sha256_hash = demonstrate_hashing(text)
        key, encrypted_text, decrypted_text = demonstrate_symmetric_encryption(text)
        print(f"MD5 Hash: {md5_hash}")
        print(f"SHA256 Hash: {sha256_hash}")
        print(f"Encryption Key: {key.decode()}")
        print(f"Encrypted Text: {encrypted_text.decode()}")
        print(f"Decrypted Text: {decrypted_text}")

    display_results(get_user_input())

if __name__ == "__main__":
    main()