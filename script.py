import hashlib
from cryptography.fernet import Fernet

def main():
    def get_user_input():
        return input("Enter text to hash/encrypt: ")

    def demonstrate_hashing(text):
        def hash_md5(val):
            return hashlib.md5(val.encode()).hexdigest()

        def hash_sha256(val):
            return hashlib.sha256(val.encode()).hexdigest()

        md5_result = hash_md5(text)
        sha256_result = hash_sha256(text)
        return md5_result, sha256_result

    def demonstrate_symmetric_encryption(text):
        def generate_key():
            return Fernet.generate_key()
        
        def encrypt_message(key, message):
            return Fernet(key).encrypt(message.encode())
        
        def decrypt_message(key, token):
            return Fernet(key).decrypt(token).decode()

        key = generate_key()
        encrypted = encrypt_message(key, text)
        decrypted = decrypt_message(key, encrypted)
        return key, encrypted, decrypted

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