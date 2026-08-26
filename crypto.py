import hashlib
from cryptography.fernet import Fernet

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