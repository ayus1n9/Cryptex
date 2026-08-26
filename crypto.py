import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

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

def demonstrate_asymmetric_encryption(text):
    def generate_rsa_keypair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(plain_text, public_key):
        plain_text = plain_text.encode()
        pad = padding.OAEP(
            mgf = padding.MGF1(
                algorithm = hashes.SHA256()
                ),
            algorithm = hashes.SHA256(),
            label = None
            )
        encrypted_bytes = public_key.encrypt(plain_text, pad)
        return encrypted_bytes
    
    def rsa_decrypt(encrypted_bytes, private_key):
        pad = padding.OAEP(
            mgf = padding.MGF1(
                algorithm = hashes.SHA256()
                ),
            algorithm = hashes.SHA256(),
            label = None
            )
        decrypted_bytes = private_key.decrypt(encrypted_bytes, pad)
        return decrypted_bytes.decode()

    priv_key, pub_key = generate_rsa_keypair()
    encrypted = rsa_encrypt(text, pub_key)
    decrypted = rsa_decrypt(encrypted, priv_key)
    return priv_key.key_size, encrypted, decrypted
