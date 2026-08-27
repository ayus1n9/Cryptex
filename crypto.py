import hashlib, hmac
import bcrypt
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

def demonstrate_password_hashing(password):
    def hash_password_bcrypt(password):
        pswd = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(pswd, salt)
        return hashed

    def verify_password_bcrypt(password, hashed):
        encoded = password.encode('utf-8')
        hash = bcrypt.checkpw(encoded, hashed)
        return hash

    hash1 = hash_password_bcrypt(password)
    hash2 = hash_password_bcrypt(password)
    is_match_correct = verify_password_bcrypt(password, hash1)
    is_match_wrong = verify_password_bcrypt("wrong_password", hash1)
    return (hash1.decode(), hash2.decode(), is_match_correct, is_match_wrong)

def demonstrate_hmac(message):
    def generate_hmac(message, secret_key) -> str:
        msg, key = message.encode(), secret_key.encode()
        hmac_val = hmac.new(key, msg, hashlib.sha256)
        hmac_str = hmac_val.hexdigest()
        return hmac_str

    def verify_hmac(message, secret_key, hmac_str) -> bool:
        hmac_nval = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()
        cmpr = hmac.compare_digest(hmac_nval, hmac_str)
        return cmpr

    my_key = "my_secret_key"
    generated_hmac = generate_hmac(message, my_key)
    valid_check, invalid_check = verify_hmac(message, my_key, generated_hmac), verify_hmac(message, "wrong_key", generated_hmac)
    return generated_hmac, valid_check, invalid_check, my_key


