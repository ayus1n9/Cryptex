import os
import json
import time
import hashlib, hmac
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def demonstrate_hashing(text):
    def hash_md5(val):
        return hashlib.md5(val.encode()).hexdigest()
    def hash_sha256(val):
        return hashlib.sha256(val.encode()).hexdigest()
    md5_result = hash_md5(text)
    sha256_result = hash_sha256(text)
    return md5_result, sha256_result

def generate_key():
    return Fernet.generate_key()

def demonstrate_symmetric_encryption(text):
    def encrypt_message(key, message):
        return Fernet(key).encrypt(message.encode())
    def decrypt_message(key, token):
        return Fernet(key).decrypt(token).decode()
    key = generate_key()
    encrypted = encrypt_message(key, text)
    decrypted = decrypt_message(key, encrypted)
    return key, encrypted, decrypted

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def demonstrate_asymmetric_encryption(text):
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

def demonstrate_digital_signature(message: str):
    def sign_message(message: str, private_key) -> bytes:
        hashed = hashlib.sha256(message.encode()).digest()
        signed = private_key.sign(
            hashed,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signed
    def verify_signature(message: str, signed: bytes, public_key) -> bool:
        hashed = hashlib.sha256(message.encode()).digest()
        try:
            public_key.verify(
                signed,
                hashed,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    priv_key, pub_key = generate_rsa_keypair()
    signature = sign_message(message, priv_key)
    valid_verify = verify_signature(message, signature, pub_key)
    tampered_verify = verify_signature(message+"!", signature, pub_key)
    return signature, valid_verify, tampered_verify

def hash_file(filepath: str, algorithm: str) -> str:
    if algorithm == "sha256":
        hashed = hashlib.sha256()
    elif algorithm == "md5":
        hashed = hashlib.md5()
    else:
        raise ValueError("Unsupported algorithm")
    with open(f"{filepath}","rb") as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            hashed.update(data)
    return hashed.hexdigest()

def encrypt_file(input_path: str, output_path: str, key: bytes):
    fernet_key = Fernet(key)
    with open(f"{input_path}", "rb") as file:
        data = file.read()
        data_encrypt = fernet_key.encrypt(data)
    with open(f"{output_path}", "wb") as n_file:
        write = n_file.write(data_encrypt)
    return write, data_encrypt

def decrypt_file(input_path: str, output_path: str, key: bytes):
    fernet_key = Fernet(key)
    with open(f"{input_path}", "rb") as file:
        data = file.read()
        data_decrypt = fernet_key.decrypt(data)
    with open(f"{output_path}", "wb") as n_file:
        write = n_file.write(data_decrypt)
    return write, data_decrypt

def batch_hash_folder(folder_path: str) -> dict:
    results = {}
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        try:
            if os.path.isfile(full_path):
                results[filename] = hash_file(full_path, "sha256")
        except (FileNotFoundError, PermissionError):
            pass
    with open('hashes.json', 'w') as f:
        json.dump(results, f, indent=2)
    return results

def benchmark_crypto(iterations: int = 100):
    """Benchmark all cryptographic operations and return timing results."""
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    rsa_priv, rsa_pub = generate_rsa_keypair()

    test_msg = "benchmark_test_string"
    test_bytes = test_msg.encode("utf-8")

    fernet_encrypted = fernet.encrypt(test_bytes)
    rsa_pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    rsa_encrypted = rsa_pub.encrypt(test_bytes, rsa_pad)

    test_digest = hashlib.sha256(test_bytes).digest()
    rsa_sig_pad = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    rsa_signature = rsa_priv.sign(test_digest, rsa_sig_pad, hashes.SHA256())

    results = {}

    start = time.perf_counter()
    for _ in range(iterations):
        hashlib.md5(test_bytes).hexdigest()
    end = time.perf_counter()
    results["md5"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        hashlib.sha256(test_bytes).hexdigest()
    end = time.perf_counter()
    results["sha256"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        fernet.encrypt(test_bytes)
    end = time.perf_counter()
    results["fernet_encrypt"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        fernet.decrypt(fernet_encrypted)
    end = time.perf_counter()
    results["fernet_decrypt"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        bcrypt.hashpw(test_bytes, bcrypt.gensalt())
    end = time.perf_counter()
    results["bcrypt"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_pub.encrypt(test_bytes, rsa_pad)
    end = time.perf_counter()
    results["rsa_encrypt"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_priv.decrypt(rsa_encrypted, rsa_pad)
    end = time.perf_counter()
    results["rsa_decrypt"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_priv.sign(test_digest, rsa_sig_pad, hashes.SHA256())
    end = time.perf_counter()
    results["rsa_sign"] = {"total": end - start, "per_op": (end - start) / iterations}

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_pub.verify(rsa_signature, test_digest, rsa_sig_pad, hashes.SHA256())
    end = time.perf_counter()
    results["rsa_verify"] = {"total": end - start, "per_op": (end - start) / iterations}

    return results