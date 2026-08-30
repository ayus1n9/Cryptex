import unittest
import tempfile
import os
from crypto import (
    demonstrate_hashing,
    demonstrate_symmetric_encryption,
    demonstrate_asymmetric_encryption,
    demonstrate_password_hashing,
    demonstrate_hmac,
    demonstrate_digital_signature,
    hash_file,
    encrypt_file,
    decrypt_file
)


class TestHashing(unittest.TestCase):
    def test_md5_consistency(self):
        h1, _ = demonstrate_hashing("hello")
        h2, _ = demonstrate_hashing("hello")
        self.assertEqual(h1, h2)

    def test_sha256_consistency(self):
        _, h1 = demonstrate_hashing("hello")
        _, h2 = demonstrate_hashing("hello")
        self.assertEqual(h1, h2)

    def test_different_inputs_different_hashes(self):
        h1, _ = demonstrate_hashing("hello")
        h2, _ = demonstrate_hashing("world")
        self.assertNotEqual(h1, h2)


class TestSymmetricEncryption(unittest.TestCase):
    def test_roundtrip(self):
        key, encrypted, decrypted = demonstrate_symmetric_encryption("secret_message")
        self.assertEqual(decrypted, "secret_message")

    def test_different_keys_each_run(self):
        key1, _, _ = demonstrate_symmetric_encryption("test")
        key2, _, _ = demonstrate_symmetric_encryption("test")
        self.assertNotEqual(key1, key2)


class TestAsymmetricEncryption(unittest.TestCase):
    def test_roundtrip(self):
        key_size, encrypted, decrypted = demonstrate_asymmetric_encryption("test_data")
        self.assertEqual(decrypted, "test_data")
        self.assertEqual(key_size, 2048)


class TestPasswordHashing(unittest.TestCase):
    def test_verify_correct_password(self):
        hash1, _, is_correct, _ = demonstrate_password_hashing("mypassword")
        self.assertTrue(is_correct)

    def test_verify_wrong_password(self):
        hash1, _, _, is_wrong = demonstrate_password_hashing("mypassword")
        self.assertFalse(is_wrong)

    def test_different_hashes_same_password(self):
        h1, h2, _, _ = demonstrate_password_hashing("samepass")
        self.assertNotEqual(h1, h2)


class TestHMAC(unittest.TestCase):
    def test_valid_hmac(self):
        hmac_val, valid, _, _ = demonstrate_hmac("test_message")
        self.assertTrue(valid)

    def test_invalid_hmac(self):
        hmac_val, _, invalid, _ = demonstrate_hmac("test_message")
        self.assertFalse(invalid)


class TestDigitalSignatures(unittest.TestCase):
    def test_valid_signature(self):
        sig, valid, _ = demonstrate_digital_signature("contract")
        self.assertTrue(valid)

    def test_tampered_signature(self):
        sig, _, tampered = demonstrate_digital_signature("contract")
        self.assertFalse(tampered)


class TestFileOperations(unittest.TestCase):
    def test_file_hash_consistency(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("file content here")
            temp_path = f.name
        try:
            h1 = hash_file(temp_path, "sha256")
            h2 = hash_file(temp_path, "sha256")
            self.assertEqual(h1, h2)
        finally:
            os.unlink(temp_path)

    def test_file_encrypt_decrypt(self):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as f:
            f.write(b"secret file data")
            temp_path = f.name
        enc_path = temp_path + ".enc"
        dec_path = temp_path + ".dec"
        try:
            encrypt_file(temp_path, enc_path, key)
            self.assertTrue(os.path.exists(enc_path))
            decrypt_file(enc_path, dec_path, key)
            with open(dec_path, "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, b"secret file data")
        finally:
            for p in (temp_path, enc_path, dec_path):
                if os.path.exists(p):
                    os.unlink(p)


if __name__ == "__main__":
    unittest.main()