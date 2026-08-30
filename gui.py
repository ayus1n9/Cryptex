import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
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


def on_hash_click():
    text = inputs.get()
    if not text:
        messagebox.showwarning("Input Required", "Please enter some text!")
        return
    md5_hash, sha256_hash = demonstrate_hashing(text)
    outputs.delete(1.0, tk.END)
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, "HASHING (One-Way, Deterministic)\n")
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, f"MD5:     {md5_hash}\n")
    outputs.insert(tk.END, f"SHA-256: {sha256_hash}\n")


def on_encrypt_click():
    text = inputs.get()
    if not text:
        messagebox.showwarning("Input Required", "Please enter some text!")
        return
    key, encrypted, decrypted = demonstrate_symmetric_encryption(text)
    outputs.delete(1.0, tk.END)
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, "SYMMETRIC ENCRYPTION (Fernet)\n")
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, f"Key:       {key.decode()}\n")
    outputs.insert(tk.END, f"Encrypted: {encrypted.decode()}\n")
    outputs.insert(tk.END, f"Decrypted: {decrypted}\n")
    outputs.insert(tk.END, f"Match:     {decrypted == text}\n")


def on_asymmetric_click():
    text = inputs.get()
    if not text:
        messagebox.showwarning("Input Required", "Please enter some text!")
        return
    key_size, encrypted, decrypted = demonstrate_asymmetric_encryption(text)
    outputs.delete(1.0, tk.END)
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, "ASYMMETRIC ENCRYPTION (RSA)\n")
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, f"Key Size:  {key_size} bits\n")
    outputs.insert(tk.END, f"Encrypted: {encrypted.hex()[:64]}...\n")
    outputs.insert(tk.END, f"Decrypted: {decrypted}\n")
    outputs.insert(tk.END, f"Match:     {decrypted == text}\n")


def on_password_click():
    text = inputs.get()
    if not text:
        messagebox.showwarning("Input Required", "Please enter some text!")
        return
    hash1, hash2, is_correct, is_wrong = demonstrate_password_hashing(text)
    outputs.delete(1.0, tk.END)
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, "PASSWORD HASHING (bcrypt)\n")
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, f"Hash 1:     {hash1}\n")
    outputs.insert(tk.END, f"Hash 2:     {hash2}\n")
    outputs.insert(tk.END, f"Identical?: {hash1 == hash2}\n")
    outputs.insert(tk.END, f"Correct:    {is_correct}\n")
    outputs.insert(tk.END, f"Wrong:      {is_wrong}\n")


def on_hmac_click():
    text = inputs.get()
    if not text:
        messagebox.showwarning("Input Required", "Please enter some text!")
        return
    generated_hmac, valid, invalid, secret_key = demonstrate_hmac(text)
    outputs.delete(1.0, tk.END)
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, "HMAC (Integrity + Authenticity)\n")
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, f"Secret Key: {secret_key}\n")
    outputs.insert(tk.END, f"HMAC:       {generated_hmac}\n")
    outputs.insert(tk.END, f"Valid:      {valid}\n")
    outputs.insert(tk.END, f"Invalid:    {invalid}\n")


def on_sign_click():
    text = inputs.get()
    if not text:
        messagebox.showwarning("Input Required", "Please enter some text!")
        return
    signature, valid, tampered = demonstrate_digital_signature(text)
    outputs.delete(1.0, tk.END)
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, "DIGITAL SIGNATURES\n")
    outputs.insert(tk.END, "=" * 50 + "\n")
    outputs.insert(tk.END, f"Signature: {signature.hex()[:64]}...\n")
    outputs.insert(tk.END, f"Valid:     {valid}\n")
    outputs.insert(tk.END, f"Tampered:  {tampered}\n")


def on_file_hash_click():
    filepath = filedialog.askopenfilename(title="Select file to hash")
    if not filepath:
        return
    try:
        result = hash_file(filepath, "sha256")
        outputs.delete(1.0, tk.END)
        outputs.insert(tk.END, "=" * 50 + "\n")
        outputs.insert(tk.END, "FILE HASHING\n")
        outputs.insert(tk.END, "=" * 50 + "\n")
        outputs.insert(tk.END, f"File:   {filepath}\n")
        outputs.insert(tk.END, f"SHA-256: {result}\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def on_file_encrypt_click():
    filepath = filedialog.askopenfilename(title="Select file to encrypt")
    if not filepath:
        return
    output_path = filepath + ".enc"
    key = Fernet.generate_key()
    try:
        bytes_written, _ = encrypt_file(filepath, output_path, key)
        outputs.delete(1.0, tk.END)
        outputs.insert(tk.END, "=" * 50 + "\n")
        outputs.insert(tk.END, "FILE ENCRYPTION\n")
        outputs.insert(tk.END, "=" * 50 + "\n")
        outputs.insert(tk.END, f"Input:  {filepath}\n")
        outputs.insert(tk.END, f"Output: {output_path}\n")
        outputs.insert(tk.END, f"Bytes:  {bytes_written}\n")
        outputs.insert(tk.END, f"Key:    {key.decode()}\n")
        outputs.insert(tk.END, "\nSave this key! You will need it to decrypt.\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def on_file_decrypt_click():
    filepath = filedialog.askopenfilename(title="Select file to decrypt")
    if not filepath:
        return
    key_str = tk.simpledialog.askstring("Key Required", "Enter Fernet key:")
    if not key_str:
        return
    output_path = filepath.replace(".enc", ".dec")
    try:
        key = key_str.encode()
        bytes_written, _ = decrypt_file(filepath, output_path, key)
        outputs.delete(1.0, tk.END)
        outputs.insert(tk.END, "=" * 50 + "\n")
        outputs.insert(tk.END, "FILE DECRYPTION\n")
        outputs.insert(tk.END, "=" * 50 + "\n")
        outputs.insert(tk.END, f"Input:  {filepath}\n")
        outputs.insert(tk.END, f"Output: {output_path}\n")
        outputs.insert(tk.END, f"Bytes:  {bytes_written}\n")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# ========== BUILD GUI ==========
root = tk.Tk()
root.title("Cryptex - Cryptography Toolkit")
root.geometry("900x700")

tk.Label(root, text="Enter text:", font=("Arial", 12)).pack(pady=5)

inputs = tk.Entry(root, width=70, font=("Arial", 11))
inputs.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Hash", command=on_hash_click, width=12).pack(side=tk.LEFT, padx=3)
tk.Button(btn_frame, text="Encrypt", command=on_encrypt_click, width=12).pack(side=tk.LEFT, padx=3)
tk.Button(btn_frame, text="RSA", command=on_asymmetric_click, width=12).pack(side=tk.LEFT, padx=3)
tk.Button(btn_frame, text="Password", command=on_password_click, width=12).pack(side=tk.LEFT, padx=3)
tk.Button(btn_frame, text="HMAC", command=on_hmac_click, width=12).pack(side=tk.LEFT, padx=3)
tk.Button(btn_frame, text="Sign", command=on_sign_click, width=12).pack(side=tk.LEFT, padx=3)

file_frame = tk.Frame(root)
file_frame.pack(pady=5)

tk.Button(file_frame, text="Hash File", command=on_file_hash_click, width=15).pack(side=tk.LEFT, padx=3)
tk.Button(file_frame, text="Encrypt File", command=on_file_encrypt_click, width=15).pack(side=tk.LEFT, padx=3)
tk.Button(file_frame, text="Decrypt File", command=on_file_decrypt_click, width=15).pack(side=tk.LEFT, padx=3)

tk.Label(root, text="Output:", font=("Arial", 12)).pack(pady=5)

outputs = scrolledtext.ScrolledText(root, width=100, height=25, font=("Courier", 10))
outputs.pack(padx=10, pady=5)

root.mainloop()