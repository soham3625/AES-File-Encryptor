import os
from tkinter import Tk, Label, Button, filedialog, Entry, StringVar, messagebox
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256

def derive_key(password):
    return sha256(password.encode()).digest()

def pad(data):
    pad_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_length]) * pad_length

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(file_path, password):
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext))

    encrypted_path = file_path + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(iv + ciphertext)

    messagebox.showinfo("Success", f"Encrypted file saved as:\n{encrypted_path}")

def decrypt_file(file_path, password):
    key = derive_key(password)

    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    if file_path.endswith('.enc'):
        original_path = file_path[:-4]
    else:
        original_path = file_path + '.dec'

    if os.path.exists(original_path):
        if not messagebox.askyesno("Overwrite?", f"{original_path} exists. Overwrite?"):
            return

    with open(original_path, 'wb') as f:
        f.write(plaintext)

    messagebox.showinfo("Success", f"Decrypted file saved as:\n{original_path}")

def browse_file():
    file_path = filedialog.askopenfilename()
    file_var.set(file_path)

def run_process():
    path = file_var.get()
    password = pass_var.get()
    if not os.path.isfile(path):
        messagebox.showerror("Error", "File not found.")
        return
    if not password:
        messagebox.showerror("Error", "Secret key.")
        return

    if mode_var.get() == "Encrypt":
        encrypt_file(path, password)
    else:
        decrypt_file(path, password)

app = Tk()
app.title("AES File Encryptor/Decryptor")
app.geometry("400x200")

file_var = StringVar()
pass_var = StringVar()
mode_var = StringVar(value="Encrypt")

Label(app, text="Select File:").pack()
Entry(app, textvariable=file_var, width=50).pack()
Button(app, text="Browse", command=browse_file).pack(pady=2)

Label(app, text="Secret key:").pack()
Entry(app, textvariable=pass_var, show="*", width=50).pack()
Button(app, text="Encrypt", command=lambda: mode_var.set("Encrypt")).pack(side="left", padx=20, pady=10)
Button(app, text="Decrypt", command=lambda: mode_var.set("Decrypt")).pack(side="left", padx=20)

Button(app, text="Run", command=run_process).pack(side="right", padx=20)

app.mainloop()
