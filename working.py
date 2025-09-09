import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
import base64

# --- Padding Functions ---
def pad(text, block_size=16):
    while len(text) % block_size != 0:
        text += ' '
    return text

# --- Encrypt Function ---
def encrypt_text():
    plaintext = input_text.get("1.0", tk.END).strip()

    if not plaintext:
        messagebox.showwarning("Warning", "Please enter text!")
        return

    key = b'ThisIsA16ByteKey'  # 16 bytes fixed key
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, 16)

    encrypted = cipher.encrypt(padded.encode())
    encrypted_b64 = base64.b64encode(encrypted).decode()
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted_b64)

# --- Decrypt Function ---
def decrypt_text():
    encrypted_b64 = input_text.get("1.0", tk.END).strip()

    if not encrypted_b64:
        messagebox.showwarning("Warning", "Please enter encrypted text!")
        return

    try:
        encrypted = base64.b64decode(encrypted_b64)
    except:
        messagebox.showerror("Error", "Invalid base64 input!")
        return

    key = b'ThisIsA16ByteKey'
    cipher = AES.new(key, AES.MODE_ECB)

    decrypted = cipher.decrypt(encrypted).decode().rstrip()
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decrypted)

# --- UI Setup ---
root = tk.Tk()
root.title("AES Encryption/Decryption")
root.geometry("500x400")

# Input text
tk.Label(root, text="Enter Text:", font=("Arial", 12)).pack(pady=5)
input_text = tk.Text(root, height=4, width=50)
input_text.pack(pady=5)

# Buttons
frame = tk.Frame(root)
frame.pack(pady=10)

encrypt_btn = tk.Button(frame, text="Encrypt", command=encrypt_text, bg="lightblue", width=12)
encrypt_btn.grid(row=0, column=0, padx=10)

decrypt_btn = tk.Button(frame, text="Decrypt", command=decrypt_text, bg="lightgreen", width=12)
decrypt_btn.grid(row=0, column=1, padx=10)

# Output text
tk.Label(root, text="Result:", font=("Arial", 12)).pack(pady=5)
output_text = tk.Text(root, height=4, width=50)
output_text.pack(pady=5)

root.mainloop()
