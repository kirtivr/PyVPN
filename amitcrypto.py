
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)  # Generate a random 16-byte key for AES-128
iv = os.urandom(16)   # Initialization vector for CBC mode

def enc(sock, message, addr):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    sock.sendto(encrypted_message, addr)
    return encrypted_message

def dec(sock, message, addr):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(message)
    unpadded_message = unpad(decrypted_message, AES.block_size)
    return unpadded_message.decode()