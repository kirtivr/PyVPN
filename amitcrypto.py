from Crypto.Cipher import XOR
 from Crypto.Cipher import AES
 from Crypto.Util.Padding import pad, unpad
 import os
 
 key = b'abcdefghijklmnop'  # 16-byte key for AES-128

def enc(sock, message, addr):
     # Convert message to bytes if it's a string
     if isinstance(message, str):
         message_bytes = message.encode()
     else:
         message_bytes = message
     iv = os.urandom(16)  # Generate random IV
     cipher = AES.new(key, AES.MODE_CBC, iv)
     padded_message = pad(message_bytes, AES.block_size)
     ciphertext = cipher.encrypt(padded_message)
     encrypted_data = iv + ciphertext
     sock.sendto(encrypted_data, addr)
     return encrypted_data

def dec(sock, message, addr):
     iv = message[:16]
     ciphertext = message[16:]
     cipher = AES.new(key, AES.MODE_CBC, iv)
     padded_plaintext = cipher.decrypt(ciphertext)
     plaintext_bytes = unpad(padded_plaintext, AES.block_size)
     return plaintext_bytes

#message = "dfjsdfjsdfjdsfdfsk"
#print message
#newm = enc(1, message, message)
#print newm
#print dec(1, newm, newm)
