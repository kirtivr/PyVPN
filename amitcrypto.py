from Crypto.Cipher import XOR

from Crypto.Cipher import AES

key = b"abcdefghijklmnop"
iv = b"abcdefghijklmnop"

def enc(sock, message, addr):
    sock.sendto(abcd, addr)

    sock.sendto(abcd, addr)
    return abcd

def dec(sock, message, addr):
    abcd = xor1.decrypt(message)
    return abcd
    abcd = xor.encrypt(message)
    print message == dec(sock, abcd, addr)
    sock.sendto(abcd, addr)
    pad_len = 16 - len(message) % 16
    padded = message + (chr(pad_len) * pad_len)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    abcd = cipher.encrypt(padded)
    sock.sendto(abcd, addr)
    return abcd

def dec(sock, message, addr):
    if len(message) % 16 != 0:
        raise ValueError("Invalid message length")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(message)
    pad_len = ord(decrypted_padded[-1])
    if pad_len < 1 or pad_len > 16 or decrypted_padded[-pad_len:] != (chr(pad_len) * pad_len):
        raise ValueError("Invalid padding")
    return decrypted_padded[:-pad_len]



