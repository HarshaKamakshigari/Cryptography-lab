from Crypto.Cipher import DES
import base64

DES_KEY = b'8bytekey' 

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_message(message):
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    padded_text = pad(message)
    encrypted_text = cipher.encrypt(padded_text.encode())
    return base64.b64encode(encrypted_text).decode()

def decrypt_message(encrypted_message):
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    decoded_encrypted_message = base64.b64decode(encrypted_message)
    decrypted_text = cipher.decrypt(decoded_encrypted_message).decode().rstrip()
    return decrypted_text
