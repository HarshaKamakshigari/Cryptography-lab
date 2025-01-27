from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(plain_text, key):
    
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes long")
    
    
    plain_bytes = plain_text.encode('utf-8')
    padded_text = pad(plain_bytes, DES.block_size)
    
    
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    
    
    encrypted_bytes = cipher.encrypt(padded_text)
    
    return encrypted_bytes.hex()

def des_decrypt(encrypted_text, key):
    
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes long")
    
    
    encrypted_bytes = bytes.fromhex(encrypted_text)
    
    
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    
    
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    
    
    return unpad(decrypted_padded, DES.block_size).decode('utf-8')


plain_text = input("Enter plaintext : ")
key = input("Enter 8-character key: ")


if len(key) != 8:
    print("Error: Key must be exactly 8 characters long.")
else:
    
    encrypted_text = des_encrypt(plain_text, key)
    print("Encrypted:", encrypted_text)

    decrypted_text = des_decrypt(encrypted_text, key)
    print("Decrypted:", decrypted_text)
