from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii


def encrypt_AES(message, key):
    cipher = AES.new(key, AES.MODE_GCM)  
    encrypted_data, tag = cipher.encrypt_and_digest(message) 
    return encrypted_data, cipher.nonce, tag 


def decrypt_AES(encrypted_data, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce)  
    return cipher.decrypt_and_verify(encrypted_data, tag) 

def get_secret_key(point):
    hash_object = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    hash_object.update(int.to_bytes(point.y, 32, 'big'))
    return hash_object.digest() 


def encrypt_ECC(message, public_key, curve):
    temp_private_key = secrets.randbelow(curve.field.n)  
    shared_key_point = temp_private_key * public_key  
    secret_key = get_secret_key(shared_key_point)  
    encrypted_data, nonce, tag = encrypt_AES(message, secret_key)  

    temp_public_key = temp_private_key * curve.g  
    return encrypted_data, nonce, tag, temp_public_key

def decrypt_ECC(encrypted_data, nonce, tag, temp_public_key, private_key):
    shared_key_point = private_key * temp_public_key  
    secret_key = get_secret_key(shared_key_point)  
    return decrypt_AES(encrypted_data, nonce, tag, secret_key)  

def test_encryption(curve_name):
    print(f"\nUsing Curve: {curve_name}")
    curve = registry.get_curve(curve_name)  

    private_key = secrets.randbelow(curve.field.n)  
    public_key = private_key * curve.g  

    message = b'Hell0 SRM AP'
    print("Original Message:", message)

    encrypted_data, nonce, tag, temp_public_key = encrypt_ECC(message, public_key, curve)

    encrypted_msg_info = {
        'ciphertext': binascii.hexlify(encrypted_data).decode(),
        'nonce': binascii.hexlify(nonce).decode(),
        'authTag': binascii.hexlify(tag).decode(),
        'tempPublicKey': hex(temp_public_key.x) + hex(temp_public_key.y % 2)[2:]
    }
    print("Encrypted Message:", encrypted_msg_info)

    decrypted_message = decrypt_ECC(encrypted_data, nonce, tag, temp_public_key, private_key)
    print("Decrypted Message:", decrypted_message)

test_encryption('brainpoolP192r1')
test_encryption('brainpoolP256r1')