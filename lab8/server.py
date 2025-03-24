import socket
import hashlib
import random
import base64
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore

def generate_dh_key():
    prime = 23  
    g = 5       
    private_key = random.randint(1, prime-1)
    public_key = pow(g, private_key, prime)
    return private_key, public_key, prime, g

def calculate_shared_secret(private_key, other_public_key, prime):
    shared_secret = pow(other_public_key, private_key, prime)
    shared_key = hashlib.sha512(str(shared_secret).encode()).digest()[:32]
    return shared_key

def compute_hash(message):
    return hashlib.sha512(message.encode()).digest()

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    message_hash = compute_hash(message)
    data = message.encode() + message_hash
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cipher.iv + encrypted_data).decode()

def decrypt_message(encrypted_data, key):
    raw_data = base64.b64decode(encrypted_data)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    hash_size = 64 
    decrypted_message = decrypted_data[:-hash_size]
    received_hash = decrypted_data[-hash_size:]
    calculated_hash = compute_hash(decrypted_message.decode())
    integrity_verified = (calculated_hash == received_hash)
    return decrypted_message.decode(), integrity_verified

def main():
    server_private, server_public, prime, g = generate_dh_key()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 4000))
    server_socket.listen(1)
    print('Server is listening on port 4000...')
    
    client_socket, address = server_socket.accept()
    print(f"Client {address} connected")
    
    params = f"{server_public},{prime},{g}"
    client_socket.send(params.encode())
    
    client_public = int(client_socket.recv(1024).decode())
    print(f"Client's public key: {client_public}")
    
    shared_key = calculate_shared_secret(server_private, client_public, prime)
    print("Shared key established")
    
    encrypted_msg = client_socket.recv(1024).decode()
    decrypted_msg, integrity_ok = decrypt_message(encrypted_msg, shared_key)
    
    print("\nReceived message:")
    print(f"Content: {decrypted_msg}")
    print(f"Integrity check: {'PASSED' if integrity_ok else 'FAILED'}")
    
    response = "Message received with integrity verification"
    encrypted_response = encrypt_message(response, shared_key)
    client_socket.send(encrypted_response.encode())
    
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
     main()