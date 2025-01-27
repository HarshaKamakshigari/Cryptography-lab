import socket
from des_utils import encrypt_message, decrypt_message

SERVER_HOST = '127.0.0.1'  # Change if running on a different machine
SERVER_PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

print("[+] Connected to server.")

while True:
    message = input("Enter message to send: ")
    if message.lower() == 'exit':
        break

    encrypted_message = encrypt_message(message)
    client_socket.send(encrypted_message.encode())
    print(f"[*] Sent encrypted message: {encrypted_message}")

    received_encrypted = client_socket.recv(1024).decode()
    decrypted_response = decrypt_message(received_encrypted)
    print(f"[+] Server Response (decrypted): {decrypted_response}")

client_socket.close()
