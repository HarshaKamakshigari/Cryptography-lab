import socket
from des_utils import encrypt_message, decrypt_message

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"[*] Listening on port {PORT}...")

client_socket, client_address = server_socket.accept()
print(f"[+] Connection from {client_address}")

while True:
    received_encrypted = client_socket.recv(1024).decode()
    if not received_encrypted:
        break

    decrypted_message = decrypt_message(received_encrypted)
    print(f"[+] Client: {decrypted_message}")

    response = input("Enter response to client: ")
    encrypted_response = encrypt_message(response)
    client_socket.send(encrypted_response.encode())

client_socket.close()
server_socket.close()
