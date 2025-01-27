import time
KEY = 3 

def encrypt_message(plaintext):
    encrypted_message = ""
    for char in plaintext:
        if char.isalpha():  
            shift = KEY % 26
            if char.islower():
                encrypted_message += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif char.isupper():
                encrypted_message += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            encrypted_message += char 
    return encrypted_message

def read_message_from_file():
    with open('message.txt', 'r') as file:
        return file.read()

def write_encrypted_message_to_file(encrypted_message):
    with open('encrypted_message.txt', 'w') as file:
        file.write(encrypted_message)

while True:
    message = read_message_from_file()  
    if message:  
        print(f"Client: Message from server: {message}")
        encrypted_message = encrypt_message(message) 
        print(f"Client: Encrypted message: {encrypted_message}")
        write_encrypted_message_to_file(encrypted_message) 
        print("Client: Encrypted message written to file.")
    time.sleep(5)
