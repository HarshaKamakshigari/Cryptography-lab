import time

KEY = 3  

def decrypt_message(ciphertext):
    decrypted_message = ""
    for char in ciphertext:
        if char.isalpha():
            shift = KEY % 26
            if char.islower():
                decrypted_message += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            elif char.isupper():
                decrypted_message += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            decrypted_message += char  
    return decrypted_message

def read_encrypted_message_from_file():
    with open('encrypted_message.txt', 'r') as file:
        return file.read()

def write_decrypted_message_to_file(decrypted_message):
    with open('decrypted_message.txt', 'w') as file:
        file.write(decrypted_message)

while True:
    encrypted_message = read_encrypted_message_from_file()
    
    if encrypted_message:  
        print(f"Server: Encrypted message read: {encrypted_message}")
        
        decrypted_message = decrypt_message(encrypted_message)
        print(f"Server: Decrypted message: {decrypted_message}")
        
        write_decrypted_message_to_file(decrypted_message)
        print("Server: Decrypted message written to decrypted_message.txt")
    
    time.sleep(5) 
