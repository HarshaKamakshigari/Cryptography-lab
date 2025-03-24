import hashlib

def gen_sha512(text):
    hash_object = hashlib.sha512(text.encode())
    return hash_object.hexdigest()

message = input("Enter the msg: ")
hash_code = gen_sha512(message)
print("Hash Code:", hash_code)
