from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.optimized_bls12_381 import curve_order
import os


class Client:
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.private_key = int.from_bytes(os.urandom(32), "big") % curve_order
        self.public_key = bls_pop.SkToPk(self.private_key)
    
    def sign(self, message: bytes) -> bytes:
        return bls_pop.Sign(self.private_key, message)
    
    def get_pubkey(self) -> bytes:
        return self.public_key

class Server:
    def __init__(self):
        self.clients = {}
        self.groups = {}
    
    def register(self, client: Client) -> bool:
        if client.client_id in self.clients:
            return False
        self.clients[client.client_id] = client.get_pubkey()
        return True
    
    def verify(self, client_id: str, message: bytes, signature: bytes) -> bool:
        if client_id not in self.clients:
            return False
        return bls_pop.Verify(self.clients[client_id], message, signature)
    
    def create_group(self, group_id: str, client_ids: list) -> bool:
        if any(id not in self.clients for id in client_ids):
            return False
        self.groups[group_id] = client_ids
        return True
    
    def verify_group(self, group_id: str, message: bytes, signatures: list, signers: list) -> bool:
        if group_id not in self.groups or set(signers) != set(self.groups[group_id]):
            return False
        return all(self.verify(s, message, sig) for s, sig in zip(signers, signatures))

def main():
    server = Server()
    clients = [Client(f"client_{i}") for i in range(1, 4)]
    
    for c in clients:
        server.register(c)
    
    msg = b"Test message"
    for c in clients:
        sig = c.sign(msg)
        print(f"{c.client_id} signature valid:", server.verify(c.client_id, msg, sig))
    
    group_id = "group1"
    members = [c.client_id for c in clients[:2]] 
    server.create_group(group_id, members)
    
    group_msg = b"Group message"
    group_sigs = [c.sign(group_msg) for c in clients[:2]]
    print("Group signature valid:", 
          server.verify_group(group_id, group_msg, group_sigs, members))

if __name__ == "__main__":
    main()