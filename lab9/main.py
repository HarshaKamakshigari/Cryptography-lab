# Import necessary libraries
from py_ecc.bls.ciphersuites import G2ProofOfPossession as BLS_POP
from py_ecc.bls.ciphersuites import G2Basic
from py_ecc.bls.ciphersuites import G2MessageAugmentation
import secrets

def generate_private_key():
  
    key_bytes = secrets.token_bytes(32)
    return int.from_bytes(key_bytes, byteorder='big') % (2**128)  

class Client:
    """Represents a client that can sign messages and verify signatures."""
    
    def __init__(self, name, ciphersuite=BLS_POP):
        self.name = name
        self.ciphersuite = ciphersuite
        # Generate a private key and derive the public key with retry mechanism
        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                self.private_key = generate_private_key()
                self.public_key = self.ciphersuite.SkToPk(self.private_key)
                print(f"Successfully generated keys for {name}")
                break  # If we get here, the key is valid
            except Exception as e:
                if attempt == max_attempts - 1:
                    print(f"Failed to generate valid keys for {name} after {max_attempts} attempts")
                    raise
                # Otherwise, try again with a different key
    
    def sign_message(self, message):
        """Sign a message using the client's private key."""
        try:
            signature = self.ciphersuite.Sign(self.private_key, message)
            return signature
        except Exception as e:
            print(f"Error signing message by {self.name}: {e}")
            raise
    
    def verify_signature(self, public_key, message, signature):
        """Verify a signature using the public key."""
        try:
            return self.ciphersuite.Verify(public_key, message, signature)
        except Exception as e:
            print(f"Error verifying signature by {self.name}: {e}")
            return False

def demonstrate_individual_signing(clients, message):
    """Demonstrate how individual clients sign and verify messages."""
    print("\n=== Individual Signing and Verification ===")
    signatures = {}
    
    for client in clients:
        print(f"\nClient {client.name} signing message: {message}")
        signature = client.sign_message(message)
        signatures[client.name] = signature
        
        # Verify own signature
        verification_result = client.verify_signature(client.public_key, message, signature)
        print(f"Client {client.name} verifies own signature: {verification_result}")
        
        # Other clients verify the signature
        for verifier in clients:
            if verifier.name != client.name:
                verification_result = verifier.verify_signature(client.public_key, message, signature)
                print(f"Client {verifier.name} verifies {client.name}'s signature: {verification_result}")
    
    return signatures

def demonstrate_aggregate_signing_same_message(clients, message):
    """Demonstrate how to aggregate signatures from multiple clients on the same message."""
    print("\n=== Aggregate Signing (Same Message) ===")
    
    # Collect public keys and signatures from all clients
    public_keys = [client.public_key for client in clients]
    signatures = [client.sign_message(message) for client in clients]
    
    try:
        # Aggregate signatures into a single signature
        aggregate_signature = clients[0].ciphersuite.Aggregate(signatures)
        print(f"Created aggregate signature for {len(clients)} clients")
        
        # Verify the aggregate signature against all public keys
        verification_result = clients[0].ciphersuite.FastAggregateVerify(public_keys, message, aggregate_signature)
        print(f"Verification of aggregate signature: {verification_result}")
        
        return aggregate_signature
    except Exception as e:
        print(f"Error in aggregate signing: {e}")
        return None

def demonstrate_aggregate_signing_different_messages(clients, messages):
    """Demonstrate how to aggregate signatures from multiple clients on different messages."""
    print("\n=== Aggregate Signing (Different Messages) ===")
    
    if len(clients) != len(messages):
        print("Error: Number of clients must match number of messages")
        return None
    
    try:
        # Collect public keys and signatures from all clients (each with a different message)
        public_keys = [client.public_key for client in clients]
        signatures = [client.sign_message(message) for client, message in zip(clients, messages)]
        
        # Aggregate signatures into a single signature
        aggregate_signature = clients[0].ciphersuite.Aggregate(signatures)
        print(f"Created aggregate signature for {len(clients)} clients with different messages")
        
        # Verify the aggregate signature against all public keys and messages
        verification_result = clients[0].ciphersuite.AggregateVerify(public_keys, messages, aggregate_signature)
        print(f"Verification of aggregate signature: {verification_result}")
        
        return aggregate_signature
    except Exception as e:
        print(f"Error in aggregate signing with different messages: {e}")
        return None

def simulate_document_workflow():
    """Simulate a workflow where a document is passed between clients for signing."""
    print("\n=== Document Workflow Simulation ===")
    
    # Create a document
    document = b"This is a legal contract between multiple parties..."
    print(f"Original document: {document.decode()}")
    
    try:
        # Create clients
        alice = Client("Alice")
        bob = Client("Bob")
        charlie = Client("Charlie")
        
        # Document is passed in sequence for signing
        print("\nDocument signing workflow:")
        
        # Alice signs first
        print("\nStep 1: Alice signs the document")
        alice_signature = alice.sign_message(document)
        print(f"  Signature created")
        
        # Verify Alice's signature before proceeding
        alice_verification = alice.verify_signature(alice.public_key, document, alice_signature)
        print(f"  Signature verification: {alice_verification}")
        
        # Bob signs next
        print("\nStep 2: Bob signs the document")
        bob_signature = bob.sign_message(document)
        print(f"  Signature created")
        
        # Verify Bob's signature before proceeding
        bob_verification = bob.verify_signature(bob.public_key, document, bob_signature)
        print(f"  Signature verification: {bob_verification}")
        
        # Charlie signs last
        print("\nStep 3: Charlie signs the document")
        charlie_signature = charlie.sign_message(document)
        print(f"  Signature created")
        
        # Verify Charlie's signature
        charlie_verification = charlie.verify_signature(charlie.public_key, document, charlie_signature)
        print(f"  Signature verification: {charlie_verification}")
        
        # Aggregate all signatures for efficient storage and verification
        print("\nFinal step: Aggregate all signatures for efficient verification")
        all_signatures = [alice_signature, bob_signature, charlie_signature]
        all_public_keys = [alice.public_key, bob.public_key, charlie.public_key]
        
        aggregate_signature = alice.ciphersuite.Aggregate(all_signatures)
        print(f"  Created an aggregate signature containing all three signatures")
        
        # Verify the aggregate signature
        aggregate_verification = alice.ciphersuite.FastAggregateVerify(
            all_public_keys, document, aggregate_signature
        )
        print(f"  Verification of the aggregate signature: {aggregate_verification}")
        print("  If verification succeeds, we know all parties have signed the document!")
    
    except Exception as e:
        print(f"Error in document workflow simulation: {e}")

def main():
    """Main function to run all demonstrations."""
    print("Digital Signature Simulation using py_ecc BLS Ciphersuites")
    print("--------------------------------------------------------")
    
    try:
        # Create clients using the BLS_POP ciphersuite
        print("Creating clients...")
        client1 = Client("Client1", BLS_POP)
        client2 = Client("Client2", BLS_POP)
        client3 = Client("Client3", BLS_POP)
        
        clients = [client1, client2, client3]
        
        # Create a sample message
        message = b"Hello, this is a test message!"
        print(f"\nSample message: {message.decode()}")
        
        # 1. Demonstrate individual signing and verification
        individual_signatures = demonstrate_individual_signing(clients, message)
        
        # 2. Demonstrate aggregate signing with the same message
        aggregate_signature = demonstrate_aggregate_signing_same_message(clients, message)
        
        # 3. Demonstrate aggregate signing with different messages
        different_messages = [
            b"Message for Client1",
            b"Message for Client2", 
            b"Message for Client3"
        ]
        aggregate_signature_diff = demonstrate_aggregate_signing_different_messages(clients, different_messages)
        
        # 4. Simulate a real-world document workflow
        simulate_document_workflow()
    
    except Exception as e:
        print(f"Error in main execution: {e}")

if __name__ == "__main__":
    main()