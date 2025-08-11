#!/usr/bin/env python3

from sm2 import generate_key_pair, sign_text, verify_text, encrypt_text, decrypt_text

def main():
    print("=== SM2 Simple Usage Examples ===\n")
    
    print("1. Key Pair Generation:")
    alice = generate_key_pair()
    bob = generate_key_pair()
    print(f"Alice private key: {alice.private_key_hex}")
    print(f"Alice public key:  {alice.public_key_hex}")
    print()
    
    print("2. Digital Signature:")
    message = "Important message from Alice"
    signature = sign_text(message, alice.private_key_hex)
    print(f"Message: {message}")
    print(f"Signature: {signature}")
    
    is_valid = verify_text(message, signature, alice.public_key_hex)
    print(f"Signature valid: {is_valid}")
    print()
    
    print("3. Public Key Encryption:")
    secret = "This is a secret message for Bob"
    print(f"Original secret: {secret}")
    
    encrypted = encrypt_text(secret, bob.public_key_hex)
    print(f"Encrypted: {encrypted[:50]}...{encrypted[-50:]}")
    
    decrypted = decrypt_text(encrypted, bob.private_key_hex)
    print(f"Decrypted: {decrypted}")
    print(f"Decryption successful: {decrypted == secret}")
    print()
    
    print("4. Secure Communication Example:")
    
    message = "Meet me at the library at 3pm. -Alice"
    
    message_signature = sign_text(message, alice.private_key_hex)
    
    data_to_encrypt = f"{message}|SIGNATURE|{message_signature}"
    encrypted_data = encrypt_text(data_to_encrypt, bob.public_key_hex)
    
    print(f"Alice's message: {message}")
    print(f"Encrypted package length: {len(encrypted_data)} chars")
    
    decrypted_data = decrypt_text(encrypted_data, bob.private_key_hex)
    parts = decrypted_data.split("|SIGNATURE|")
    received_message = parts[0]
    received_signature = parts[1]
    
    signature_valid = verify_text(received_message, received_signature, alice.public_key_hex)
    
    print(f"Bob received: {received_message}")
    print(f"Signature verification: {'SUCCESS' if signature_valid else 'FAILED'}")
    print(f"Message integrity: {'CONFIRMED' if received_message == message else 'COMPROMISED'}")

if __name__ == "__main__":
    main()
