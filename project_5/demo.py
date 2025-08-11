from sm2 import (
    generate_key_pair, sign_message, verify_signature,
    encrypt_message, decrypt_message, sign_text, verify_text,
    encrypt_text, decrypt_text
)
from utils import bytes_to_hex


def print_separator(title: str):
    print(f"\n{'='*60}")
    print(f"{title:^60}")
    print('='*60)


def demonstrate_key_generation():
    print_separator("SM2 Key Pair Generation")
    
    keypair = generate_key_pair()
    
    print(f"Private Key (32 bytes):")
    print(f"  {keypair.private_key_hex}")
    print(f"\nPublic Key (64 bytes - uncompressed format):")
    print(f"  X: {keypair.public_key_hex[:64]}")
    print(f"  Y: {keypair.public_key_hex[64:]}")
    
    return keypair


def demonstrate_digital_signature(keypair):
    print_separator("SM2 Digital Signature")
    
    message_hex = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
    print(f"Message (hex): {message_hex}")
    
    signature = sign_message(message_hex, keypair.private_key_hex)
    print(f"\nSignature (64 bytes):")
    print(f"  R: {signature[:64]}")
    print(f"  S: {signature[64:]}")
    
    is_valid = verify_signature(message_hex, signature, keypair.public_key_hex)
    print(f"\nSignature Verification: {'VALID' if is_valid else 'INVALID'}")
    
    wrong_message = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F21"
    is_valid_wrong = verify_signature(wrong_message, signature, keypair.public_key_hex)
    print(f"Wrong message verification: {'VALID' if is_valid_wrong else 'INVALID'}")
    
    print(f"\nText Message Example:")
    text_message = "Hello, this is a test message for SM2 digital signature!"
    print(f"Text: {text_message}")
    
    text_signature = sign_text(text_message, keypair.private_key_hex)
    text_valid = verify_text(text_message, text_signature, keypair.public_key_hex)
    print(f"Text Signature: {text_signature[:32]}...{text_signature[-32:]}")
    print(f"Text Verification: {'VALID' if text_valid else 'INVALID'}")


def demonstrate_encryption(keypair):
    print_separator("SM2 Public Key Encryption")
    
    message_hex = "48656C6C6F2C20534D322045706872696D657261"
    message_text = bytes.fromhex(message_hex).decode('utf-8')
    print(f"Original Message: {message_text}")
    print(f"Message (hex): {message_hex}")
    
    ciphertext = encrypt_message(message_hex, keypair.public_key_hex)
    print(f"\nCiphertext Length: {len(ciphertext)} characters ({len(ciphertext)//2} bytes)")
    print(f"Ciphertext (first/last 32 chars): {ciphertext[:32]}...{ciphertext[-32:]}")
    
    decrypted_hex = decrypt_message(ciphertext, keypair.private_key_hex)
    decrypted_text = bytes.fromhex(decrypted_hex).decode('utf-8')
    print(f"\nDecrypted Message: {decrypted_text}")
    print(f"Decrypted (hex): {decrypted_hex}")
    print(f"Decryption Success: {'YES' if decrypted_hex.lower() == message_hex.lower() else 'NO'}")
    
    print(f"\nDirect Text Encryption:")
    test_text = "SM2 encryption works great for protecting sensitive data!"
    print(f"Original Text: {test_text}")
    
    encrypted_text = encrypt_text(test_text, keypair.public_key_hex)
    decrypted_text = decrypt_text(encrypted_text, keypair.private_key_hex)
    
    print(f"Encrypted (first/last 32 chars): {encrypted_text[:32]}...{encrypted_text[-32:]}")
    print(f"Decrypted Text: {decrypted_text}")
    print(f"Text Encryption Success: {'YES' if decrypted_text == test_text else 'NO'}")


def demonstrate_cross_compatibility():
    print_separator("Cross-Compatibility Test")
    
    alice_keypair = generate_key_pair()
    bob_keypair = generate_key_pair()
    
    print("Alice's public key:", alice_keypair.public_key_hex[:32] + "...")
    print("Bob's public key:  ", bob_keypair.public_key_hex[:32] + "...")
    
    secret_message = "This is a secret message from Alice to Bob using SM2!"
    print(f"\nAlice's message: {secret_message}")
    
    encrypted_for_bob = encrypt_text(secret_message, bob_keypair.public_key_hex)
    print(f"Encrypted for Bob (length: {len(encrypted_for_bob)} chars)")
    
    decrypted_by_bob = decrypt_text(encrypted_for_bob, bob_keypair.private_key_hex)
    print(f"Bob decrypted: {decrypted_by_bob}")
    
    success = decrypted_by_bob == secret_message
    print(f"Cross-party encryption: {'SUCCESS' if success else 'FAILED'}")
    
    response = "Message received and verified! - Bob"
    response_signature = sign_text(response, bob_keypair.private_key_hex)
    
    signature_valid = verify_text(response, response_signature, bob_keypair.public_key_hex)
    print(f"\nBob's response: {response}")
    print(f"Signature verification by Alice: {'VALID' if signature_valid else 'INVALID'}")


def demonstrate_large_data():
    print_separator("Large Data Encryption")
    
    keypair = generate_key_pair()
    
    large_message = "SM2 Encryption Test: " + "A" * 1000 + " End of test data."
    print(f"Large message length: {len(large_message)} characters")
    print(f"First 60 chars: {large_message[:60]}...")
    print(f"Last 60 chars:  ...{large_message[-60:]}")
    
    encrypted_large = encrypt_text(large_message, keypair.public_key_hex)
    decrypted_large = decrypt_text(encrypted_large, keypair.private_key_hex)
    
    print(f"\nEncrypted length: {len(encrypted_large)} characters")
    print(f"Decryption success: {'YES' if decrypted_large == large_message else 'NO'}")
    
    if decrypted_large == large_message:
        print("First 60 chars of decrypted:", decrypted_large[:60] + "...")
        print("Last 60 chars of decrypted: ..." + decrypted_large[-60:])


def demonstrate_complete_workflow():
    print_separator("完整工作流程示例 - Alice 和 Bob 通信")
    
    print("步骤 1: 生成密钥对")
    alice = generate_key_pair()
    bob = generate_key_pair()
    
    print(f"Alice 公钥: {alice.public_key_hex[:32]}...")
    print(f"Bob 公钥:   {bob.public_key_hex[:32]}...")
    
    print(f"\n步骤 2: Alice 发送签名消息")
    message = "你好 Bob，我是 Alice！这是一条重要的消息。"
    print(f"原始消息: {message}")
    
    signature = sign_text(message, alice.private_key_hex)
    print(f"Alice 的签名: {signature[:32]}...{signature[-32:]}")
    
    print(f"\n步骤 3: Bob 验证 Alice 的签名")
    is_authentic = verify_text(message, signature, alice.public_key_hex)
    print(f"签名验证结果: {'验证通过 ✓' if is_authentic else '验证失败 ✗'}")
    print(f"Bob: {'消息确实来自 Alice' if is_authentic else '警告：消息可能被篡改！'}")
    
    print(f"\n步骤 4: Bob 加密回复给 Alice")
    reply = "你好 Alice！我是 Bob，消息已收到并验证通过。这是我的加密回复。"
    print(f"Bob 的回复: {reply}")
    
    encrypted_reply = encrypt_text(reply, alice.public_key_hex)
    print(f"加密后的回复长度: {len(encrypted_reply)} 字符")
    print(f"加密回复 (部分): {encrypted_reply[:64]}...")
    
    print(f"\n步骤 5: Alice 解密 Bob 的回复")
    decrypted_reply = decrypt_text(encrypted_reply, alice.private_key_hex)
    print(f"解密后的回复: {decrypted_reply}")
    
    decryption_success = decrypted_reply == reply
    print(f"解密验证: {'成功 ✓' if decryption_success else '失败 ✗'}")
    
    print(f"\n步骤 6: Alice 签名确认收到回复")
    confirmation = f"收到你的回复：{reply[:20]}... - Alice 已确认"
    confirmation_signature = sign_text(confirmation, alice.private_key_hex)
    
    print(f"Alice 确认消息: {confirmation}")
    print(f"确认签名: {confirmation_signature[:32]}...{confirmation_signature[-32:]}")
    
    print(f"\n步骤 7: Bob 验证 Alice 的确认")
    confirmation_valid = verify_text(confirmation, confirmation_signature, alice.public_key_hex)
    print(f"确认签名验证: {'通过 ✓' if confirmation_valid else '失败 ✗'}")
    
    print(f"\n🎉 完整通信流程完成！")
    print(f"✓ Alice 发送了签名消息")
    print(f"✓ Bob 验证了消息的真实性") 
    print(f"✓ Bob 发送了加密回复")
    print(f"✓ Alice 成功解密了回复")
    print(f"✓ Alice 发送了签名确认")
    print(f"✓ Bob 验证了确认的真实性")


def main():
    print("SM2 Cryptographic Algorithm Demonstration")
    print("Based on GM/T 0003.5-2012 Standard")
    
    try:
        keypair = demonstrate_key_generation()
        
        demonstrate_digital_signature(keypair)
        demonstrate_encryption(keypair)
        demonstrate_cross_compatibility()
        demonstrate_large_data()
        demonstrate_complete_workflow()
        demonstrate_complete_workflow()
        
        print_separator("Demonstration Complete")
        print("All SM2 operations completed successfully!")
        print("\nThis implementation supports:")
        print("• Key pair generation with cryptographically secure random numbers")
        print("• Digital signature generation and verification")
        print("• Public key encryption and decryption")
        print("• Hexadecimal string input/output format")
        print("• Text string convenience functions")
        print("• Cross-compatibility between different key pairs")
        
    except Exception as e:
        print(f"\nError during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
