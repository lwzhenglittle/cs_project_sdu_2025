import unittest
from sm2 import (
    generate_key_pair, sign_message, verify_signature,
    encrypt_message, decrypt_message, sign_text, verify_text,
    encrypt_text, decrypt_text, SM2KeyPair
)
from sm2_math import Point, G, N, P, point_multiply, is_on_curve
from utils import hex_to_int, int_to_hex, bytes_to_hex, hex_to_bytes


class TestSM2Math(unittest.TestCase):
    
    def test_curve_parameters(self):
        self.assertTrue(is_on_curve(G))
        
        result = point_multiply(N, G)
        self.assertTrue(result.is_infinity)
        
        result = point_multiply(N - 1, G)
        self.assertFalse(result.is_infinity)
    
    def test_point_operations(self):
        p1 = Point(G.x, G.y)
        p2 = point_multiply(2, G)
        p3 = point_multiply(3, G)
        
        from sm2_math import point_add
        result = point_add(p1, p2)
        self.assertEqual(result.x, p3.x)
        self.assertEqual(result.y, p3.y)
        
        from sm2_math import point_double
        double_g = point_double(G)
        self.assertEqual(double_g.x, p2.x)
        self.assertEqual(double_g.y, p2.y)


class TestSM2KeyGeneration(unittest.TestCase):
    
    def test_key_generation(self):
        keypair = generate_key_pair()
        
        self.assertEqual(len(keypair.private_key_hex), 64)
        self.assertTrue(1 <= keypair.private_key < N)
        
        self.assertEqual(len(keypair.public_key_hex), 128)
        
        self.assertTrue(is_on_curve(keypair.public_key_point))
        
        expected_public = point_multiply(keypair.private_key, G)
        self.assertEqual(keypair.public_key_point.x, expected_public.x)
        self.assertEqual(keypair.public_key_point.y, expected_public.y)
    
    def test_deterministic_key_generation(self):
        private_key_hex = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"
        private_key = hex_to_int(private_key_hex)
        
        public_key_point = point_multiply(private_key, G)
        expected_public_hex = (
            int_to_hex(public_key_point.x, 32) + 
            int_to_hex(public_key_point.y, 32)
        )
        
        keypair = SM2KeyPair(private_key_hex, expected_public_hex)
        self.assertEqual(keypair.private_key_hex.lower(), private_key_hex.lower())


class TestSM2Signature(unittest.TestCase):
    
    def setUp(self):
        self.private_key_hex = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"
        
        private_key = hex_to_int(self.private_key_hex)
        public_key_point = point_multiply(private_key, G)
        self.public_key_hex = (
            int_to_hex(public_key_point.x, 32) + 
            int_to_hex(public_key_point.y, 32)
        )
        
        self.keypair = SM2KeyPair(self.private_key_hex, self.public_key_hex)
    
    def test_signature_generation_and_verification(self):
        message_hex = "0102030405060708"
        
        signature = sign_message(message_hex, self.private_key_hex)
        
        is_valid = verify_signature(message_hex, signature, self.public_key_hex)
        self.assertTrue(is_valid)
    
    def test_signature_format(self):
        message_hex = "AABBCCDD"
        signature = sign_message(message_hex, self.private_key_hex)
        
        self.assertEqual(len(signature), 128)
        
        from utils import validate_hex
        self.assertTrue(validate_hex(signature))
    
    def test_invalid_signature_detection(self):
        message_hex = "0102030405060708"
        
        valid_signature = sign_message(message_hex, self.private_key_hex)
        
        invalid_signature = "00" + valid_signature[2:]
        is_valid = verify_signature(message_hex, invalid_signature, self.public_key_hex)
        self.assertFalse(is_valid)
        
        modified_message = "0102030405060709"
        is_valid = verify_signature(modified_message, valid_signature, self.public_key_hex)
        self.assertFalse(is_valid)
        
        wrong_keypair = generate_key_pair()
        is_valid = verify_signature(message_hex, valid_signature, wrong_keypair.public_key_hex)
        self.assertFalse(is_valid)
    
    def test_text_signature(self):
        text = "Hello, SM2!"
        
        signature = sign_text(text, self.private_key_hex)
        is_valid = verify_text(text, signature, self.public_key_hex)
        self.assertTrue(is_valid)
        
        is_valid = verify_text("Hello, SM3!", signature, self.public_key_hex)
        self.assertFalse(is_valid)


class TestSM2Encryption(unittest.TestCase):
    
    def setUp(self):
        self.keypair = generate_key_pair()
    
    def test_encryption_and_decryption(self):
        message_hex = "0102030405060708090A0B0C0D0E0F10"
        
        ciphertext = encrypt_message(message_hex, self.keypair.public_key_hex)
        
        decrypted = decrypt_message(ciphertext, self.keypair.private_key_hex)
        
        self.assertEqual(decrypted.lower(), message_hex.lower())
    
    def test_ciphertext_format(self):
        message_hex = "AABBCCDD"
        ciphertext = encrypt_message(message_hex, self.keypair.public_key_hex)
        
        expected_length = (64 + 32 + 2) * 2
        self.assertEqual(len(ciphertext), expected_length)
    
    def test_empty_message_encryption(self):
        message_hex = ""
        
        ciphertext = encrypt_message(message_hex, self.keypair.public_key_hex)
        decrypted = decrypt_message(ciphertext, self.keypair.private_key_hex)
        
        self.assertEqual(decrypted, "")
    
    def test_large_message_encryption(self):
        message_hex = "".join([f"{i:02x}" for i in range(256)])
        
        ciphertext = encrypt_message(message_hex, self.keypair.public_key_hex)
        decrypted = decrypt_message(ciphertext, self.keypair.private_key_hex)
        
        self.assertEqual(decrypted.lower(), message_hex.lower())
    
    def test_decryption_error_detection(self):
        message_hex = "0102030405060708"
        ciphertext = encrypt_message(message_hex, self.keypair.public_key_hex)
        
        wrong_keypair = generate_key_pair()
        with self.assertRaises(ValueError):
            decrypt_message(ciphertext, wrong_keypair.private_key_hex)
        
        corrupted_ciphertext = "00" + ciphertext[2:]
        with self.assertRaises(ValueError):
            decrypt_message(corrupted_ciphertext, self.keypair.private_key_hex)
    
    def test_text_encryption(self):
        text = "Hello, SM2 encryption!"
        
        ciphertext = encrypt_text(text, self.keypair.public_key_hex)
        decrypted_text = decrypt_text(ciphertext, self.keypair.private_key_hex)
        
        self.assertEqual(decrypted_text, text)


class TestSM2TestVectors(unittest.TestCase):
    
    def test_known_signature_vector(self):
        private_key_hex = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263"
        
        private_key = hex_to_int(private_key_hex)
        public_key_point = point_multiply(private_key, G)
        public_key_hex = (
            int_to_hex(public_key_point.x, 32) + 
            int_to_hex(public_key_point.y, 32)
        )
        
        message_hex = "0102030405060708"
        
        signature = sign_message(message_hex, private_key_hex)
        is_valid = verify_signature(message_hex, signature, public_key_hex)
        
        self.assertTrue(is_valid)
        self.assertEqual(len(signature), 128)


class TestSM2EdgeCases(unittest.TestCase):
    
    def test_invalid_key_formats(self):
        with self.assertRaises(ValueError):
            hex_to_int("123")
        
        keypair = generate_key_pair()
        with self.assertRaises(ValueError):
            SM2KeyPair(keypair.private_key_hex, "123")
    
    def test_boundary_conditions(self):
        keypair = generate_key_pair()
        
        message_hex = "01"
        signature = sign_message(message_hex, keypair.private_key_hex)
        is_valid = verify_signature(message_hex, signature, keypair.public_key_hex)
        self.assertTrue(is_valid)
        
        ciphertext = encrypt_message(message_hex, keypair.public_key_hex)
        decrypted = decrypt_message(ciphertext, keypair.private_key_hex)
        self.assertEqual(decrypted.lower(), message_hex.lower())


def run_performance_test():
    import time
    
    print("\nSM2 Performance Test")
    print("=" * 50)
    
    start_time = time.time()
    num_keys = 10
    for _ in range(num_keys):
        generate_key_pair()
    key_gen_time = time.time() - start_time
    print(f"Key Generation: {key_gen_time/num_keys:.4f}s per key pair")
    
    keypair = generate_key_pair()
    message_hex = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
    
    start_time = time.time()
    num_sigs = 50
    for _ in range(num_sigs):
        sign_message(message_hex, keypair.private_key_hex)
    sign_time = time.time() - start_time
    print(f"Signature Generation: {sign_time/num_sigs:.4f}s per signature")
    
    signature = sign_message(message_hex, keypair.private_key_hex)
    start_time = time.time()
    num_verifs = 50
    for _ in range(num_verifs):
        verify_signature(message_hex, signature, keypair.public_key_hex)
    verify_time = time.time() - start_time
    print(f"Signature Verification: {verify_time/num_verifs:.4f}s per verification")
    
    start_time = time.time()
    num_encryptions = 20
    for _ in range(num_encryptions):
        encrypt_message(message_hex, keypair.public_key_hex)
    encrypt_time = time.time() - start_time
    print(f"Encryption: {encrypt_time/num_encryptions:.4f}s per encryption")


if __name__ == "__main__":
    print("Running SM2 Unit Tests...")
    unittest.main(verbosity=2, exit=False)
    
    run_performance_test()
