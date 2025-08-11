import hashlib
from typing import Tuple, Optional
from sm2_math import (
    Point, G, N, P, A, B,
    point_multiply, point_add, generate_random_in_range,
    is_on_curve, mod_inverse, sm3_hash, kdf
)
from utils import (
    hex_to_bytes, bytes_to_hex, int_to_hex, hex_to_int,
    int_to_bytes, bytes_to_int, pad_hex, xor_bytes
)


class SM2KeyPair:
    
    def __init__(self, private_key_hex: str, public_key_hex: str):
        self.private_key_hex = private_key_hex
        self.public_key_hex = public_key_hex
        
        self.private_key = hex_to_int(private_key_hex)
        
        public_key_bytes = hex_to_bytes(public_key_hex)
        if len(public_key_bytes) != 64:
            raise ValueError("Public key must be 64 bytes (128 hex characters)")
        
        self.public_key_point = Point(
            bytes_to_int(public_key_bytes[:32]),
            bytes_to_int(public_key_bytes[32:])
        )
        
        if not is_on_curve(self.public_key_point):
            raise ValueError("Public key point is not on the SM2 curve")


def generate_key_pair() -> SM2KeyPair:
    private_key = generate_random_in_range(N)
    
    public_key_point = point_multiply(private_key, G)
    
    private_key_hex = int_to_hex(private_key, 32)
    public_key_hex = (
        int_to_hex(public_key_point.x, 32) +
        int_to_hex(public_key_point.y, 32)
    )
    
    return SM2KeyPair(private_key_hex, public_key_hex)


def _get_z_value(user_id: bytes, public_key_point: Point) -> bytes:
    entl = len(user_id) * 8
    entl_bytes = entl.to_bytes(2, byteorder='big')
    
    a_bytes = int_to_bytes(A, 32)
    b_bytes = int_to_bytes(B, 32)
    gx_bytes = int_to_bytes(G.x, 32)
    gy_bytes = int_to_bytes(G.y, 32)
    qx_bytes = int_to_bytes(public_key_point.x, 32)
    qy_bytes = int_to_bytes(public_key_point.y, 32)
    
    z_input = (entl_bytes + user_id + a_bytes + b_bytes + 
               gx_bytes + gy_bytes + qx_bytes + qy_bytes)
    
    return sm3_hash(z_input)


def sign_message(message_hex: str, private_key_hex: str, 
                 user_id: str = "1234567812345678") -> str:
    message = hex_to_bytes(message_hex)
    private_key = hex_to_int(private_key_hex)
    user_id_bytes = user_id.encode('utf-8')
    
    public_key_point = point_multiply(private_key, G)
    
    z_value = _get_z_value(user_id_bytes, public_key_point)
    
    hash_input = z_value + message
    message_hash = sm3_hash(hash_input)
    e = bytes_to_int(message_hash) % N
    
    while True:
        k = generate_random_in_range(N)
        
        point_k = point_multiply(k, G)
        x1 = point_k.x
        
        r = (e + x1) % N
        if r == 0 or (r + k) % N == 0:
            continue
        
        d_inv = mod_inverse((1 + private_key) % N, N)
        s = (d_inv * (k - (r * private_key) % N)) % N
        if s == 0:
            continue
        
        break
    
    r_hex = int_to_hex(r, 32)
    s_hex = int_to_hex(s, 32)
    return r_hex + s_hex


def verify_signature(message_hex: str, signature_hex: str, public_key_hex: str,
                     user_id: str = "1234567812345678") -> bool:
    try:
        message = hex_to_bytes(message_hex)
        user_id_bytes = user_id.encode('utf-8')
        
        if len(signature_hex) != 128:
            return False
        r = hex_to_int(signature_hex[:64])
        s = hex_to_int(signature_hex[64:])
        
        public_key_bytes = hex_to_bytes(public_key_hex)
        if len(public_key_bytes) != 64:
            return False
        
        public_key_point = Point(
            bytes_to_int(public_key_bytes[:32]),
            bytes_to_int(public_key_bytes[32:])
        )
        
        if not is_on_curve(public_key_point):
            return False
        
        if not (1 <= r < N and 1 <= s < N):
            return False
        
        z_value = _get_z_value(user_id_bytes, public_key_point)
        
        hash_input = z_value + message
        message_hash = sm3_hash(hash_input)
        e = bytes_to_int(message_hash) % N
        
        t = (r + s) % N
        if t == 0:
            return False
        
        point_s = point_multiply(s, G)
        point_t = point_multiply(t, public_key_point)
        point_result = point_add(point_s, point_t)
        
        if point_result.is_infinity:
            return False
        
        R = (e + point_result.x) % N
        return R == r
        
    except Exception:
        return False


def encrypt_message(message_hex: str, public_key_hex: str) -> str:
    message = hex_to_bytes(message_hex)
    message_len = len(message)
    
    public_key_bytes = hex_to_bytes(public_key_hex)
    if len(public_key_bytes) != 64:
        raise ValueError("Public key must be 64 bytes")
    
    public_key_point = Point(
        bytes_to_int(public_key_bytes[:32]),
        bytes_to_int(public_key_bytes[32:])
    )
    
    if not is_on_curve(public_key_point):
        raise ValueError("Public key point is not on curve")
    
    while True:
        k = generate_random_in_range(N)
        
        c1_point = point_multiply(k, G)
        
        shared_point = point_multiply(k, public_key_point)
        if shared_point.is_infinity:
            continue
        
        kdf_input = int_to_bytes(shared_point.x, 32) + int_to_bytes(shared_point.y, 32)
        key_material = kdf(kdf_input, message_len)
        
        if all(b == 0 for b in key_material):
            continue
        
        c2 = xor_bytes(message, key_material)
        
        hash_input = (int_to_bytes(shared_point.x, 32) + message + 
                      int_to_bytes(shared_point.y, 32))
        c3 = sm3_hash(hash_input)
        
        break
    
    c1_bytes = int_to_bytes(c1_point.x, 32) + int_to_bytes(c1_point.y, 32)
    ciphertext = c1_bytes + c3 + c2
    
    return bytes_to_hex(ciphertext)


def decrypt_message(ciphertext_hex: str, private_key_hex: str) -> str:
    ciphertext = hex_to_bytes(ciphertext_hex)
    private_key = hex_to_int(private_key_hex)
    
    if len(ciphertext) < 97:
        raise ValueError("Ciphertext too short")
    
    c1_bytes = ciphertext[:64]
    c1_point = Point(
        bytes_to_int(c1_bytes[:32]),
        bytes_to_int(c1_bytes[32:])
    )
    
    if not is_on_curve(c1_point):
        raise ValueError("C1 point is not on curve")
    
    c3 = ciphertext[64:96]
    
    c2 = ciphertext[96:]
    c2_len = len(c2)
    
    shared_point = point_multiply(private_key, c1_point)
    if shared_point.is_infinity:
        raise ValueError("Invalid ciphertext: shared secret is point at infinity")
    
    kdf_input = int_to_bytes(shared_point.x, 32) + int_to_bytes(shared_point.y, 32)
    key_material = kdf(kdf_input, c2_len)
    
    message = xor_bytes(c2, key_material)
    
    hash_input = (int_to_bytes(shared_point.x, 32) + message + 
                  int_to_bytes(shared_point.y, 32))
    expected_c3 = sm3_hash(hash_input)
    
    if c3 != expected_c3:
        raise ValueError("Integrity check failed: invalid ciphertext or key")
    
    return bytes_to_hex(message)


def key_exchange_init(private_key_hex: str, peer_public_key_hex: str) -> Tuple[str, str]:
    ephemeral_private = generate_random_in_range(N)
    ephemeral_public_point = point_multiply(ephemeral_private, G)
    
    peer_public_bytes = hex_to_bytes(peer_public_key_hex)
    peer_public_point = Point(
        bytes_to_int(peer_public_bytes[:32]),
        bytes_to_int(peer_public_bytes[32:])
    )
    
    private_key = hex_to_int(private_key_hex)
    shared_point = point_multiply(private_key + ephemeral_private, peer_public_point)
    
    ephemeral_public_hex = (
        int_to_hex(ephemeral_public_point.x, 32) +
        int_to_hex(ephemeral_public_point.y, 32)
    )
    shared_secret_hex = int_to_hex(shared_point.x, 32)
    
    return ephemeral_public_hex, shared_secret_hex


def sign_text(text: str, private_key_hex: str, user_id: str = "1234567812345678") -> str:
    message_hex = bytes_to_hex(text.encode('utf-8'))
    return sign_message(message_hex, private_key_hex, user_id)


def verify_text(text: str, signature_hex: str, public_key_hex: str,
                user_id: str = "1234567812345678") -> bool:
    message_hex = bytes_to_hex(text.encode('utf-8'))
    return verify_signature(message_hex, signature_hex, public_key_hex, user_id)


def encrypt_text(text: str, public_key_hex: str) -> str:
    message_hex = bytes_to_hex(text.encode('utf-8'))
    return encrypt_message(message_hex, public_key_hex)


def decrypt_text(ciphertext_hex: str, private_key_hex: str) -> str:
    message_hex = decrypt_message(ciphertext_hex, private_key_hex)
    return hex_to_bytes(message_hex).decode('utf-8')
