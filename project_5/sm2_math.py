import hashlib
import secrets
from typing import Tuple, Optional


P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF

A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


class Point:
    
    def __init__(self, x: Optional[int] = None, y: Optional[int] = None):
        self.x = x
        self.y = y
        self.is_infinity = (x is None and y is None)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.is_infinity == other.is_infinity
    
    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(∞)"
        return f"Point({hex(self.x)}, {hex(self.y)})"


def mod_inverse(a: int, m: int) -> int:
    if a < 0:
        a = (a % m + m) % m
    
    original_m = m
    x0, x1 = 0, 1
    
    if m == 1:
        return 0
    
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    
    if a != 1:
        raise ValueError(f"Modular inverse does not exist for original a mod {original_m}")
    
    return (x1 % original_m + original_m) % original_m


def point_add(p1: Point, p2: Point) -> Point:
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    
    if p1.x == p2.x:
        if p1.y == p2.y:
            return point_double(p1)
        else:
            return Point()
    
    dx = (p2.x - p1.x) % P
    dy = (p2.y - p1.y) % P
    s = (dy * mod_inverse(dx, P)) % P
    
    x3 = (s * s - p1.x - p2.x) % P
    y3 = (s * (p1.x - x3) - p1.y) % P
    
    return Point(x3, y3)


def point_double(p: Point) -> Point:
    if p.is_infinity:
        return Point()
    
    if p.y == 0:
        return Point()
    
    numerator = (3 * p.x * p.x + A) % P
    denominator = (2 * p.y) % P
    s = (numerator * mod_inverse(denominator, P)) % P
    
    x3 = (s * s - 2 * p.x) % P
    y3 = (s * (p.x - x3) - p.y) % P
    
    return Point(x3, y3)


def point_multiply(k: int, point: Point) -> Point:
    if k == 0 or point.is_infinity:
        return Point()
    
    if k == 1:
        return point
    
    if k < 0:
        k = -k
        point = Point(point.x, (-point.y) % P)
    
    result = Point()
    addend = point
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    
    return result


def is_on_curve(point: Point) -> bool:
    if point.is_infinity:
        return True
    
    left = (point.y * point.y) % P
    right = (point.x * point.x * point.x + A * point.x + B) % P
    
    return left == right


def generate_random_in_range(n: int) -> int:
    while True:
        byte_length = (n.bit_length() + 7) // 8
        random_bytes = secrets.token_bytes(byte_length)
        random_int = int.from_bytes(random_bytes, byteorder='big')
        
        if 1 <= random_int < n:
            return random_int


def sm3_hash(data: bytes) -> bytes:
    from sm3 import sm3_hash as sm3_impl
    return sm3_impl(data)


def kdf(shared_key: bytes, key_len: int) -> bytes:
    if key_len == 0:
        return b''
    
    hash_len = 32
    iterations = (key_len + hash_len - 1) // hash_len
    
    result = b''
    for i in range(1, iterations + 1):
        counter = i.to_bytes(4, byteorder='big')
        hash_input = shared_key + counter
        result += sm3_hash(hash_input)
    
    return result[:key_len]


G = Point(GX, GY)

assert is_on_curve(G), "Base point G is not on the curve"
assert point_multiply(N, G).is_infinity, "Base point G does not have the correct order"
