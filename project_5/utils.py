import binascii
from typing import Union


def bytes_to_hex(data: bytes) -> str:
    return data.hex().lower()


def hex_to_bytes(hex_string: str) -> bytes:
    hex_string = hex_string.replace(' ', '').replace('\n', '').lower()
    
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    
    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal string: {hex_string}") from e


def int_to_bytes(value: int, byte_length: int = None) -> bytes:
    if byte_length is None:
        if value == 0:
            byte_length = 1
        else:
            byte_length = (value.bit_length() + 7) // 8
    
    return value.to_bytes(byte_length, byteorder='big')


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')


def int_to_hex(value: int, byte_length: int = None) -> str:
    return bytes_to_hex(int_to_bytes(value, byte_length))


def hex_to_int(hex_string: str) -> int:
    return bytes_to_int(hex_to_bytes(hex_string))


def pad_hex(hex_string: str, byte_length: int) -> str:
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    
    char_length = byte_length * 2
    
    return hex_string.zfill(char_length).lower()


def validate_hex(hex_string: str, expected_byte_length: int = None) -> bool:
    try:
        hex_string = hex_string.replace(' ', '').replace('\n', '')
        
        if hex_string.startswith('0x'):
            hex_string = hex_string[2:]
        
        int(hex_string, 16)
        
        if expected_byte_length is not None:
            if len(hex_string) != expected_byte_length * 2:
                return False
        
        return True
    except ValueError:
        return False


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"Byte sequences must have equal length: {len(a)} != {len(b)}")
    
    return bytes(x ^ y for x, y in zip(a, b))


def format_point_hex(x: int, y: int) -> str:
    x_hex = int_to_hex(x, 32)
    y_hex = int_to_hex(y, 32)
    return f"({x_hex}, {y_hex})"


def compress_point(x: int, y: int) -> str:
    prefix = '02' if y % 2 == 0 else '03'
    x_hex = int_to_hex(x, 32)
    return prefix + x_hex


def print_hex_blocks(data: bytes, block_size: int = 16, label: str = "Data") -> None:
    print(f"\n{label} ({len(data)} bytes):")
    hex_string = data.hex()
    
    for i in range(0, len(hex_string), block_size * 2):
        block = hex_string[i:i + block_size * 2]
        formatted_block = ' '.join(block[j:j+2] for j in range(0, len(block), 2))
        print(f"  {formatted_block}")


def validate_private_key_hex(private_key_hex: str) -> bool:
    if not validate_hex(private_key_hex, 32):
        return False
    
    from sm2_math import N
    private_key_int = hex_to_int(private_key_hex)
    return 1 <= private_key_int < N


def validate_public_key_hex(public_key_hex: str) -> bool:
    if not validate_hex(public_key_hex, 64):
        return False
    
    public_key_bytes = hex_to_bytes(public_key_hex)
    x = bytes_to_int(public_key_bytes[:32])
    y = bytes_to_int(public_key_bytes[32:])
    
    from sm2_math import is_on_curve, Point
    point = Point(x, y)
    return is_on_curve(point)


def timing_safe_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0
