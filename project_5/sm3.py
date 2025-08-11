import struct
from typing import List


_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]


def _left_rotate(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def _ff(x: int, y: int, z: int, round_num: int) -> int:
    if round_num < 16:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)


def _gg(x: int, y: int, z: int, round_num: int) -> int:
    if round_num < 16:
        return x ^ y ^ z
    else:
        return (x & y) | ((~x) & z)


def _p0(x: int) -> int:
    return x ^ _left_rotate(x, 9) ^ _left_rotate(x, 17)


def _p1(x: int) -> int:
    return x ^ _left_rotate(x, 15) ^ _left_rotate(x, 23)


def _t_constant(round_num: int) -> int:
    if round_num < 16:
        return 0x79CC4519
    else:
        return 0x7A879D8A


def _sm3_compress(message_block: bytes, state: List[int]) -> List[int]:
    w = list(struct.unpack('>16I', message_block))
    
    for i in range(16, 68):
        w_i_16 = w[i-16]
        w_i_9 = w[i-9]
        w_i_3 = w[i-3]
        w_i_13 = w[i-13]
        w_i_6 = w[i-6]
        
        temp = w_i_16 ^ w_i_9 ^ _left_rotate(w_i_3, 15)
        temp = _p1(temp)
        w.append(temp ^ _left_rotate(w_i_13, 7) ^ w_i_6)
    
    w1 = []
    for i in range(64):
        w1.append(w[i] ^ w[i + 4])
    
    a, b, c, d, e, f, g, h = state
    
    for j in range(64):
        t_j = _t_constant(j)
        t_j_rotated = _left_rotate(t_j, j % 32)
        
        ss1 = _left_rotate(((_left_rotate(a, 12)) + e + t_j_rotated) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ _left_rotate(a, 12)
        
        tt1 = (_ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
        tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
        
        d = c
        c = _left_rotate(b, 9)
        b = a
        a = tt1
        h = g
        g = _left_rotate(f, 19)
        f = e
        e = _p0(tt2)
    
    new_state = []
    for i, val in enumerate([a, b, c, d, e, f, g, h]):
        new_state.append(val ^ state[i])
    
    return new_state


def sm3_hash(message: bytes) -> bytes:
    state = _IV[:]
    
    msg_bit_len = len(message) * 8
    
    message = bytearray(message)
    message.append(0x80)
    
    while len(message) % 64 != 56:
        message.append(0x00)
    
    message.extend(struct.pack('>Q', msg_bit_len))
    
    for i in range(0, len(message), 64):
        block = bytes(message[i:i+64])
        state = _sm3_compress(block, state)
    
    result = b''
    for word in state:
        result += struct.pack('>I', word)
    
    return result


def sm3_hex(message: bytes) -> str:
    return sm3_hash(message).hex().lower()


def sm3_text(text: str, encoding: str = 'utf-8') -> str:
    return sm3_hex(text.encode(encoding))


def _test_sm3():
    test_vectors = [
        {
            'input': b'',
            'expected': '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'
        },
        {
            'input': b'abc',
            'expected': '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
        },
        {
            'input': b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
            'expected': 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'
        }
    ]
    
    print("Testing SM3 implementation:")
    all_passed = True
    
    for i, vector in enumerate(test_vectors):
        result = sm3_hex(vector['input'])
        expected = vector['expected']
        passed = result == expected
        all_passed &= passed
        
        print(f"Test {i+1}: {'PASS' if passed else 'FAIL'}")
        if not passed:
            print(f"  Input: {vector['input']}")
            print(f"  Expected: {expected}")
            print(f"  Got:      {result}")
    
    return all_passed


if __name__ == "__main__":
    _test_sm3()
