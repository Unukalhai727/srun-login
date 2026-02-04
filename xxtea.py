from math import floor


def _ordat(msg: str, idx: int) -> int:
    if len(msg) > idx:
        return ord(msg[idx])
    else:
        return 0

def _sencode(msg: str, key: bool) -> list[int]:
    pwd: list[int] = [_ordat(msg, i) | _ordat(msg, i + 1) << 8 | _ordat(msg, i + 2) << 16 | _ordat(msg, i + 3) << 24 for i in range(0, len(msg), 4)]
    if key:
        pwd.append(len(msg))
    return pwd

def _lencode(msg: list[int]) -> str:
    mag = [chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff) for i in range(0, len(msg))]
    return "".join(mag)

def xencode(msg: str, key: str) -> str:
    if msg == "":
        return ""
    pwd = _sencode(msg, True)
    pwdk = _sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    c = 0x86014019 | 0x183639A0
    q = floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return _lencode(pwd)
