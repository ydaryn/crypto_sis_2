from __future__ import annotations

import json
import math
import os
import struct
import time
from typing import Dict, List, Tuple

MASK32 = 0xFFFFFFFF

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

H0 = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _shr(x: int, n: int) -> int:
    return x >> n


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((~x) & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _bsig0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _bsig1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _ssig0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _ssig1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def to_bytes(data: bytes | str) -> bytes:
    return data if isinstance(data, bytes) else data.encode("utf-8")


def sha256(data: bytes | str) -> bytes:
    msg = bytearray(to_bytes(data))
    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg.extend(struct.pack(">Q", bit_len))

    h = H0[:]
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        w = list(struct.unpack(">16I", block)) + [0] * 48
        for t in range(16, 64):
            w[t] = (w[t - 16] + _ssig0(w[t - 15]) + w[t - 7] + _ssig1(w[t - 2])) & MASK32

        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            t1 = (hh + _bsig1(e) + _ch(e, f, g) + K[t] + w[t]) & MASK32
            t2 = (_bsig0(a) + _maj(a, b, c)) & MASK32
            hh = g
            g = f
            f = e
            e = (d + t1) & MASK32
            d = c
            c = b
            b = a
            a = (t1 + t2) & MASK32

        h[0] = (h[0] + a) & MASK32
        h[1] = (h[1] + b) & MASK32
        h[2] = (h[2] + c) & MASK32
        h[3] = (h[3] + d) & MASK32
        h[4] = (h[4] + e) & MASK32
        h[5] = (h[5] + f) & MASK32
        h[6] = (h[6] + g) & MASK32
        h[7] = (h[7] + hh) & MASK32

    return b"".join(struct.pack(">I", x) for x in h)


def sha256_hex(data: bytes | str) -> str:
    return sha256(data).hex()


def sha256_file(path: str, chunk_size: int = 65536) -> str:
    with open(path, "rb") as f:
        data = f.read()  # kept simple for educational use
    return sha256(data).hex()


def hmac_sha256(key: bytes | str, message: bytes | str) -> bytes:
    key_b = to_bytes(key)
    msg_b = to_bytes(message)
    block_size = 64
    if len(key_b) > block_size:
        key_b = sha256(key_b)
    if len(key_b) < block_size:
        key_b = key_b + b"\x00" * (block_size - len(key_b))
    ipad = bytes((x ^ 0x36) for x in key_b)
    opad = bytes((x ^ 0x5C) for x in key_b)
    return sha256(opad + sha256(ipad + msg_b))


def hmac_sha256_hex(key: bytes | str, message: bytes | str) -> str:
    return hmac_sha256(key, message).hex()


def verify_hmac(key: bytes | str, message: bytes | str, tag_hex: str) -> bool:
    try:
        given = bytes.fromhex(tag_hex.strip())
    except ValueError:
        return False
    expected = hmac_sha256(key, message)
    return constant_time_compare(expected, given)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def pbkdf2_hmac_sha256(password: bytes | str, salt: bytes | str, iterations: int, dk_len: int) -> bytes:
    password_b = to_bytes(password)
    salt_b = to_bytes(salt)
    hlen = 32
    blocks = math.ceil(dk_len / hlen)
    output = bytearray()

    for block_index in range(1, blocks + 1):
        u = hmac_sha256(password_b, salt_b + struct.pack(">I", block_index))
        t = bytearray(u)
        for _ in range(1, iterations):
            u = hmac_sha256(password_b, u)
            for i in range(hlen):
                t[i] ^= u[i]
        output.extend(t)
    return bytes(output[:dk_len])


def hkdf_extract(salt: bytes | str, ikm: bytes | str) -> bytes:
    salt_b = to_bytes(salt)
    ikm_b = to_bytes(ikm)
    if len(salt_b) == 0:
        salt_b = b"\x00" * 32
    return hmac_sha256(salt_b, ikm_b)


def hkdf_expand(prk: bytes, info: bytes | str, length: int) -> bytes:
    info_b = to_bytes(info)
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info_b + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def hkdf(salt: bytes | str, ikm: bytes | str, info: bytes | str, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def save_password(username: str, password: str, db_path: str = "passwords.json", iterations: int = 100) -> Dict[str, str]:
    salt = os.urandom(16)
    derived = pbkdf2_hmac_sha256(password, salt, iterations, 32)
    if os.path.exists(db_path):
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)
    else:
        db = {}
    db[username] = {
        "salt": salt.hex(),
        "iterations": iterations,
        "hash": derived.hex(),
    }
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    return db[username]


def verify_password(username: str, password: str, db_path: str = "passwords.json") -> bool:
    if not os.path.exists(db_path):
        return False
    with open(db_path, "r", encoding="utf-8") as f:
        db = json.load(f)
    record = db.get(username)
    if not record:
        return False
    salt = bytes.fromhex(record["salt"])
    expected = bytes.fromhex(record["hash"])
    candidate = pbkdf2_hmac_sha256(password, salt, int(record["iterations"]), len(expected))
    return constant_time_compare(candidate, expected)


def create_integrity_manifest(paths: List[str], manifest_path: str = "manifest.json") -> Dict[str, Dict[str, str | int]]:
    manifest: Dict[str, Dict[str, str | int]] = {}
    for path in paths:
        st = os.stat(path)
        manifest[path] = {
            "sha256": sha256_file(path),
            "size": st.st_size,
        }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def verify_integrity_manifest(manifest_path: str = "manifest.json") -> List[Tuple[str, str]]:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    results = []
    for path, meta in manifest.items():
        if not os.path.exists(path):
            results.append((path, "MISSING"))
            continue
        current = sha256_file(path)
        results.append((path, "OK" if current == meta["sha256"] else "MODIFIED"))
    return results


def avalanche_demo(text: str) -> Dict[str, str | int | float]:
    original = to_bytes(text)
    if not original:
        original = b"a"
    changed = bytearray(original)
    changed[0] ^= 0x01
    h1 = sha256(original)
    h2 = sha256(bytes(changed))
    diff_bits = sum(bin(x ^ y).count("1") for x, y in zip(h1, h2))
    return {
        "original_hash": h1.hex(),
        "changed_hash": h2.hex(),
        "different_bits": diff_bits,
        "percentage": diff_bits / 256 * 100,
    }


def benchmark_sha256(size_mb: int = 5) -> Dict[str, float]:
    data = os.urandom(size_mb * 1024 * 1024)
    start = time.perf_counter()
    sha256(data)
    elapsed = time.perf_counter() - start
    return {"size_mb": float(size_mb), "seconds": elapsed, "mb_per_second": size_mb / elapsed if elapsed else 0.0}


def benchmark_hmac(size_mb: int = 5) -> Dict[str, float]:
    data = os.urandom(size_mb * 1024 * 1024)
    key = os.urandom(32)
    start = time.perf_counter()
    hmac_sha256(key, data)
    elapsed = time.perf_counter() - start
    return {"size_mb": float(size_mb), "seconds": elapsed, "mb_per_second": size_mb / elapsed if elapsed else 0.0}


def benchmark_pbkdf2(iterations: int = 100_000) -> Dict[str, float | int]:
    start = time.perf_counter()
    pbkdf2_hmac_sha256("password", "salt", iterations, 32)
    elapsed = time.perf_counter() - start
    return {"iterations": iterations, "seconds": elapsed}


def run_self_tests() -> Dict[str, str]:
    results: Dict[str, str] = {}

    sha_tests = {
        "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    }
    for msg, expected in sha_tests.items():
        got = sha256_hex(msg)
        results[f"SHA-256('{msg}')"] = "PASS" if got == expected else f"FAIL (got {got})"

    hmac_key = bytes.fromhex("0b" * 20)
    hmac_msg = b"Hi There"
    hmac_expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    got_hmac = hmac_sha256_hex(hmac_key, hmac_msg)
    results["HMAC RFC4231 Test 1"] = "PASS" if got_hmac == hmac_expected else f"FAIL (got {got_hmac})"

    pbkdf2_expected = "120fb6cffcf8b32c43e7225256c4f837a86548c9"
    got_pbkdf2 = pbkdf2_hmac_sha256("password", "salt", 1, 20).hex()
    results["PBKDF2-HMAC-SHA256 sanity test"] = "PASS" if got_pbkdf2 == pbkdf2_expected else f"FAIL (got {got_pbkdf2})"

    av = avalanche_demo("hello")
    results["Avalanche demo"] = f"{av['different_bits']} bits differ ({av['percentage']:.2f}%)"

    return results
