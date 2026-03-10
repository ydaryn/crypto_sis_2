from __future__ import annotations

import os
from pathlib import Path

from crypto_core import (
    avalanche_demo,
    benchmark_hmac,
    benchmark_pbkdf2,
    benchmark_sha256,
    create_integrity_manifest,
    hkdf,
    hmac_sha256,
    pbkdf2_hmac_sha256,
    run_self_tests,
    save_password,
    sha256_file,
    sha256_hex,
    verify_integrity_manifest,
    verify_password,
)


def header() -> None:
    print("\n" + "=" * 60)
    print("SIS 2 - SHA-256 / HMAC / PBKDF2 / HKDF CLI")
    print("=" * 60)


def menu() -> None:
    print(
        """
1. SHA-256 text hash
2. SHA-256 file hash
3. HMAC generate
4. HMAC verify
5. Save password
6. Verify password
7. PBKDF2 derive key
8. HKDF derive key
9. Create integrity manifest
10. Verify integrity manifest
11. Avalanche demo
12. Run self-tests
13. Run benchmarks
0. Exit
"""
    )


def prompt_path(message: str) -> str:
    path = input(message).strip()
    return os.path.expanduser(path)


def read_file_bytes(path: str) -> bytes:
    with open(os.path.expanduser(path), "rb") as f:
        return f.read()


def read_key_bytes() -> bytes:
    mode = input("Key format (text/hex): ").strip().lower()
    key_input = input("Enter key: ")

    if mode == "hex":
        return bytes.fromhex(key_input.strip())
    elif mode == "text":
        return key_input.encode("utf-8")
    else:
        raise ValueError("Key format must be 'text' or 'hex'")


def read_message_bytes() -> bytes:
    mode = input("Message source (text/file): ").strip().lower()

    if mode == "text":
        msg = input("Enter message: ")
        return msg.encode("utf-8")
    elif mode == "file":
        path = input("Enter file path: ").strip()
        return read_file_bytes(path)
    else:
        raise ValueError("Message source must be 'text' or 'file'")


def constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def action_sha_text() -> None:
    text = input("Enter text: ")
    print("SHA-256:", sha256_hex(text))


def action_sha_file() -> None:
    path = prompt_path("Enter file path: ")
    print("SHA-256:", sha256_file(path))


def action_hmac_generate() -> None:
    key = read_key_bytes()
    msg = read_message_bytes()
    tag = hmac_sha256(key, msg).hex()
    print("HMAC-SHA256:", tag)


def action_hmac_verify() -> None:
    key = read_key_bytes()
    msg = read_message_bytes()
    provided_tag_hex = input("Enter expected hex tag: ").strip().lower()

    try:
        provided_tag = bytes.fromhex(provided_tag_hex)
    except ValueError:
        raise ValueError("Tag must be valid hexadecimal")

    actual_tag = hmac_sha256(key, msg)
    print("Valid" if constant_time_equal(actual_tag, provided_tag) else "Invalid")
    print("Computed:", actual_tag.hex())


def action_save_password() -> None:
    user = input("Username: ")
    pw = input("Password: ")
    rec = save_password(user, pw)
    print("Saved.")
    print("Salt:", rec["salt"])
    print("Iterations:", rec["iterations"])
    print("Hash:", rec["hash"])


def action_verify_password() -> None:
    user = input("Username: ")
    pw = input("Password: ")
    print("Correct" if verify_password(user, pw) else "Wrong / user not found")


def action_pbkdf2() -> None:
    pw = input("Password: ")
    salt = input("Salt: ")
    iterations = int(input("Iterations (e.g. 100000): ").strip())
    length = int(input("Output length in bytes: ").strip())
    print("Derived key:", pbkdf2_hmac_sha256(pw, salt, iterations, length).hex())


def action_hkdf() -> None:
    ikm = input("Input keying material: ")
    salt = input("Salt (can be empty): ")
    info = input("Info/context: ")
    length = int(input("Output length in bytes: ").strip())
    print("Derived key:", hkdf(salt, ikm, info, length).hex())


def action_manifest_create() -> None:
    raw = input("Enter file paths separated by commas: ").strip()
    paths = [os.path.expanduser(p.strip()) for p in raw.split(",") if p.strip()]
    manifest = create_integrity_manifest(paths)
    print("Manifest saved to manifest.json")
    for path, meta in manifest.items():
        print(f"- {path}: {meta['sha256']}")


def action_manifest_verify() -> None:
    path = prompt_path("Manifest path [manifest.json]: ") or "manifest.json"
    for item, status in verify_integrity_manifest(path):
        print(f"{item}: {status}")


def action_avalanche() -> None:
    text = input("Enter text: ")
    result = avalanche_demo(text)
    print("Original hash:", result["original_hash"])
    print("Changed hash :", result["changed_hash"])
    print("Different bits:", result["different_bits"])
    print(f"Percentage: {result['percentage']:.2f}%")


def action_tests() -> None:
    for name, result in run_self_tests().items():
        print(f"{name}: {result}")


def action_benchmarks() -> None:
    print("SHA-256:", benchmark_sha256())
    print("HMAC   :", benchmark_hmac())
    print("PBKDF2 :", benchmark_pbkdf2())


ACTIONS = {
    "1": action_sha_text,
    "2": action_sha_file,
    "3": action_hmac_generate,
    "4": action_hmac_verify,
    "5": action_save_password,
    "6": action_verify_password,
    "7": action_pbkdf2,
    "8": action_hkdf,
    "9": action_manifest_create,
    "10": action_manifest_verify,
    "11": action_avalanche,
    "12": action_tests,
    "13": action_benchmarks,
}


def main() -> None:
    header()
    while True:
        menu()
        choice = input("Choose: ").strip()
        if choice == "0":
            print("Bye.")
            break
        action = ACTIONS.get(choice)
        if not action:
            print("Unknown option.")
            continue
        try:
            action()
        except FileNotFoundError:
            print("File not found.")
        except ValueError as e:
            print("Invalid input:", e)
        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    main()