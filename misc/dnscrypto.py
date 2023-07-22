from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64
import ipaddress
import secrets
import argh


def encrypt_blowfish_base32(ip: str, password: str) -> str:
    # Convert the IP address to a 4-byte representation
    ip_bytes = bytes(map(int, ip.split(".")))

    cipher = Blowfish.new(password.encode(), Blowfish.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(ip_bytes, Blowfish.block_size))
    output = base64.b32encode(encrypted_text).decode("utf-8").rstrip("=")
    return output


def decrypt_blowfish_base32(input_string: str, password: str) -> str:
    # Add padding characters
    while len(input_string) % 8 != 0:
        input_string += "="

    encrypted_text = base64.b32decode(input_string)
    cipher = Blowfish.new(password.encode(), Blowfish.MODE_ECB)
    ip_bytes = unpad(cipher.decrypt(encrypted_text), Blowfish.block_size)

    # Convert the 4-byte representation back into a string
    ip = ".".join(map(str, ip_bytes))
    return ip


def encode_ip(ip, password):
    return encrypt_blowfish_base32(ip, password).lower()


def decode_ip(encoded_ip, password):
    return decrypt_blowfish_base32(encoded_ip.upper(), password)


def test():
    password = secrets.token_urlsafe(32)
    for ip in ipaddress.ip_network("172.16.102.0/24"):
        ip = str(ip)
        encoded_part = encode_ip(ip, password)
        print(encoded_part)
        decoded_ip = decode_ip(encoded_part, password)
        assert decoded_ip == ip


if __name__ == "__main__":
    argh.dispatch_commands([test, encode_ip])
