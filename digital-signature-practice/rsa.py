import random
import math


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # Ensure the number is odd and has the correct bit length
        if is_prime(p):
            return p


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = extended_gcd(b % a, a)
            return g, x - (b // a) * y, y

    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return x % phi if x > 0 else (x + phi) % phi  # Ensure the result is positive


def generate_keypair(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:  # Ensure p and q are distinct
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher


def decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return "".join(plain)


if __name__ == "__main__":
    bits = 16  # Number of bits for prime numbers
    public_key, private_key = generate_keypair(bits)
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    message = "Hello, RSA!"
    print("Original Message:", message)

    encrypted_message = encrypt(public_key, message)
    print("Encrypted Message:", "".join(map(lambda x: str(x), encrypted_message)))

    decrypted_message = decrypt(private_key, encrypted_message)
    print("Decrypted Message:", decrypted_message)

    # Additional test cases
    test_cases = [
        ("Short message", 16),
        ("A bit longer message to test RSA encryption and decryption.", 24),
        ("Testing with a different key size.", 32),
        ("Edge case with empty string", 16),
        ("Special characters !@#$%^&*()_+", 16),
    ]

    for msg, bits in test_cases:
        print("\nTesting with message:", msg)
        print("Key size (bits):", bits)
        public_key, private_key = generate_keypair(bits)
        encrypted_message = encrypt(public_key, msg)
        decrypted_message = decrypt(private_key, encrypted_message)
        print("Encrypted Message:", "".join(map(lambda x: str(x), encrypted_message)))
        print("Decrypted Message:", decrypted_message)
        assert msg == decrypted_message, "Decryption failed for message: " + msg

    # Test with incorrect decryption key
    print("\nTesting with incorrect decryption key")
    public_key, private_key = generate_keypair(16)
    encrypted_message = encrypt(public_key, "Test message")
    wrong_private_key = generate_keypair(16)[1]
    try:
        decrypted_message = decrypt(wrong_private_key, encrypted_message)
        print("Decrypted Message with wrong key:", decrypted_message)
    except Exception as e:
        print("Decryption failed with wrong key:", str(e))
