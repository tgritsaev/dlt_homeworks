import random
import hashlib

# Define the elliptic curve parameters for secp256k1
Pr = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Prime modulus
A = 0  # Curve parameter A
B = 7  # Curve parameter B
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798  # Generator x-coordinate
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8  # Generator y-coordinate
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Order of the curve


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y


def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError("division by zero")
    return pow(k, p - 2, p)


def point_addition(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P.x == Q.x and P.y != Q.y:
        return None
    if P == Q:
        # Point doubling
        m = (3 * P.x * P.x + A) * inverse_mod(2 * P.y, Pr)  # Use the prime modulus P here
    else:
        # Point addition
        m = (Q.y - P.y) * inverse_mod(Q.x - P.x, Pr)  # Use the prime modulus P here
    x = m * m - P.x - Q.x
    y = m * (P.x - x) - P.y
    return Point(x % Pr, y % Pr)  # Use the prime modulus P here


def scalar_multiplication(k, P):
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        k >>= 1
    return R


def generate_keypair():
    private_key = random.randrange(1, N)
    public_key = scalar_multiplication(private_key, Point(Gx, Gy))
    return private_key, public_key


def sign_message(private_key, message):
    z = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    r = s = 0
    while r == 0 or s == 0:
        k = random.randrange(1, N)
        R = scalar_multiplication(k, Point(Gx, Gy))
        r = R.x % N
        s = ((z + r * private_key) * inverse_mod(k, N)) % N
    return (r, s)


def verify_signature(public_key, message, signature):
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    w = inverse_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    P = point_addition(scalar_multiplication(u1, Point(Gx, Gy)), scalar_multiplication(u2, public_key))
    return P is not None and P.x % N == r


if __name__ == "__main__":
    private_key, public_key = generate_keypair()
    print("Private Key:", private_key)
    print("Public Key:", (public_key.x, public_key.y))

    message = "Hello, ECDSA!"
    print("Original Message:", message)

    signature = sign_message(private_key, message)
    print("Signature:", signature)

    is_valid = verify_signature(public_key, message, signature)
    print("Signature Valid:", is_valid)

    # Additional test cases
    test_cases = [
        "Short message",
        "A bit longer message to test ECDSA signing and verification.",
        "Testing with a different message.",
        "Edge case with empty string",
        "Special characters !@#$%^&*()_+",
    ]

    for msg in test_cases:
        print("\nTesting with message:", msg)
        signature = sign_message(private_key, msg)
        is_valid = verify_signature(public_key, msg, signature)
        print("Signature:", signature)
        print("Signature Valid:", is_valid)
        assert is_valid, "Signature verification failed for message: " + msg

    # Test with incorrect signature
    print("\nTesting with incorrect signature")
    wrong_signature = (signature[0] + 1, signature[1])
    is_valid = verify_signature(public_key, message, wrong_signature)
    print("Signature Valid with wrong signature:", is_valid)
    assert not is_valid, "Signature verification should fail with incorrect signature"
