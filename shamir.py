import secrets

# 2^521 - 1 is a prime, large enough for a 32-byte (256-bit) key
PRIME = 2**521 - 1
SHARE_Y_BYTES = 66  # 521 bits fits in 66 bytes


def _eval_poly(coeffs, x):
    """Evaluate polynomial at x (Horner's method) modulo PRIME."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % PRIME
    return result


def split(secret_int, n, t):
    """Split secret into n shares; any t can recover it."""
    if not (2 <= t <= n <= 255):
        raise ValueError("need 2 <= t <= n <= 255")
    coeffs = [secret_int] + [secrets.randbelow(PRIME) for _ in range(t - 1)]
    return [(x, _eval_poly(coeffs, x)) for x in range(1, n + 1)]


def recover(shares):
    """Lagrange interpolation at x = 0."""
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m != j:
                num = (num * (-xm)) % PRIME
                den = (den * (xj - xm)) % PRIME
        secret = (secret + yj * num * pow(den, -1, PRIME)) % PRIME
    return secret


def share_to_bytes(share):
    x, y = share
    return bytes([x]) + y.to_bytes(SHARE_Y_BYTES, "big")


def bytes_to_share(b):
    return (b[0], int.from_bytes(b[1:], "big"))
