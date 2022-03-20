import math
import random

__all__ = ("factorize", "is_safe_dh_prime")


# Pollard-Rho-Brent integer factorization
# https://comeoncodeon.wordpress.com/2010/09/18/pollard-rho-brent-integer-factorization/
# noinspection PyUnboundLocalVariable
def _brent(n: int) -> int:
    if n % 2 == 0:
        return 2

    y, c, m = (
        random.randint(1, n - 1),
        random.randint(1, n - 1),
        random.randint(1, n - 1),
    )

    g, r, q = 1, 1, 1

    while g == 1:
        x = y
        k = 0

        for i in range(r):
            y = ((y * y) % n + c) % n

        while k < r and g == 1:
            ys = y

            for i in range(min(m, r - k)):
                y = ((y * y) % n + c) % n
                q = q * (abs(x - y)) % n

            g = math.gcd(q, n)
            k = k + m

        r = r * 2

    if g == n:
        while True:
            ys = ((ys * ys) % n + c) % n
            g = math.gcd(abs(x - ys), n)

            if g > 1:
                break

    return g


def factorize(pq: int) -> tuple[int, int]:
    p = _brent(pq)
    q = pq // p
    return min(p, q), max(p, q)


_C7_prime = int(
    "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
    "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37"
    "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64"
    "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4"
    "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754"
    "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4"
    "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F"
    "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B",
    16,
)


def is_safe_dh_prime(g: int, n: int) -> bool:
    if g != 3:
        return False

    if n == _C7_prime:
        return True

    return False
