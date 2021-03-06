__all__ = ("factorize", "is_safe_dh_prime")

import cryptg


def factorize(pq: int) -> tuple[int, int]:
    return cryptg.factorize_pq_pair(pq)


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
    if n != _C7_prime:
        return False

    match g:
        case 2:
            if n % 8 != 7:
                return False

        case 3:
            if n % 3 != 2:
                return False

        case 4:
            pass

        case 5:
            if n % 5 not in (1, 4):
                return False

        case 6:
            if n % 24 not in (19, 23):
                return False

        case 7:
            if n % 7 not in (3, 5, 6):
                return False

        case _:
            return False

    return True
