def mod_inverse(a: int, m: int) -> int:
    return pow(a, -1, m)


def generate_n_inv_table() -> str:
    result = ""

    result += "static const uint8_t n_inv_table[256] = {\n"

    line = []

    for i in range(256):
        if (i % 2) == 0:
            val = "0x00"
        else:
            inv = mod_inverse(i, 2**8)
            val = f"0x{inv:02X}"

        line.append(val)
        if len(line) == 16:
            result += "    " + ", ".join(line) + ",\n"
            line = []

    result += "};"

    return result


def main() -> None:
    print(generate_n_inv_table())


if __name__ == "__main__":
    main()
