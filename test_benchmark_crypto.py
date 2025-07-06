import time
import statistics

from ll_mtproto.crypto.providers.crypto_provider_base import CryptoProviderBase
from ll_mtproto.crypto.providers.crypto_provider_cryptg import CryptoProviderCryptg
from ll_mtproto.crypto.providers.crypto_provider_openssl.crypto_provider_openssl import CryptoProviderOpenSSL


def benchmark_random(data_size: int, iterations: int, provider: CryptoProviderBase) -> None:
    print(f"\n--- Benchmarking secure_random ({data_size / 1024:.0f} KB) ---")

    start_time = time.perf_counter()
    for _ in range(iterations):
        _ = provider.secure_random(data_size)
    end_time = time.perf_counter()

    total_time = end_time - start_time
    total_data_mib = (data_size * iterations) / (1024 * 1024)
    throughput_mibps = total_data_mib / total_time
    avg_time_ms = (total_time / iterations) * 1000

    print(f"Iterations:      {iterations:,}")
    print(f"Total Time:      {total_time:.4f} s")
    print(f"Avg Time/call:   {avg_time_ms:.4f} ms")
    print(f"Throughput:      {throughput_mibps:.2f} MiB/s")


def benchmark_factorize(iterations: int, provider: CryptoProviderBase) -> None:
    print(f"\n--- Benchmarking factorize_pq ---")

    numbers_to_factor = [
        1541157150752037067,
        2616236600529642443,
        2371559762769689761,
        1889511970825394711,
        3453257802011048431,
        1585997650700150269,
        2710383355131952009,
        2863451067122149151,
        3555730626993576839,
        1628740944112907797,
        3412063834145852219,
        2995124169761413559,
        1634571027732491371,
        1669665743495537377,
        2059676534893627007,
        2047989250019597537,
        2084438288250169513,
        1511659768699021969,
        1603290835348829573,
        2010783836288632997,
        2866718303060007901,
        2684426640773849773,
        1986751222950229451
    ]

    num_count = len(numbers_to_factor)

    start_time = time.perf_counter()
    for i in range(iterations):
        num_to_factor = numbers_to_factor[i % num_count]
        _ = provider.factorize_pq(num_to_factor)
    end_time = time.perf_counter()

    total_time = end_time - start_time
    ops_per_sec = iterations / total_time
    avg_time_us = (total_time / iterations) * 1_000_000

    print(f"Iterations:      {iterations:,}")
    print(f"Total Time:      {total_time:.4f} s")
    print(f"Avg Time/call:   {avg_time_us:.2f} µs (microseconds)")
    print(f"Ops/second:      {ops_per_sec:,.2f} ops/s")


def benchmark_ige(data_size: int, iterations: int, provider: CryptoProviderBase) -> None:
    print(f"\n--- Benchmarking AES-256-IGE ({data_size / 1024:.0f} KB) ---")

    plaintext = provider.secure_random(data_size)
    key = provider.secure_random(32)
    iv = provider.secure_random(32)

    ciphertext, _ = provider.encrypt_aes_ige(plaintext, key, iv)

    print("\n[Encryption]")
    enc_times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        _ = provider.encrypt_aes_ige(plaintext, key, iv)
        end_time = time.perf_counter()
        enc_times.append(end_time - start_time)

    total_enc_time = sum(enc_times)
    total_data_mib = (data_size * iterations) / (1024 * 1024)
    enc_throughput_mibps = total_data_mib / total_enc_time
    enc_avg_time_ms = statistics.mean(enc_times) * 1000

    print(f"Iterations:      {iterations:,}")
    print(f"Total Time:      {total_enc_time:.4f} s")
    print(f"Avg Time/call:   {enc_avg_time_ms:.4f} ms")
    print(f"Throughput:      {enc_throughput_mibps:.2f} MiB/s")

    print("\n[Decryption]")
    dec_times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        _ = provider.decrypt_aes_ige(ciphertext, key, iv)
        end_time = time.perf_counter()
        dec_times.append(end_time - start_time)

    total_dec_time = sum(dec_times)
    dec_throughput_mibps = total_data_mib / total_dec_time
    dec_avg_time_ms = statistics.mean(dec_times) * 1000

    print(f"Iterations:      {iterations:,}")
    print(f"Total Time:      {total_dec_time:.4f} s")
    print(f"Avg Time/call:   {dec_avg_time_ms:.4f} ms")
    print(f"Throughput:      {dec_throughput_mibps:.2f} MiB/s")


def benchmark_provider(provider: CryptoProviderBase) -> None:
    print(f"\n--- Benchmarking provider {provider.__class__.__name__} ---")

    benchmark_factorize(iterations=1000, provider=provider)

    test_cases = [
        (
            4 * 1024,
            2000,
        ),
        (
            128 * 1024,
            1000,
        ),
        (
            1024 * 1024,
            500
        ),
        (
            5 * 1024 * 1024,
            500,
        ),
    ]

    for size, iters in test_cases:
        benchmark_random(data_size=size, iterations=iters, provider=provider)
        benchmark_ige(data_size=size, iterations=iters, provider=provider)
        print("-" * 32)


def main():
    benchmark_provider(provider=CryptoProviderOpenSSL())
    benchmark_provider(provider=CryptoProviderCryptg())


if __name__ == "__main__":
    main()
