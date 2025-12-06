#!/usr/bin/env python3
"""
RSA Performance Benchmarking Script (CORRECTED VERSION)
Measures execution time, memory usage, and throughput
"""

import sys
import os
import time
import tracemalloc

# Add parent directory to path to import rsa module
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from rsa.rsa_system import RSA, PrimeGenerator
from rsa.rsa import generate_keypair, encrypt, decrypt

def benchmark_key_generation(bits, iterations=5):
    """Benchmark RSA key generation using the actual API"""
    print(f"\n{'='*60}")
    print(f"Benchmarking Key Generation ({bits}-bit)")
    print('='*60)

    times = []
    peak_memory = []

    for i in range(iterations):
        tracemalloc.start()
        start = time.perf_counter()  # More accurate than time.time()

        # Use the ACTUAL API that Flask uses
        keypair = generate_keypair(bits)

        elapsed = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        times.append(elapsed)
        peak_memory.append(peak)
        print(f"  Iteration {i+1}: {elapsed*1000:.1f}ms | Peak Memory: {peak/1024/1024:.2f} MB")

    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    avg_memory = sum(peak_memory) / len(peak_memory)

    print(f"\n  Average: {avg_time*1000:.1f}ms ({avg_time:.3f}s)")
    print(f"  Min: {min_time*1000:.1f}ms | Max: {max_time*1000:.1f}ms")
    print(f"  Avg Memory: {avg_memory/1024/1024:.2f} MB")

    return {
        'bits': bits,
        'avg_time': avg_time,
        'avg_time_ms': avg_time * 1000,
        'min_time': min_time,
        'max_time': max_time,
        'avg_memory_mb': avg_memory / 1024 / 1024,
        'iterations': iterations
    }

def benchmark_encryption(keypair_dict, iterations=1000):
    """Benchmark RSA encryption using actual API"""
    size = keypair_dict['size']
    print(f"\n{'='*60}")
    print(f"Benchmarking Encryption ({size}-bit key)")
    print('='*60)

    message = "Hello World!"  # Use actual text message
    times = []

    # Warmup
    for _ in range(10):
        encrypt(message, keypair_dict['public_key'], size)

    # Actual benchmark
    for i in range(iterations):
        start = time.perf_counter()
        ciphertext = encrypt(message, keypair_dict['public_key'], size)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg_time = sum(times) / len(times)
    total_time = sum(times)
    throughput = iterations / total_time

    print(f"  Iterations: {iterations}")
    print(f"  Average: {avg_time*1000:.3f}ms")
    print(f"  Throughput: {throughput:,.0f} ops/sec")

    return {
        'avg_time': avg_time,
        'avg_time_ms': avg_time * 1000,
        'throughput': throughput
    }

def benchmark_decryption(keypair_dict, iterations=1000):
    """Benchmark RSA decryption using actual API"""
    size = keypair_dict['size']
    print(f"\n{'='*60}")
    print(f"Benchmarking Decryption ({size}-bit key)")
    print('='*60)

    message = "Hello World!"
    ciphertext = encrypt(message, keypair_dict['public_key'], size)
    times = []

    # Warmup
    for _ in range(10):
        decrypt(ciphertext, keypair_dict['private_key'], size)

    # Actual benchmark
    for i in range(iterations):
        start = time.perf_counter()
        plaintext = decrypt(ciphertext, keypair_dict['private_key'], size)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg_time = sum(times) / len(times)
    total_time = sum(times)
    throughput = iterations / total_time

    print(f"  Iterations: {iterations}")
    print(f"  Average: {avg_time*1000:.3f}ms")
    print(f"  Throughput: {throughput:,.0f} ops/sec")

    return {
        'avg_time': avg_time,
        'avg_time_ms': avg_time * 1000,
        'throughput': throughput
    }

def benchmark_prime_generation(bits, iterations=10):
    """Benchmark prime generation"""
    print(f"\n{'='*60}")
    print(f"Benchmarking Prime Generation ({bits}-bit)")
    print('='*60)

    times = []
    for i in range(iterations):
        start = time.perf_counter()
        prime = PrimeGenerator.generate_prime(bits)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        print(f"  Iteration {i+1}: {elapsed*1000:.1f}ms")

    avg_time = sum(times) / len(times)

    print(f"\n  Average: {avg_time*1000:.1f}ms")

    return {
        'bits': bits,
        'avg_time': avg_time,
        'avg_time_ms': avg_time * 1000
    }

def main():
    print("="*60)
    print("RSA Performance Benchmark Suite")
    print("CSCI 663 - Cryptography Project")
    print("="*60)

    results = {}

    # Benchmark different key sizes (all 4 supported sizes)
    key_sizes = [256, 512, 1024, 2048]

    print("\n" + "="*60)
    print("PHASE 1: Key Generation Benchmarks")
    print("="*60)

    keygen_results = []
    for bits in key_sizes:
        # More iterations for smaller keys, fewer for larger
        iterations = 5 if bits <= 512 else 3 if bits <= 1024 else 2
        result = benchmark_key_generation(bits, iterations=iterations)
        keygen_results.append(result)

    # Generate keypairs for encryption/decryption tests
    print("\n" + "="*60)
    print("PHASE 2: Generating Test Keypairs")
    print("="*60)

    keypairs = {}
    for bits in [512, 1024]:
        print(f"  Generating {bits}-bit keypair...")
        keypairs[bits] = generate_keypair(bits)
        print(f"  ✓ {bits}-bit keypair ready")

    # Benchmark encryption/decryption
    print("\n" + "="*60)
    print("PHASE 3: Encryption/Decryption Benchmarks")
    print("="*60)

    enc_results = {}
    dec_results = {}

    for bits, keypair in keypairs.items():
        # Fewer iterations for larger keys
        iterations = 1000 if bits == 512 else 500
        enc_results[bits] = benchmark_encryption(keypair, iterations=iterations)
        dec_results[bits] = benchmark_decryption(keypair, iterations=iterations)

    # Prime generation benchmark
    print("\n" + "="*60)
    print("PHASE 4: Prime Generation Benchmarks")
    print("="*60)

    prime_results = []
    for bits in [128, 256, 512, 1024]:
        iterations = 10 if bits <= 256 else 5
        result = benchmark_prime_generation(bits, iterations=iterations)
        prime_results.append(result)

    # Summary
    print("\n" + "="*60)
    print("BENCHMARK SUMMARY")
    print("="*60)

    print("\n📊 Key Generation Times:")
    print(f"{'Key Size':<12} {'Avg Time':<15} {'Min Time':<15} {'Max Time':<15} {'Memory'}")
    print("-" * 75)
    for r in keygen_results:
        print(f"{r['bits']}-bit{'':<5} "
              f"{r['avg_time_ms']:.1f}ms{'':<8} "
              f"{r['min_time']*1000:.1f}ms{'':<8} "
              f"{r['max_time']*1000:.1f}ms{'':<8} "
              f"{r['avg_memory_mb']:.2f} MB")

    print("\n⚡ Encryption Performance:")
    print(f"{'Key Size':<12} {'Avg Time':<15} {'Throughput'}")
    print("-" * 60)
    for bits, r in enc_results.items():
        print(f"{bits}-bit{'':<5} {r['avg_time_ms']:.3f}ms{'':<8} {r['throughput']:,.0f} ops/sec")

    print("\n🔓 Decryption Performance:")
    print(f"{'Key Size':<12} {'Avg Time':<15} {'Throughput':<20} {'vs Encrypt'}")
    print("-" * 75)
    for bits, r in dec_results.items():
        ratio = dec_results[bits]['avg_time'] / enc_results[bits]['avg_time']
        print(f"{bits}-bit{'':<5} "
              f"{r['avg_time_ms']:.3f}ms{'':<8} "
              f"{r['throughput']:,.0f} ops/sec{'':<8} "
              f"{ratio:.1f}x slower")

    print("\n🔢 Prime Generation Times:")
    print(f"{'Prime Size':<12} {'Avg Time'}")
    print("-" * 60)
    for r in prime_results:
        print(f"{r['bits']}-bit{'':<5} {r['avg_time_ms']:.1f}ms")

    print("\n" + "="*60)
    print("✅ Benchmark Complete!")
    print("="*60)

    print("\n💡 Key Insights:")
    print(f"  • Decryption is ~{dec_results[1024]['avg_time']/enc_results[1024]['avg_time']:.0f}x slower than encryption (expected)")
    print(f"  • 1024-bit key generation: {keygen_results[2]['avg_time_ms']:.0f}ms")
    print(f"  • 2048-bit key generation: {keygen_results[3]['avg_time_ms']:.0f}ms")
    print(f"  • Encryption throughput (1024-bit): {enc_results[1024]['throughput']:,.0f} ops/sec")
    print(f"  • Decryption throughput (1024-bit): {dec_results[1024]['throughput']:,.0f} ops/sec")

if __name__ == '__main__':
    main()
