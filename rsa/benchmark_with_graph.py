#!/usr/bin/env python3
"""
RSA Performance Benchmarking Script with Graph Visualization
Measures execution time, memory usage, and throughput
Generates visual charts for presentation
"""

import sys
import os
import time
import tracemalloc
import matplotlib.pyplot as plt
import numpy as np

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from rsa.rsa_system import RSA, PrimeGenerator
from rsa.rsa import generate_keypair, encrypt, decrypt

def benchmark_key_generation(bits, iterations=5):
    """Benchmark RSA key generation using the actual API"""
    print(f"\nBenchmarking {bits}-bit Key Generation...")
    times = []
    peak_memory = []

    for i in range(iterations):
        tracemalloc.start()
        start = time.perf_counter()
        keypair = generate_keypair(bits)
        elapsed = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append(elapsed)
        peak_memory.append(peak)

    avg_time = sum(times) / len(times)
    return {
        'bits': bits,
        'avg_time_ms': avg_time * 1000,
        'min_time_ms': min(times) * 1000,
        'max_time_ms': max(times) * 1000,
        'avg_memory_mb': sum(peak_memory) / len(peak_memory) / 1024 / 1024
    }

def benchmark_encryption_decryption(bits, iterations=500):
    """Benchmark encryption and decryption"""
    print(f"Benchmarking {bits}-bit Encryption/Decryption...")

    # Generate keypair
    keypair = generate_keypair(bits)
    message = "Hello World!"

    # Benchmark encryption
    enc_times = []
    for _ in range(10):  # Warmup
        encrypt(message, keypair['public_key'], bits)
    for _ in range(iterations):
        start = time.perf_counter()
        ciphertext = encrypt(message, keypair['public_key'], bits)
        enc_times.append(time.perf_counter() - start)

    # Benchmark decryption
    dec_times = []
    for _ in range(10):  # Warmup
        decrypt(ciphertext, keypair['private_key'], bits)
    for _ in range(iterations):
        start = time.perf_counter()
        decrypt(ciphertext, keypair['private_key'], bits)
        dec_times.append(time.perf_counter() - start)

    return {
        'bits': bits,
        'enc_avg_ms': (sum(enc_times) / len(enc_times)) * 1000,
        'enc_throughput': iterations / sum(enc_times),
        'dec_avg_ms': (sum(dec_times) / len(dec_times)) * 1000,
        'dec_throughput': iterations / sum(dec_times)
    }

def create_graphs(keygen_results, encdec_results):
    """Create visualization graphs"""

    # Set up the figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('RSA Performance Benchmarks\nCSCI 663 - Cryptography Project',
                 fontsize=16, fontweight='bold')

    # Extract data
    key_sizes = [r['bits'] for r in keygen_results]
    keygen_times = [r['avg_time_ms'] for r in keygen_results]

    enc_sizes = [r['bits'] for r in encdec_results]
    enc_times = [r['enc_avg_ms'] for r in encdec_results]
    dec_times = [r['dec_avg_ms'] for r in encdec_results]
    enc_throughput = [r['enc_throughput'] for r in encdec_results]
    dec_throughput = [r['dec_throughput'] for r in encdec_results]

    # Graph 1: Key Generation Times
    bars1 = ax1.bar(range(len(key_sizes)), keygen_times, color=['#2ecc71', '#3498db', '#f39c12', '#e74c3c'])
    ax1.set_xlabel('Key Size (bits)', fontweight='bold')
    ax1.set_ylabel('Time (ms)', fontweight='bold')
    ax1.set_title('Key Generation Performance', fontweight='bold')
    ax1.set_xticks(range(len(key_sizes)))
    ax1.set_xticklabels([f'{size}' for size in key_sizes])
    ax1.grid(True, alpha=0.3, axis='y')

    # Add value labels on bars
    for i, (bar, val) in enumerate(zip(bars1, keygen_times)):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{val:.1f}ms',
                ha='center', va='bottom', fontweight='bold')

    # Graph 2: Encryption vs Decryption Time
    x = np.arange(len(enc_sizes))
    width = 0.35
    bars2a = ax2.bar(x - width/2, enc_times, width, label='Encryption', color='#3498db')
    bars2b = ax2.bar(x + width/2, dec_times, width, label='Decryption', color='#e74c3c')
    ax2.set_xlabel('Key Size (bits)', fontweight='bold')
    ax2.set_ylabel('Time (ms)', fontweight='bold')
    ax2.set_title('Encryption vs Decryption Time', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels([f'{size}' for size in enc_sizes])
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis='y')

    # Add value labels
    for bars in [bars2a, bars2b]:
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.2f}',
                    ha='center', va='bottom', fontsize=9)

    # Graph 3: Throughput Comparison
    bars3a = ax3.bar(x - width/2, enc_throughput, width, label='Encryption', color='#2ecc71')
    bars3b = ax3.bar(x + width/2, dec_throughput, width, label='Decryption', color='#f39c12')
    ax3.set_xlabel('Key Size (bits)', fontweight='bold')
    ax3.set_ylabel('Operations/Second', fontweight='bold')
    ax3.set_title('Throughput (ops/sec)', fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels([f'{size}' for size in enc_sizes])
    ax3.legend()
    ax3.grid(True, alpha=0.3, axis='y')
    ax3.set_yscale('log')  # Log scale for better visualization

    # Graph 4: Encryption vs Decryption Ratio
    ratios = [dec / enc for enc, dec in zip(enc_times, dec_times)]
    bars4 = ax4.bar(range(len(enc_sizes)), ratios, color=['#9b59b6', '#34495e'])
    ax4.set_xlabel('Key Size (bits)', fontweight='bold')
    ax4.set_ylabel('Ratio (Decryption/Encryption)', fontweight='bold')
    ax4.set_title('Decryption Slowdown Factor', fontweight='bold')
    ax4.set_xticks(range(len(enc_sizes)))
    ax4.set_xticklabels([f'{size}' for size in enc_sizes])
    ax4.grid(True, alpha=0.3, axis='y')
    ax4.axhline(y=1, color='r', linestyle='--', alpha=0.5, label='Equal Performance')
    ax4.legend()

    # Add value labels
    for bar, val in zip(bars4, ratios):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height,
                f'{val:.1f}x',
                ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()

    # Save the figure
    output_file = 'rsa_performance_graphs.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"\n✅ Graph saved as: {output_file}")

    # Show the plot
    plt.show()

def main():
    print("="*60)
    print("RSA Performance Benchmark with Graphs")
    print("CSCI 663 - Cryptography Project")
    print("="*60)

    # Phase 1: Key Generation
    print("\n" + "="*60)
    print("PHASE 1: Key Generation Benchmarks")
    print("="*60)

    key_sizes = [256, 512, 1024, 2048]
    keygen_results = []

    for bits in key_sizes:
        iterations = 5 if bits <= 512 else 3 if bits <= 1024 else 2
        result = benchmark_key_generation(bits, iterations)
        keygen_results.append(result)
        print(f"  {bits}-bit: {result['avg_time_ms']:.1f}ms (avg)")

    # Phase 2: Encryption/Decryption
    print("\n" + "="*60)
    print("PHASE 2: Encryption/Decryption Benchmarks")
    print("="*60)

    encdec_results = []
    for bits in [512, 1024]:
        iterations = 500 if bits == 512 else 300
        result = benchmark_encryption_decryption(bits, iterations)
        encdec_results.append(result)
        print(f"  {bits}-bit Encryption: {result['enc_avg_ms']:.3f}ms | {result['enc_throughput']:,.0f} ops/sec")
        print(f"  {bits}-bit Decryption: {result['dec_avg_ms']:.3f}ms | {result['dec_throughput']:,.0f} ops/sec")

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print("\nKey Generation Times:")
    for r in keygen_results:
        print(f"  {r['bits']}-bit: {r['avg_time_ms']:.1f}ms")

    print("\nEncryption vs Decryption (1024-bit):")
    result_1024 = encdec_results[1]
    ratio = result_1024['dec_avg_ms'] / result_1024['enc_avg_ms']
    print(f"  Encryption:  {result_1024['enc_avg_ms']:.3f}ms")
    print(f"  Decryption:  {result_1024['dec_avg_ms']:.3f}ms")
    print(f"  Ratio:       {ratio:.1f}x slower")

    # Create graphs
    print("\n" + "="*60)
    print("Generating Performance Graphs...")
    print("="*60)
    create_graphs(keygen_results, encdec_results)

    print("\n" + "="*60)
    print("✅ Benchmark Complete!")
    print("="*60)

if __name__ == '__main__':
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("ERROR: matplotlib is required for graphs")
        print("Install with: pip install matplotlib numpy")
        sys.exit(1)

    main()
