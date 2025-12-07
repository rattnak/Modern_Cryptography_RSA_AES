"""
Benchmark script for the AES implementation in this repo.

Usage (from project root):
    python -m benchmark.benchmark_aes --iterations 50
or
    python benchmark/benchmark_aes.py --iterations 50

Measures key generation, encryption, and decryption timings and
optionally Python memory allocations via `tracemalloc`.
Writes results to `benchmark/results_aes_{timestamp}.json`.
"""
import argparse
import importlib.util
import json
import pathlib
import time
import statistics
import tracemalloc
from datetime import datetime


def load_aes_module():
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    aes_file = repo_root / 'aes' / 'aes.py'
    if not aes_file.exists():
        raise FileNotFoundError(f"Cannot find aes implementation at {aes_file}")
    spec = importlib.util.spec_from_file_location('aes_impl', str(aes_file))
    aes_impl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aes_impl)
    return aes_impl


def time_function(func, *args, measure_memory=False):
    if measure_memory:
        tracemalloc.start()
    t0 = time.perf_counter()
    res = func(*args)
    t1 = time.perf_counter()
    peak = None
    if measure_memory:
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return (t1 - t0), res, peak


def benchmark_keygen(aes_impl, size, iterations=5, measure_memory=False):
    times = []
    peaks = [] if measure_memory else None
    for _ in range(iterations):
        elapsed, key, peak = time_function(aes_impl.generate_key, size, measure_memory=measure_memory)
        times.append(elapsed)
        if measure_memory:
            peaks.append(peak)
    return {
        'size': size,
        'iterations': iterations,
        'times': times,
        'time_mean': statistics.mean(times),
        'time_std': statistics.pstdev(times) if iterations > 1 else 0.0,
        'memory_peaks': peaks if measure_memory else None,
        'memory_peak_mean': statistics.mean(peaks) if measure_memory and peaks else None,
    }


def benchmark_encrypt_decrypt(aes_impl, size, iterations=20, measure_memory=False, message='Benchmark AES message'):
    key = aes_impl.generate_key(size)

    encrypt_times = []
    decrypt_times = []
    enc_peaks = [] if measure_memory else None
    dec_peaks = [] if measure_memory else None

    # Warm-up
    ciphertext = aes_impl.encrypt(message, key, size)

    for _ in range(iterations):
        et, ciphertext, ep = time_function(aes_impl.encrypt, message, key, size, measure_memory=measure_memory)
        encrypt_times.append(et)
        if measure_memory:
            enc_peaks.append(ep)

        dt, plaintext, dp = time_function(aes_impl.decrypt, ciphertext, key, size, measure_memory=measure_memory)
        decrypt_times.append(dt)
        if measure_memory:
            dec_peaks.append(dp)

    return {
        'size': size,
        'iterations': iterations,
        'encrypt_times': encrypt_times,
        'decrypt_times': decrypt_times,
        'encrypt_mean': statistics.mean(encrypt_times),
        'encrypt_std': statistics.pstdev(encrypt_times) if iterations > 1 else 0.0,
        'decrypt_mean': statistics.mean(decrypt_times),
        'decrypt_std': statistics.pstdev(decrypt_times) if iterations > 1 else 0.0,
        'encrypt_memory_peaks': enc_peaks if measure_memory else None,
        'decrypt_memory_peaks': dec_peaks if measure_memory else None,
    }


def main():
    parser = argparse.ArgumentParser(description='Benchmark AES functions in the repo')
    parser.add_argument('--iterations', '-n', type=int, default=50, help='Iterations per measurement')
    parser.add_argument('--sizes', '-s', nargs='+', type=int, default=[128, 192, 256], help='Key sizes to test')
    parser.add_argument('--measure-memory', action='store_true', help='Measure Python memory via tracemalloc')
    parser.add_argument('--message', type=str, default='Hello AES benchmark', help='Message to encrypt/decrypt')
    parser.add_argument('--out', type=str, default=None, help='Optional output JSON path')
    args = parser.parse_args()

    aes_impl = load_aes_module()

    results = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'iterations': args.iterations,
        'sizes': args.sizes,
        'measure_memory': args.measure_memory,
        'benchmarks': []
    }

    for size in args.sizes:
        print(f"Benchmarking AES size={size} (iterations={args.iterations})...")
        kg = benchmark_keygen(aes_impl, size, iterations=max(1, args.iterations // 5), measure_memory=args.measure_memory)
        io = benchmark_encrypt_decrypt(aes_impl, size, iterations=args.iterations, measure_memory=args.measure_memory, message=args.message)
        results['benchmarks'].append({'keygen': kg, 'io': io})

    # Prepare output
    out_path = args.out
    if not out_path:
        stamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        out_dir = pathlib.Path('benchmark')
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f'results_aes_{stamp}.json'
    else:
        out_path = pathlib.Path(out_path)

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print('\nAES benchmark complete.')
    print(f'Results written to: {out_path}')


if __name__ == '__main__':
    main()
