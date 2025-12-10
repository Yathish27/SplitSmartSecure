#!/usr/bin/env python3
"""
Test script to demonstrate algorithm selection based on message size.
"""

from shared.crypto_primitives import CryptoPrimitives
from shared.constants import SMALL_MESSAGE_THRESHOLD, LARGE_MESSAGE_THRESHOLD

def test_algorithm_selection():
    """Test that algorithm selection works correctly."""
    print("=" * 80)
    print("Algorithm Selection Test".center(80))
    print("=" * 80)
    
    # Test key (32 bytes for 256-bit)
    test_key = b'0' * 32
    
    # Test 1: Small message (< 1KB) → Should use ChaCha20-Poly1305
    print("\n1. Small Message Test (< 1KB)")
    print(f"   Threshold: {SMALL_MESSAGE_THRESHOLD} bytes")
    small_msg = b"Small expense data" * 50  # ~900 bytes
    print(f"   Message size: {len(small_msg)} bytes")
    algo1, nonce1, cipher1 = CryptoPrimitives.encrypt_message(test_key, small_msg)
    print(f"   Selected algorithm: {algo1}")
    assert algo1 == "ChaCha20-Poly1305", f"Expected ChaCha20-Poly1305, got {algo1}"
    print("   ✓ Correctly selected ChaCha20-Poly1305")
    
    # Test 2: Medium message (1KB - 10KB) → Should use AES-256-GCM
    print("\n2. Medium Message Test (1KB - 10KB)")
    print(f"   Threshold range: {SMALL_MESSAGE_THRESHOLD} - {LARGE_MESSAGE_THRESHOLD} bytes")
    medium_msg = b"Medium expense data" * 200  # ~3.6KB
    print(f"   Message size: {len(medium_msg)} bytes")
    algo2, nonce2, cipher2 = CryptoPrimitives.encrypt_message(test_key, medium_msg)
    print(f"   Selected algorithm: {algo2}")
    assert algo2 == "AES-256-GCM", f"Expected AES-256-GCM, got {algo2}"
    print("   ✓ Correctly selected AES-256-GCM")
    
    # Test 3: Large message (> 10KB) → Should use AES-256-GCM
    print("\n3. Large Message Test (> 10KB)")
    print(f"   Threshold: {LARGE_MESSAGE_THRESHOLD} bytes")
    large_msg = b"Large expense data with lots of details" * 500  # ~18KB
    print(f"   Message size: {len(large_msg)} bytes")
    algo3, nonce3, cipher3 = CryptoPrimitives.encrypt_message(test_key, large_msg)
    print(f"   Selected algorithm: {algo3}")
    assert algo3 == "AES-256-GCM", f"Expected AES-256-GCM, got {algo3}"
    print("   ✓ Correctly selected AES-256-GCM")
    
    # Test 4: Verify decryption works for both algorithms
    print("\n4. Decryption Test")
    plaintext1 = CryptoPrimitives.decrypt_message(test_key, algo1, nonce1, cipher1)
    assert plaintext1 == small_msg, "ChaCha20 decryption failed"
    print("   ✓ ChaCha20-Poly1305 decryption successful")
    
    plaintext2 = CryptoPrimitives.decrypt_message(test_key, algo2, nonce2, cipher2)
    assert plaintext2 == medium_msg, "AES-GCM decryption failed"
    print("   ✓ AES-256-GCM decryption successful")
    
    plaintext3 = CryptoPrimitives.decrypt_message(test_key, algo3, nonce3, cipher3)
    assert plaintext3 == large_msg, "AES-GCM decryption failed"
    print("   ✓ AES-256-GCM decryption successful")
    
    print("\n" + "=" * 80)
    print("All Tests Passed!".center(80))
    print("=" * 80)
    print("\nSummary:")
    print(f"  • Messages < {SMALL_MESSAGE_THRESHOLD} bytes → ChaCha20-Poly1305")
    print(f"  • Messages {SMALL_MESSAGE_THRESHOLD}-{LARGE_MESSAGE_THRESHOLD} bytes → AES-256-GCM")
    print(f"  • Messages > {LARGE_MESSAGE_THRESHOLD} bytes → AES-256-GCM")
    print("\n✓ Algorithm selection is working correctly!")

if __name__ == "__main__":
    test_algorithm_selection()

