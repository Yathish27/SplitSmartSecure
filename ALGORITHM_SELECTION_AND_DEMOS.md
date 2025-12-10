# Algorithm Selection & Demo Scripts Status

## Question 1: Are we still using ChaCha20-Poly1305 for smaller messages?

### Answer: **YES, algorithm selection is still active!**

The system automatically selects encryption algorithms based on message size:

### Algorithm Selection Logic

Located in `shared/crypto_primitives.py` → `select_encryption_algorithm()`:

```python
# Thresholds (from shared/constants.py):
SMALL_MESSAGE_THRESHOLD = 1024 bytes   # < 1KB → ChaCha20-Poly1305
LARGE_MESSAGE_THRESHOLD = 10240 bytes  # > 10KB → AES-256-GCM
# Between 1KB-10KB → AES-256-GCM (default)
```

### Selection Rules:

1. **Small Messages (< 1024 bytes)**: 
   - Uses **ChaCha20-Poly1305**
   - Better for small messages, especially on non-AES hardware
   - Fast software implementation

2. **Medium Messages (1024-10240 bytes)**:
   - Uses **AES-256-GCM** (default)
   - Good balance for most expense messages

3. **Large Messages (> 10240 bytes)**:
   - Uses **AES-256-GCM**
   - Hardware-accelerated on modern CPUs
   - Best performance for large data

### How It Works:

1. When `encrypt_message()` is called without specifying an algorithm:
   ```python
   encrypted = client.crypto.encrypt_message(plaintext)  # Auto-selects
   ```

2. The algorithm is automatically selected based on `len(plaintext)`

3. The selected algorithm is included in the encrypted message:
   ```python
   {
       "algorithm": "ChaCha20-Poly1305",  # or "AES-256-GCM"
       "nonce": "...",
       "ciphertext": "..."
   }
   ```

4. The receiver uses the algorithm field to decrypt correctly

### Current Status:

✅ **Algorithm selection is ACTIVE and working**
✅ Both algorithms are implemented and tested
✅ Selection happens automatically based on message size
✅ The algorithm field is included in all encrypted messages

### Verification:

You can verify this by checking:
- `shared/crypto_primitives.py` → `select_encryption_algorithm()` (line 436)
- `shared/crypto_primitives.py` → `encrypt_message()` (line 463)
- `shared/constants.py` → Thresholds (lines 35-36)

---

## Question 2: Were demo scripts updated for web UI?

### Answer: **PARTIALLY - Demos work but don't demonstrate web UI**

### Current Status:

The demo scripts (`demos/demo_*.py`) are **still CLI-based** and use the **direct client/server architecture**:

✅ **What Works:**
- Demos still function correctly
- They use the underlying `SplitSmartClient` and `SplitSmartServer` classes
- They demonstrate cryptographic attacks and defenses
- They show algorithm selection (algorithm field is displayed)
- They work independently of the web UI

❌ **What's Missing:**
- Demos don't demonstrate the web UI features
- No password authentication demonstration
- No web-based expense submission
- No analytics dashboard visualization
- No blockchain visualization in web context

### Demo Scripts Architecture:

```
demos/demo_*.py
    ↓
client.client.SplitSmartClient  (CLI client)
    ↓
server.server.SplitSmartServer  (Direct server)
    ↓
Crypto operations (same as web UI uses)
```

### Web UI Architecture:

```
web_app.py (Flask)
    ↓
client.client.SplitSmartClient  (Same client class!)
    ↓
server.server.SplitSmartServer  (Same server class!)
    ↓
Crypto operations (same as demos use)
```

### Key Point:

**Both architectures use the SAME underlying crypto code!**

- Web UI: Flask → SplitSmartClient → Crypto
- Demo Scripts: CLI → SplitSmartClient → Crypto

The demos demonstrate the **cryptographic security features**, which are the same whether accessed via CLI or web UI.

### What Demos Currently Show:

1. **demo_eavesdropping.py**: 
   - Shows encrypted messages
   - Displays algorithm used (AES-GCM or ChaCha20)
   - Demonstrates confidentiality

2. **demo_modification.py**:
   - Shows authentication tag verification
   - Demonstrates integrity protection
   - Mentions all three algorithms

3. **demo_spoofing.py**:
   - Shows digital signature verification
   - Demonstrates authentication

4. **demo_replay.py**:
   - Shows monotonic counter protection
   - Demonstrates replay prevention

5. **demo_tampering.py**:
   - Shows hash chain verification
   - Demonstrates tamper detection

### Recommendations:

#### Option 1: Keep Current Demos (Recommended)
- ✅ Demos focus on cryptographic security (core feature)
- ✅ Work independently of UI
- ✅ Easy to run and understand
- ✅ Demonstrate the security features that protect both CLI and web UI

#### Option 2: Add Web UI Demos
Create new demo scripts that:
- Launch Flask server
- Use browser automation (Selenium)
- Demonstrate attacks through web UI
- Show web-specific features (analytics, blockchain visualization)

#### Option 3: Hybrid Approach
- Keep existing CLI demos for crypto demonstrations
- Add web UI integration tests that verify the same security features work through the web interface

---

## Summary

### Question 1: Algorithm Selection
✅ **YES** - ChaCha20-Poly1305 is used for small messages (< 1KB)
✅ **YES** - AES-256-GCM is used for larger messages
✅ **YES** - Selection is automatic and working

### Question 2: Demo Scripts
✅ **PARTIALLY** - Demos work but are CLI-based
✅ **SAME CODE** - Web UI uses same crypto code as demos
✅ **RECOMMENDED** - Keep CLI demos for crypto demonstrations
⚠️ **OPTIONAL** - Could add web UI demos if needed

---

## Testing Algorithm Selection

To verify algorithm selection is working:

```python
from shared.crypto_primitives import CryptoPrimitives

# Small message (< 1KB) → Should use ChaCha20-Poly1305
small_msg = b"Small expense" * 50  # ~600 bytes
algo1, nonce1, cipher1 = CryptoPrimitives.encrypt_message(b'0'*32, small_msg)
print(f"Small message: {algo1}")  # Should print "ChaCha20-Poly1305"

# Large message (> 10KB) → Should use AES-256-GCM
large_msg = b"Large expense data" * 1000  # ~17KB
algo2, nonce2, cipher2 = CryptoPrimitives.encrypt_message(b'0'*32, large_msg)
print(f"Large message: {algo2}")  # Should print "AES-256-GCM"
```

---

## Files to Check

1. **Algorithm Selection**:
   - `shared/crypto_primitives.py` (lines 436-460, 463-489)
   - `shared/constants.py` (lines 35-36)

2. **Demo Scripts**:
   - `demos/demo_eavesdropping.py`
   - `demos/demo_modification.py`
   - `demos/demo_spoofing.py`
   - `demos/demo_replay.py`
   - `demos/demo_tampering.py`

3. **Web UI**:
   - `web_app.py` (uses same client/server classes)
   - `client/client.py` (used by both CLI and web UI)

