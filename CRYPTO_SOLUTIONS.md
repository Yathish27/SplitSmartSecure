# Cryptographic Solutions in SplitSmart

This document explains all cryptographic algorithms used in SplitSmart, why they were chosen, and where they are implemented.

## Table of Contents

1. [RSA-2048](#rsa-2048)
2. [RSA-PSS Digital Signatures](#rsa-pss-digital-signatures)
3. [Diffie-Hellman Key Exchange](#diffie-hellman-key-exchange)
4. [HKDF Key Derivation](#hkdf-key-derivation)
5. [AES-256-GCM](#aes-256-gcm)
6. [ChaCha20-Poly1305](#chacha20-poly1305)
7. [AES-256-CBC-HMAC](#aes-256-cbc-hmac)
8. [SHA-256 Hash Function](#sha-256-hash-function)
9. [HMAC-SHA256](#hmac-sha256)
10. [bcrypt](#bcrypt)

---

## RSA-2048

### What It Is
RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm used for key pairs.

### Why We Use It
- **Long-term identity keys**: Each user and the server have a persistent RSA key pair that serves as their cryptographic identity
- **Digital signatures**: Used as the foundation for RSA-PSS signatures
- **2048-bit keys**: Provide 112 bits of security, sufficient for current security requirements

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `generate_rsa_keypair()`

**Usage Locations**:
1. **Client Identity Keys** (`client/crypto_client.py`)
   - Generated once per user during registration
   - Stored in `keys/{username}_private.pem` and `keys/{username}_public.pem`
   - Used for signing expense records

2. **Server Identity Key** (`server/crypto_server.py`)
   - Generated once during server initialization
   - Stored in `keys/server_private.pem` and `keys/server_public.pem`
   - Used for signing Diffie-Hellman public keys during key exchange

**Security Property**: Provides authentication and non-repudiation

---

## RSA-PSS Digital Signatures

### What It Is
RSA-PSS (Probabilistic Signature Scheme) is a digital signature scheme that provides strong security guarantees.

### Why We Use It
- **Non-repudiation**: Users cannot deny creating an expense (they signed it)
- **Origin authentication**: Proves who created each expense record
- **Tamper detection**: Any modification to signed data invalidates the signature
- **Industry standard**: Recommended by NIST and widely used

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `sign_data()`, `verify_signature()`

**Usage Locations**:
1. **Expense Signing** (`client/crypto_client.py` - `sign_expense()`)
   - Each expense is signed with the user's private key
   - Signature includes: payer, amount, description, counter, timestamp
   - Prevents spoofing attacks

2. **Key Exchange Signatures** (`client/crypto_client.py`, `server/crypto_server.py`)
   - Client signs its Diffie-Hellman public key
   - Server signs its Diffie-Hellman public key
   - Prevents man-in-the-middle attacks during key exchange

3. **Signature Verification** (`server/server.py`)
   - Server verifies all expense signatures before accepting them
   - Rejects expenses with invalid signatures

**Security Property**: Prevents spoofing and provides non-repudiation

---

## Diffie-Hellman Key Exchange

### What It Is
Diffie-Hellman (DH) is a key exchange protocol that allows two parties to establish a shared secret over an insecure channel.

### Why We Use It
- **Forward secrecy**: Ephemeral keys protect past sessions even if long-term keys are compromised
- **Session key establishment**: Creates a shared secret for symmetric encryption
- **2048-bit parameters**: Provides strong security
- **Ephemeral keys**: New keys for each session prevent replay of old sessions

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `generate_dh_parameters()`, `generate_dh_keypair()`, `compute_dh_shared_secret()`

**Usage Locations**:
1. **Key Exchange Protocol** (`client/crypto_client.py` - `initiate_key_exchange()`, `complete_key_exchange()`)
   - Client generates ephemeral DH key pair
   - Client sends DH public key + signature to server
   - Server generates ephemeral DH key pair
   - Server sends DH public key + signature to client
   - Both compute shared secret: `shared_secret = DH(client_private, server_public)`

2. **Session Key Derivation** (`client/crypto_client.py`, `server/crypto_server.py`)
   - Shared secret is used to derive session encryption key via HKDF

**Security Property**: Provides forward secrecy and secure session establishment

---

## HKDF Key Derivation

### What It Is
HKDF (HMAC-based Key Derivation Function) is a key derivation function that extracts uniform randomness from input material.

### Why We Use It
- **Key extraction**: Converts DH shared secret (which may have bias) into uniform key material
- **Deterministic**: Same input produces same output (both client and server derive same key)
- **SHA-256 based**: Uses secure hash function
- **Industry standard**: RFC 5869, widely used in TLS and other protocols

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `derive_session_key()`

**Usage Locations**:
1. **Session Key Derivation** (`client/crypto_client.py` - `complete_key_exchange()`)
   ```python
   self.session_key = CryptoPrimitives.derive_session_key(shared_secret)
   ```

2. **Server Session Key** (`server/crypto_server.py` - `respond_to_key_exchange()`)
   ```python
   session_key = CryptoPrimitives.derive_session_key(shared_secret)
   ```

3. **AES-CBC-HMAC Key Splitting** (`shared/crypto_primitives.py` - `aes_cbc_hmac_encrypt()`)
   - Derives separate encryption and MAC keys from single key

**Security Property**: Ensures cryptographically strong session keys

---

## AES-256-GCM

### What It Is
AES-256-GCM (Galois/Counter Mode) is an authenticated encryption algorithm that provides both confidentiality and authenticity.

### Why We Use It
- **AEAD (Authenticated Encryption with Associated Data)**: Single algorithm provides both encryption and authentication
- **Hardware acceleration**: Modern CPUs have AES-NI instructions for fast encryption
- **Best for large messages**: Optimal performance for messages >10KB
- **256-bit keys**: Strong security (128 bits of security)
- **Authentication tag**: 128-bit tag detects any modification

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `aes_gcm_encrypt()`, `aes_gcm_decrypt()`

**Usage Locations**:
1. **Message Encryption** (`client/crypto_client.py` - `encrypt_message()`)
   - Encrypts expense submission messages
   - Encrypts all protocol messages

2. **Message Decryption** (`server/server.py` - `process_message()`)
   - Decrypts and verifies client messages
   - Rejects messages with invalid authentication tags

3. **Automatic Selection** (`shared/crypto_primitives.py` - `select_encryption_algorithm()`)
   - Selected for messages >10KB
   - Default for medium-sized messages (1KB-10KB)

**Security Property**: Provides confidentiality and integrity (modification detection)

---

## ChaCha20-Poly1305

### What It Is
ChaCha20-Poly1305 is an authenticated encryption algorithm designed for software implementations.

### Why We Use It
- **Software optimized**: Faster than AES on systems without AES-NI hardware
- **Timing attack resistant**: Constant-time operations
- **Best for small messages**: Optimal for messages <1KB
- **Mobile-friendly**: Better performance on mobile devices
- **AEAD**: Provides both encryption and authentication

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `chacha20_poly1305_encrypt()`, `chacha20_poly1305_decrypt()`

**Usage Locations**:
1. **Small Message Encryption** (`shared/crypto_primitives.py` - `select_encryption_algorithm()`)
   - Automatically selected for messages <1KB
   - Used via `encrypt_message()` function

2. **Protocol Messages** (`client/crypto_client.py`, `server/server.py`)
   - Used when message size triggers selection

**Security Property**: Provides confidentiality and integrity for small messages

---

## AES-256-CBC-HMAC

### What It Is
AES-256-CBC (Cipher Block Chaining) with HMAC-SHA256 provides authenticated encryption using Encrypt-then-MAC.

### Why We Use It
- **Compatibility**: Fallback option for systems that don't support AEAD modes
- **Encrypt-then-MAC**: Secure composition (encrypt first, then MAC)
- **Legacy support**: For environments requiring CBC mode
- **Split keys**: Uses separate keys for encryption and MAC

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `aes_cbc_hmac_encrypt()`, `aes_cbc_hmac_decrypt()`

**Usage Locations**:
1. **Compatibility Mode** (`shared/crypto_primitives.py` - `encrypt_message()`)
   - Can be manually selected if needed
   - Not used by default (AEAD modes preferred)

**Security Property**: Provides confidentiality and integrity (via separate MAC)

---

## SHA-256 Hash Function

### What It Is
SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that produces a 256-bit hash.

### Why We Use It
- **Hash chain**: Creates tamper-evident blockchain ledger
- **Deterministic**: Same input always produces same output
- **One-way**: Cannot reverse hash to get original data
- **Collision resistant**: Different inputs produce different hashes
- **Industry standard**: Widely used and trusted

### Where It's Used

**Implementation**: `shared/crypto_primitives.py` - `hash_data()`, `hash_chain_link()`

**Usage Locations**:
1. **Genesis Hash** (`server/ledger.py` - `__init__()`)
   - Creates initial hash: `hash("SplitSmart Genesis Block")`

2. **Hash Chain** (`server/ledger.py` - `add_entry()`)
   - Each new entry: `hash = SHA256(previous_hash || entry_data)`
   - Creates tamper-evident chain

3. **Chain Verification** (`server/ledger.py` - `verify_chain()`)
   - Recomputes all hashes to detect tampering

4. **Request Hash Deduplication** (`web_app.py` - `api_add_expense()`)
   - Computes hash of request data for replay protection
   - `request_hash = SHA256(username || payer || amount || description)`

5. **Merkle Root** (`server/ledger.py` - `compute_merkle_root()`)
   - Computes Merkle root of all entries for efficient verification

**Security Property**: Provides tamper evidence and replay protection

---

## HMAC-SHA256

### What It Is
HMAC-SHA256 (Hash-based Message Authentication Code) uses SHA-256 to create a message authentication code.

### Why We Use It
- **Request integrity**: Verifies web API requests haven't been modified
- **Shared secret**: Uses session-based integrity key
- **Tamper detection**: Any modification to request body invalidates HMAC
- **Web API protection**: Protects against modification attacks at HTTP layer

### Where It's Used

**Implementation**: `web_app.py` - HMAC computation and verification

**Usage Locations**:
1. **Client-Side HMAC** (`static/js/app.js` - `addExpense()`)
   - Computes HMAC-SHA256 of request body using integrity key
   - Adds `X-Request-HMAC` header to requests
   - Uses Web Crypto API: `crypto.subtle.sign()`

2. **Server-Side Verification** (`web_app.py` - `api_add_expense()`)
   - Retrieves integrity key from session
   - Computes expected HMAC of request body
   - Compares with `X-Request-HMAC` header using `hmac.compare_digest()`
   - Rejects requests with invalid or missing HMAC

3. **Integrity Key Generation** (`web_app.py` - `api_login()`)
   - Generates random 256-bit integrity key per session
   - Stored in Flask session and returned to client
   - Client stores in `localStorage` for persistence

4. **AES-CBC-HMAC Mode** (`shared/crypto_primitives.py` - `aes_cbc_hmac_encrypt()`)
   - Uses HMAC-SHA256 for authentication tag in CBC mode

**Security Property**: Provides request integrity at web API level

---

## bcrypt

### What It Is
bcrypt is a password hashing function designed to be slow and resistant to brute-force attacks.

### Why We Use It
- **Password storage**: Never store plaintext passwords
- **Slow by design**: Makes brute-force attacks expensive
- **Salt included**: Each password hash includes unique salt
- **Adaptive**: Can increase cost factor as hardware improves
- **Industry standard**: Widely used for password hashing

### Where It's Used

**Implementation**: `web_app.py` - Password hashing during registration and verification during login

**Usage Locations**:
1. **User Registration** (`web_app.py` - `api_register()`)
   ```python
   password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
   ```

2. **User Login** (`web_app.py` - `api_login()`)
   ```python
   if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
       # Login successful
   ```

**Security Property**: Protects user passwords from database compromise

---

## Algorithm Selection Logic

The system automatically selects encryption algorithms based on message size:

```python
if message_size < 1KB:
    algorithm = "ChaCha20-Poly1305"  # Fast for small messages
elif message_size > 10KB:
    algorithm = "AES-256-GCM"  # Hardware acceleration for large messages
else:
    algorithm = "AES-256-GCM"  # Default for medium messages
```

**Implementation**: `shared/crypto_primitives.py` - `select_encryption_algorithm()`

---

## Security Properties Summary

| Algorithm | Security Property | Attack Prevented |
|-----------|------------------|------------------|
| RSA-2048 | Authentication, Non-repudiation | Spoofing |
| RSA-PSS | Digital Signatures | Spoofing, Non-repudiation |
| Diffie-Hellman | Forward Secrecy | Eavesdropping (past sessions) |
| HKDF | Key Derivation | Weak keys |
| AES-256-GCM | Confidentiality, Integrity | Eavesdropping, Modification |
| ChaCha20-Poly1305 | Confidentiality, Integrity | Eavesdropping, Modification |
| AES-256-CBC-HMAC | Confidentiality, Integrity | Eavesdropping, Modification |
| SHA-256 | Tamper Evidence | Ledger Tampering |
| HMAC-SHA256 | Request Integrity | Modification (Web API) |
| bcrypt | Password Protection | Brute Force |

---

## Implementation Files

- **Core Primitives**: `shared/crypto_primitives.py`
- **Client Crypto**: `client/crypto_client.py`
- **Server Crypto**: `server/crypto_server.py`
- **Web API Security**: `web_app.py`
- **Client-Side HMAC**: `static/js/app.js`
- **Ledger Hashing**: `server/ledger.py`

