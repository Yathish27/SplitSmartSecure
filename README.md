# SplitSmart - Secure Expense Splitting Application

A cryptographically secure expense-splitting service demonstrating end-to-end encryption, digital signatures, tamper-evident blockchain ledger, and protection against common network attacks.

## 🎯 Project Overview

**Course**: NYU CS6903/4783 - Applied Cryptography  
**Project**: 2.7 - Designing an end-to-end cryptography solution  
**Team**: Gagan Yalamuri and Yathish Naraganahalli Veerabhadraiah

SplitSmart is a networked expense-splitting service for a fixed group of users (e.g., roommates, friends) that maintains a cryptographically secure, tamper-evident blockchain ledger of shared expenses.

## ✨ What's New - Latest Updates

### 🆕 Major Features Added

1. **🌐 Web Application (Flask)**
   - Beautiful, modern web UI with animations
   - Real-time expense tracking
   - Interactive blockchain ledger visualization
   - Analytics dashboard with charts
   - Security explanation page

2. **🔐 Multiple Encryption Algorithms**
   - **AES-256-GCM**: Hardware-accelerated, best for large messages
   - **ChaCha20-Poly1305**: Fast software implementation, best for small messages
   - **AES-256-CBC-HMAC**: Compatibility option
   - Automatic algorithm selection based on message size

3. **⛓️ Blockchain Ledger**
   - Block structure with heights and hashes
   - Merkle root computation
   - Tamper-evident hash chain
   - Chain integrity verification

4. **🔑 Password Authentication**
   - Username/password login
   - Secure password hashing (bcrypt)
   - Session management

5. **📊 Analytics Dashboard**
   - Expense summaries
   - Charts and visualizations
   - Detailed analysis
   - Balance calculations

6. **🚀 Deployment Ready**
   - Railway, Render, Heroku configurations
   - Production-ready setup
   - Environment variable support

7. **📽️ Presentation**
   - Complete PowerPoint presentation
   - 17 slides covering all features
   - Attack demonstrations

## 🔒 Security Features

### Three-Layer Cryptographic Architecture

1. **Layer 1: Handshake-Level Authentication**
   - Signed Diffie-Hellman key exchange (STS-style)
   - Mutual authentication using RSA-PSS signatures
   - Establishes secure session with forward secrecy
   - Supports multiple encryption algorithms

2. **Layer 2: Per-Entry Authentication**
   - Digital signatures on each expense record (RSA-PSS)
   - Non-repudiation and origin verification
   - Prevents spoofing attacks

3. **Layer 3: Per-Message Protection**
   - Multiple AEAD encryption algorithms
   - Automatic algorithm selection
   - Confidentiality and integrity for all messages
   - Protects against eavesdropping and modification

### Attack Defenses

| Attack Type | Defense Mechanism | Implementation | Status |
|------------|-------------------|----------------|--------|
| **Eavesdropping** | Multiple encryption algorithms | AES-256-GCM, ChaCha20-Poly1305, AES-CBC-HMAC | ✅ Protected |
| **Modification** | Authentication tags + signatures | GCM tags, Poly1305 MAC, HMAC | ✅ Protected |
| **Spoofing** | RSA-PSS digital signatures | Each entry signed by user | ✅ Protected |
| **Replay** | Monotonic counters | Old messages rejected | ✅ Protected |
| **Ledger Tampering** | Blockchain hash chain | Breaks detected on startup | ✅ Protected |
| **Brute Force** | Rate limiting | API rate limits | ✅ Protected |
| **Injection** | Input validation | Sanitization and validation | ✅ Protected |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Client (Browser)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  HTML/CSS    │  │  JavaScript  │  │  API Calls   │      │
│  │  Interface   │──│  Frontend    │──│  (AJAX)      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS
                             │
┌────────────────────────────┴────────────────────────────────┐
│                    Flask Web Server                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Flask App   │  │  API Routes   │  │  Session     │      │
│  │  (web_app.py)│──│  & Security   │──│  Management  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────────┬────────────────────────────────┘
                             │
                    Encrypted Channel
                    (AES-256-GCM/ChaCha20-Poly1305)
                             │
┌────────────────────────────┴────────────────────────────────┐
│                    SplitSmart Server                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Message     │  │  Blockchain   │  │  Storage     │      │
│  │  Processing  │──│  Ledger       │──│  (SQLite)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  Blockchain: Genesis → Block 0 → Block 1 → ... → Block N   │
│  Hash Chain: H₀ → H₁ → H₂ → ... → Hₙ                       │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Cryptographic Specifications

### Algorithms & Parameters

- **Key Exchange**: Diffie-Hellman (2048-bit) + RSA-PSS signatures
- **Symmetric Encryption**: 
  - AES-256-GCM (hardware-accelerated)
  - ChaCha20-Poly1305 (software-optimized)
  - AES-256-CBC-HMAC (compatibility)
- **Digital Signatures**: RSA-PSS (2048-bit)
- **Hash Function**: SHA-256
- **Key Derivation**: HKDF-SHA256
- **Password Hashing**: bcrypt

### Security Level

All cryptographic choices provide ≥128-bit security, aligned with NIST recommendations.

## 📁 Project Structure

```
SplitSmartSecure/
├── client/                      # Client-side code
│   ├── client.py               # Main client application
│   └── crypto_client.py        # Client-side crypto operations
├── server/                      # Server-side code
│   ├── server.py               # Main server application
│   ├── crypto_server.py        # Server-side crypto operations
│   ├── ledger.py               # Blockchain ledger management
│   └── storage.py              # SQLite database operations
├── shared/                      # Shared utilities
│   ├── crypto_primitives.py    # Core crypto functions
│   ├── protocols.py            # Protocol message formats
│   └── constants.py             # Cryptographic constants
├── demos/                       # Attack demonstrations
│   ├── demo_eavesdropping.py   # Eavesdropping attack demo
│   ├── demo_modification.py    # Modification attack demo
│   ├── demo_spoofing.py        # Spoofing attack demo
│   ├── demo_replay.py          # Replay attack demo
│   └── demo_tampering.py       # Ledger tampering demo
├── tests/                       # Test suites
│   ├── test_crypto.py          # Crypto primitives tests
│   ├── test_key_exchange.py     # Key exchange tests
│   └── test_signature.py       # Signature verification tests
├── static/                      # Web static files
│   ├── css/
│   │   └── style.css           # Web UI styles
│   └── js/
│       └── app.js              # Web UI JavaScript
├── templates/                   # Web templates
│   └── index.html              # Main web page
├── keys/                        # Key storage directory
├── data/                        # Database storage
├── main.py                      # Main demo application
├── web_app.py                   # Flask web application
├── run_all_demos.py             # Run all attack demos
├── requirements.txt             # Python dependencies
├── Procfile                     # Deployment configuration
├── runtime.txt                  # Python version
└── README.md                    # This file
```

## 🚀 Installation & Setup

### Prerequisites

- **Python 3.8 or higher** (Python 3.11 recommended)
- **pip** (Python package manager)
- **Git** (for cloning repository)

### Step-by-Step Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/G4G4N/SplitSmartSecure.git
cd SplitSmartSecure
```

#### 2. Create Virtual Environment

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed cryptography-41.0.0 flask-3.0.0 flask-cors-4.0.0 bcrypt-4.0.0 ...
```

#### 4. Verify Installation

```bash
python -c "from cryptography.hazmat.primitives import hashes; print('✓ Installation successful')"
```

**Expected output:**
```
✓ Installation successful
```

#### 5. Verify All Components

```bash
# Check Python version
python --version
# Should show: Python 3.8+ or 3.11+

# Check Flask
python -c "import flask; print(f'Flask {flask.__version__}')"

# Check cryptography
python -c "from cryptography.hazmat.primitives import hashes; print('✓ Cryptography OK')"
```

## 💻 Usage

### Option 1: Web Application (Recommended)

#### Start the Web Server

```bash
python web_app.py
```

**Expected output:**
```
================================================================================
                        SplitSmart Web Application
================================================================================

Starting Flask server...
Open your browser to: http://localhost:5000

Press Ctrl+C to stop the server
================================================================================
```

#### Access the Web UI

1. Open your browser
2. Navigate to: `http://localhost:5000`
3. You'll see the SplitSmart web interface

#### Web UI Features

- **Registration**: Create new user account
- **Login**: Secure password-based authentication
- **Add Expenses**: Submit expenses with payer, amount, description
- **View Ledger**: See blockchain ledger with all expenses
- **Analytics**: View charts and statistics
- **Blockchain Info**: See block heights, hashes, chain validity
- **Security Explanation**: Learn how encryption works

#### Test the Web Application

1. **Register a User:**
   - Click "Register"
   - Enter username and password
   - Click "Register"

2. **Login:**
   - Enter username and password
   - Click "Login"

3. **Add Expenses:**
   - Enter payer name
   - Enter amount (e.g., 50.00)
   - Enter description (e.g., "Dinner")
   - Click "Add Expense"

4. **View Blockchain:**
   - Click "Dashboard"
   - See blockchain ledger
   - View block heights and hashes

5. **View Analytics:**
   - See expense summaries
   - View charts
   - Check balances

### Option 2: Command Line Interface

#### Quick Start Demo

```bash
python main.py demo
```

**This will:**
1. Register three users (alice, bob, charlie)
2. Establish secure sessions
3. Record multiple expenses
4. Display the blockchain ledger with hash chain verification
5. Show blockchain information (blocks, hashes, chain validity)
6. Calculate and show balances

**Expected output:**
```
================================================================================
                    SplitSmart - Secure Expense Splitting Demo
================================================================================

ℹ Initializing server...
✓ Server initialized

================================================================================
                        Phase 1: User Registration
================================================================================

Registering alice...
✓ alice registered
...
```

#### Interactive Mode

```bash
python main.py interactive
```

**Available commands:**
- `register <username>` - Register a new user
- `login <username>` - Login as user
- `add <payer> <amount> <desc>` - Add expense
- `ledger` - View blockchain ledger
- `balances` - View balances
- `users` - List registered users
- `logout` - Logout current user
- `exit` - Exit program

### Option 3: Individual Attack Demonstrations

#### 1. Eavesdropping Attack

```bash
python demos/demo_eavesdropping.py
```

**What it demonstrates:**
- How attackers intercept encrypted messages
- Why they cannot decrypt without the session key
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305)

**Expected output:**
```
================================================================================
                        ATTACK DEMO: Eavesdropping
================================================================================

Scenario: An attacker intercepts network traffic between client and server
Defense: All messages are encrypted with AES-256-GCM

1. Setting up server and client...
2. Alice registers and logs in...
...
4. ATTACKER INTERCEPTS THE MESSAGE:
   Nonce: a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5...
   Ciphertext: x7y8z9a0b1c2d3e4f5g6h7i8j9k0l1m2...
...
✓ AES-256-GCM encryption protects against eavesdropping
```

#### 2. Modification Attack

```bash
python demos/demo_modification.py
```

**What it demonstrates:**
- How attackers try to modify encrypted messages
- How authentication tags detect modifications
- Why modified messages are rejected

#### 3. Spoofing Attack

```bash
python demos/demo_spoofing.py
```

**What it demonstrates:**
- How attackers try to impersonate users
- How digital signatures prevent spoofing
- Why invalid signatures are rejected

#### 4. Replay Attack

```bash
python demos/demo_replay.py
```

**What it demonstrates:**
- How attackers capture and replay old messages
- How monotonic counters prevent replay
- Why old messages are rejected

#### 5. Ledger Tampering

```bash
python demos/demo_tampering.py
```

**What it demonstrates:**
- How attackers modify database directly
- How blockchain hash chain detects tampering
- Why tampered entries break the chain

### Run All Demos

```bash
python run_all_demos.py
```

**This runs all attack demonstrations sequentially:**
1. Eavesdropping Attack
2. Modification Attack
3. Spoofing Attack
4. Replay Attack
5. Ledger Tampering

## 🔬 Testing

### Run All Tests

```bash
pytest tests/ -v
```

**Expected output:**
```
tests/test_crypto.py::test_aes_gcm_encryption ... PASSED
tests/test_crypto.py::test_rsa_signature ... PASSED
tests/test_key_exchange.py::test_dh_key_exchange ... PASSED
...
```

### Run Specific Test Suites

```bash
# Crypto primitives
pytest tests/test_crypto.py -v

# Key exchange
pytest tests/test_key_exchange.py -v

# Signature verification
pytest tests/test_signature.py -v
```

### Test Coverage

```bash
pytest tests/ --cov=. --cov-report=html
```

**This generates:**
- Coverage report in terminal
- HTML report in `htmlcov/index.html`

### Verify Security Features

#### Test 1: Encryption Algorithms

```bash
python -c "
from shared.crypto_primitives import CryptoPrimitives
key = b'0' * 32
plaintext = b'Test message'
nonce, ciphertext = CryptoPrimitives.aes_gcm_encrypt(key, plaintext)
decrypted = CryptoPrimitives.aes_gcm_decrypt(key, nonce, ciphertext)
print('✓ AES-256-GCM works:', decrypted == plaintext)
"
```

#### Test 2: Digital Signatures

```bash
python -c "
from shared.crypto_primitives import CryptoPrimitives
private_key, public_key = CryptoPrimitives.generate_rsa_keypair()
message = b'Test message'
signature = CryptoPrimitives.rsa_pss_sign(private_key, message)
is_valid = CryptoPrimitives.rsa_pss_verify(public_key, signature, message)
print('✓ RSA-PSS signatures work:', is_valid)
"
```

#### Test 3: Blockchain Ledger

```bash
python -c "
from server.server import SplitSmartServer
server = SplitSmartServer()
info = server.ledger.get_blockchain_info()
print('✓ Blockchain initialized')
print(f'  Genesis hash: {info[\"genesis_hash\"][:32]}...')
print(f'  Chain valid: {info[\"is_valid\"]}')
"
```

## ✅ Verification Checklist

### Basic Functionality

- [ ] **Installation**: All dependencies installed successfully
- [ ] **Web Server**: Flask app starts without errors
- [ ] **Registration**: Can register new users
- [ ] **Login**: Can login with username/password
- [ ] **Add Expense**: Can submit expenses
- [ ] **View Ledger**: Can see blockchain ledger
- [ ] **Analytics**: Dashboard shows data

### Security Features

- [ ] **Encryption**: Messages are encrypted (check network tab)
- [ ] **Signatures**: Expenses are signed (check ledger)
- [ ] **Hash Chain**: Blockchain integrity verified
- [ ] **Replay Protection**: Old messages rejected
- [ ] **Tamper Detection**: Database tampering detected

### Attack Demonstrations

- [ ] **Eavesdropping Demo**: Shows ciphertext is unreadable
- [ ] **Modification Demo**: Shows modified messages rejected
- [ ] **Spoofing Demo**: Shows invalid signatures rejected
- [ ] **Replay Demo**: Shows old messages rejected
- [ ] **Tampering Demo**: Shows hash chain breaks

### Web Application

- [ ] **UI Loads**: Web page displays correctly
- [ ] **Registration Form**: Can register users
- [ ] **Login Form**: Can login
- [ ] **Expense Form**: Can add expenses
- [ ] **Dashboard**: Shows analytics
- [ ] **Blockchain**: Shows block information
- [ ] **Security Page**: Explains encryption

## 📊 Protocol Flow

### 1. User Registration

```
Client                                Server
  │                                     │
  │──── Register(user_id, pub_key) ───→│
  │     password_hash                   │ Store user & initialize counter
  │                                     │
  │←──── Success ─────────────────────│
```

### 2. Login & Session Establishment (Signed DH)

```
Client                                Server
  │                                     │
  │──── Login(user_id, password) ─────→│
  │                                     │ Verify password
  │                                     │
  │──── ClientHello + DH_pub + Sig ───→│
  │                                     │ Verify signature
  │                                     │ Generate DH_pub
  │←─── ServerHello + DH_pub + Sig ───│
  │     encryption_algo                 │
  │                                     │
  │ Verify signature                    │
  │ Compute shared secret               │ Compute shared secret
  │ K_session = HKDF(secret)            │ K_session = HKDF(secret)
  │ Select encryption algorithm         │ Store algorithm in session
```

### 3. Expense Submission

```
Client                                Server
  │                                     │
  │ Create expense record               │
  │ Sign(expense || counter || ts)      │
  │ Encrypt with K_session              │
  │ (using selected algorithm)          │
  │                                     │
  │──── Encrypted(expense + sig) ─────→│
  │     algorithm, nonce, ciphertext     │
  │                                     │ Decrypt with K_session
  │                                     │ Verify signature
  │                                     │ Check counter > stored
  │                                     │ Add to blockchain
  │                                     │ Compute block hash
  │                                     │ Store in database
  │←──── Encrypted(success) ───────────│
  │     block_height, block_hash        │
```

## 🔍 Security Analysis

### Threat Model

**Attacker Capabilities:**
- Full control over network (MITM position)
- Can capture, modify, replay messages
- Read/write access to backend storage
- Can attempt brute force attacks

**Assumptions:**
- Client devices are secure
- Private keys are not compromised
- Users are authenticated to their client
- Server is trusted (centralized model)

### Security Properties

✅ **Confidentiality**: All expense data encrypted with multiple algorithms  
✅ **Integrity**: Modifications detected via authentication tags and signatures  
✅ **Authentication**: Each entry signed by user's private key  
✅ **Non-repudiation**: Digital signatures provide proof of origin  
✅ **Replay Protection**: Monotonic counters prevent replay  
✅ **Tamper Evidence**: Blockchain hash chain detects ledger modifications  
✅ **Forward Secrecy**: Ephemeral DH keys protect past sessions  
✅ **Rate Limiting**: Prevents brute force attacks  
✅ **Input Validation**: Prevents injection attacks  

### Attack Resistance

| Attack | Mechanism | Result |
|--------|-----------|--------|
| Passive eavesdropping | Capture encrypted traffic | ✗ Cannot decrypt without K_session |
| Active MITM | Modify ciphertext | ✗ Authentication tag verification fails |
| Impersonation | Submit expense as another user | ✗ Signature verification fails |
| Replay | Resend old valid message | ✗ Counter check rejects |
| Ledger tampering | Modify database entry | ✗ Hash chain breaks |
| Brute force | Multiple login attempts | ✗ Rate limiting prevents |
| SQL injection | Malicious input | ✗ Input validation prevents |

## 📈 Performance Considerations

### Cryptographic Operations

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| Key Generation (RSA-2048) | ~100ms | One-time per user |
| DH Parameter Generation | ~2-5s | One-time per server |
| DH Key Exchange | ~10ms | Per session |
| AES-GCM Encrypt/Decrypt | <1ms | Per message |
| ChaCha20-Poly1305 | <1ms | Per message (small) |
| RSA-PSS Sign/Verify | ~1-2ms | Per expense |
| SHA-256 Hash | <1ms | Per ledger entry |
| Blockchain Verification | O(n) | Linear with entries |

### Scalability

- **Users**: Designed for small groups (10-50 users)
- **Expenses**: Hash chain scales linearly O(n)
- **Sessions**: Multiple concurrent sessions supported
- **Storage**: SQLite suitable for thousands of entries
- **Web**: Flask handles concurrent requests

## 🚀 Deployment

### Quick Deploy to Railway

1. **Push to GitHub:**
   ```bash
   git push origin main
   ```

2. **Deploy on Railway:**
   - Go to [railway.app](https://railway.app)
   - Sign up with GitHub
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository

3. **Set Environment Variables:**
   - `SECRET_KEY`: Generate random string
   - `FLASK_DEBUG`: `false`

4. **Get Public URL:**
   - Railway provides URL automatically
   - Share to showcase your project!

See `DEPLOYMENT_GUIDE.md` for detailed instructions.

## 📚 Documentation

### Main Documentation Files

- **README.md** (this file) - Main project documentation
- **WEB_APP_README.md** - Web application guide
- **BLOCKCHAIN_SECURITY_README.md** - Security documentation
- **ENCRYPTION_ALGORITHMS_README.md** - Encryption algorithms guide
- **DEMO_GUIDE.md** - Demo instructions
- **DEPLOYMENT_GUIDE.md** - Deployment instructions
- **TESTING_GUIDE.md** - Testing guide

### Presentation

- **PRESENTATION.md** - Presentation content
- **SplitSmart_Presentation.pptx** - PowerPoint presentation
- **create_presentation.py** - Script to generate PPT

## 🛠️ Development

### Adding New Features

1. **New Message Type**: Add to `shared/protocols.py`
2. **New Crypto Primitive**: Add to `shared/crypto_primitives.py`
3. **New Attack Demo**: Create in `demos/` directory
4. **New Test**: Add to `tests/` directory
5. **Web Feature**: Update `web_app.py`, `templates/index.html`, `static/js/app.js`

### Code Style

- Follow PEP 8 guidelines
- Use type hints where applicable
- Document all cryptographic operations
- Include security considerations in comments

## 📝 Changelog

### Version 2.0 (Latest)

**Added:**
- ✅ Web application with Flask
- ✅ Multiple encryption algorithms (AES-GCM, ChaCha20-Poly1305, AES-CBC-HMAC)
- ✅ Blockchain ledger with block structure
- ✅ Password authentication
- ✅ Analytics dashboard
- ✅ Deployment configurations
- ✅ PowerPoint presentation
- ✅ Comprehensive documentation

**Improved:**
- ✅ Algorithm selection based on message size
- ✅ Enhanced security features
- ✅ Better error handling
- ✅ Production-ready configuration

### Version 1.0 (Initial)

**Features:**
- ✅ Basic CLI application
- ✅ AES-256-GCM encryption
- ✅ RSA-PSS signatures
- ✅ Hash chain ledger
- ✅ Attack demonstrations

## 🐛 Known Limitations

1. **Small Group Size**: Designed for fixed, small groups
2. **No User Revocation**: Cannot remove users once registered
3. **Simple Balance Calculation**: Basic debt simplification algorithm
4. **SQLite Database**: File-based, not ideal for high concurrency
5. **Centralized Server**: Single point of trust

## 🔮 Future Enhancements

### Potential Additions

- ⏳ PostgreSQL database support
- ⏳ Key rotation/evolution
- ⏳ Merkle tree for efficient proofs
- ⏳ Mobile app (iOS/Android)
- ⏳ Multi-device support per user
- ⏳ Backup and recovery mechanisms
- ⏳ Post-quantum cryptography
- ⏳ Distributed ledger

## 📚 References

### Cryptographic Primitives

- **AES-GCM**: NIST SP 800-38D
- **ChaCha20-Poly1305**: RFC 8439
- **RSA-PSS**: PKCS #1 v2.2
- **Diffie-Hellman**: RFC 2631
- **HKDF**: RFC 5869
- **SHA-256**: FIPS 180-4
- **bcrypt**: OpenBSD

### Libraries

- **cryptography**: https://cryptography.io/
- **Flask**: https://flask.palletsprojects.com/
- **Python**: https://www.python.org/

### Course Materials

- NYU CS6903/4783 - Applied Cryptography
- Lectures 1-7: Symmetric encryption, public-key crypto, signatures, key exchange

## 📝 License

This is an academic project for NYU CS6903/4783. All rights reserved.

## 👥 Authors

- **Gagan Yalamuri**
- **Yathish Naraganahalli Veerabhadraiah**

## 🙏 Acknowledgments

- NYU CS6903/4783 course staff
- Python cryptography library maintainers
- Flask framework developers
- OpenSSL project

---

## 🎓 Quick Start Summary

1. **Install**: `pip install -r requirements.txt`
2. **Run Web App**: `python web_app.py` → Open `http://localhost:5000`
3. **Run Demo**: `python main.py demo`
4. **Test Attacks**: `python demos/demo_eavesdropping.py`
5. **Run Tests**: `pytest tests/ -v`

**For detailed instructions, see sections above.**

---

**Note**: This is an educational project demonstrating cryptographic concepts. It is not intended for production use without further security auditing and hardening.
