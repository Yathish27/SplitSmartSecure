# Testing Modification and Tampering Attacks with Burp Suite

This guide explains how to test modification and tampering attacks against the SplitSmart web application using Burp Suite.

## Prerequisites

1. **Burp Suite Community Edition** (or Professional)
2. **SplitSmart web application** running locally or deployed
3. **Browser** configured to use Burp Suite as proxy
4. **Valid user account** registered and logged in

## Setup Burp Suite Proxy

1. **Start Burp Suite**
2. **Configure Proxy**:
   - Go to **Proxy** → **Options**
   - Ensure proxy is listening on `127.0.0.1:8080` (default)
   - Enable **Intercept Client Requests** (optional, for manual modification)

3. **Configure Browser**:
   - Install Burp Suite CA certificate (if using HTTPS)
   - Set browser proxy to `127.0.0.1:8080`
   - Or use Burp's built-in browser

---

## Test 1: Eavesdropping Attack (Passive Interception)

### Objective
Test if an attacker can read sensitive data by intercepting network traffic.

### Important Note
The SplitSmart application has **two layers**:
1. **Web API Layer** (HTTP/JSON) - Uses plain JSON but protected by HMAC for modification detection
2. **Cryptographic Protocol Layer** - Uses AES-256-GCM encryption (used by CLI)

For the web API, data is transmitted as **plain JSON** (visible to eavesdroppers), but:
- **HMAC protection** prevents modification
- **Replay protection** prevents duplicate requests
- The underlying cryptographic protocol (used by `client.add_expense()`) does encrypt at a lower level

### Steps

1. **Setup Burp Suite Proxy**
   - Configure browser to use Burp proxy (`127.0.0.1:8080`)
   - Go to **Proxy** → **HTTP history**

2. **Login and Submit Expense**
   - Login to the web application
   - Submit an expense with sensitive data:
     ```json
     {
       "payer": "alice",
       "amount": 100.00,
       "description": "Secret business meeting"
     }
     ```

3. **Intercept in Burp Suite**
   - Find the `POST /api/add_expense` request in **Proxy** → **HTTP history**
   - Right-click → **Send to Repeater**

4. **Examine Intercepted Data**
   - In Repeater, look at the **Request** panel
   - You'll see:
     ```json
     {
       "payer": "alice",
       "amount": 100.00,
       "description": "Secret business meeting"
     }
     ```
   - **Observation**: The data is in **plain text** (not encrypted at HTTP level)

5. **What This Demonstrates**
   - ✅ **Web API Level**: Data is visible to eavesdroppers (plain JSON)
   - ✅ **Protection**: HMAC header (`X-Request-HMAC`) prevents modification
   - ✅ **Protection**: Replay protection prevents duplicate requests
   - ⚠️ **Note**: For true encryption, use the CLI which uses the cryptographic protocol

6. **Testing True Encryption (Protocol Level)**
   - To see encrypted traffic, use the CLI demo:
     ```bash
     python demos/demo_eavesdropping.py
     ```
   - This shows AES-256-GCM encrypted messages (unintelligible ciphertext)

### Expected Results

**Web API Level (HTTP):**
- ✅ Attacker can see plain JSON data
- ✅ Attacker cannot modify data (HMAC protection)
- ✅ Attacker cannot replay requests (replay protection)

**Protocol Level (Cryptographic):**
- ✅ Attacker sees encrypted ciphertext (unintelligible)
- ✅ Attacker cannot decrypt without session key
- ✅ Confidentiality preserved

### Key Takeaway

- **Web API**: Uses plain JSON for simplicity, protected by HMAC and replay protection
- **Protocol Layer**: Uses full encryption (AES-256-GCM) for confidentiality
- **Both layers** provide security, but at different levels

---

## Test 2: Modification Attack (Message Tampering)

### Objective
Test if the application detects when an attacker modifies the request payload in transit.

### Steps

1. **Start the Application**
   ```bash
   python web_app.py
   # Or if deployed: https://your-app-url.com
   ```

2. **Login and Capture Request**
   - Open browser and navigate to the application
   - Login with valid credentials
   - Open Burp Suite → **Proxy** → **HTTP history**

3. **Submit a Legitimate Expense**
   - In the web UI, add an expense:
     - Payer: `alice`
     - Amount: `50.00`
     - Description: `Lunch`
   - Submit the form
   - Find the request in Burp Suite HTTP history: `POST /api/add_expense`

4. **Send to Repeater**
   - Right-click the request → **Send to Repeater**
   - Go to **Repeater** tab

5. **Examine Original Request**
   ```json
   POST /api/add_expense HTTP/1.1
   Host: localhost:5001
   Content-Type: application/json
   Cookie: session=...
   
   {
     "payer": "alice",
     "amount": 50.00,
     "description": "Lunch"
   }
   ```

6. **Modify the Request (Attack)**
   - Change the amount from `50.00` to `500.00`:
   ```json
   {
     "payer": "alice",
     "amount": 500.00,
     "description": "Lunch"
   }
   ```
   - Or change the payer:
   ```json
   {
     "payer": "bob",
     "amount": 50.00,
     "description": "Lunch"
   }
   ```
   - Or change the description:
   ```json
   {
     "payer": "alice",
     "amount": 50.00,
     "description": "Expensive Dinner"
   }
   ```

7. **Send Modified Request**
   - Click **Send** in Repeater
   - Observe the response

### Expected Results

**If Modification Protection Works:**
- ✅ **First request**: Returns `200 OK` with success message
- ✅ **Modified request**: Should be rejected, but...

**Important Note**: 
The web API currently accepts modified requests because:
- The web API uses plain JSON (not encrypted at HTTP level)
- The cryptographic protection happens at a lower level (client-server protocol)
- For web API testing, you're testing the **replay protection** we just added

**To Test True Modification Protection:**
You need to test at the cryptographic protocol level using the CLI demos:
```bash
python demos/demo_modification.py
```

---

## Test 2: Replay Attack (Already Protected)

### Objective
Test if the application prevents replaying the exact same request multiple times.

### Steps

1. **Capture a Valid Request**
   - Follow steps 1-4 from Test 1
   - Capture a successful expense submission

2. **Send Original Request**
   - Click **Send** in Repeater
   - Note the response: Should be `200 OK` with success

3. **Replay the Same Request**
   - Click **Send** again (without modifying anything)
   - Observe the response

### Expected Results

**With Replay Protection (Current Implementation):**
- ✅ **First request**: `200 OK` - Expense added successfully
- ✅ **Replayed request**: `409 Conflict` - "Replay attack detected: This exact request was already processed recently"

**Response Example:**
```json
{
  "success": false,
  "error": "Replay attack detected: This exact request was already processed recently"
}
```

---

## Test 3: Tampering Attack (Database Modification)

### Objective
Test if the application detects when the database is modified directly (bypassing the application).

### Important Note
Burp Suite **cannot directly modify the database**. This attack requires:
1. Direct database access (SQLite file access)
2. Or SQL injection (which the app protects against)

### Testing Tampering Detection

#### Method 1: Using the Demo Script
```bash
python demos/demo_tampering.py
```

This script:
1. Creates legitimate expenses
2. Directly modifies the SQLite database
3. Restarts the server (triggers integrity check)
4. Shows that tampering is detected

#### Method 2: Manual Database Tampering

1. **Add Legitimate Expenses**
   - Use the web UI to add 2-3 expenses
   - Note the entry IDs

2. **Stop the Server**
   ```bash
   pkill -f "python.*web_app"
   ```

3. **Modify Database Directly**
   ```bash
   sqlite3 data/splitsmart.db
   ```
   ```sql
   -- View entries
   SELECT id, payer, amount, description FROM ledger;
   
   -- Modify an entry (ATTACK)
   UPDATE ledger SET amount = 999.99 WHERE id = 1;
   
   -- Exit
   .exit
   ```

4. **Restart Server and Check**
   ```bash
   python web_app.py
   ```
   - The server should detect tampering on startup
   - Check the `/api/verify_tampering` endpoint:
   ```bash
   curl http://localhost:5001/api/verify_tampering
   ```

5. **Expected Response**
   ```json
   {
     "success": true,
     "is_valid": false,
     "error": "Hash mismatch at entry 1",
     "message": "Tampering detected: Hash mismatch at entry 1"
   }
   ```

---

## Test 4: Advanced Modification Testing

### Testing Different Modification Scenarios

#### A. Modify Amount
```json
Original: {"amount": 50.00}
Modified: {"amount": 500.00}
```
**Result**: Request accepted (web API level), but replay protection will block duplicates

#### B. Modify Payer
```json
Original: {"payer": "alice"}
Modified: {"payer": "bob"}
```
**Result**: Request accepted if bob exists, replay protection blocks duplicates

#### C. Modify Description
```json
Original: {"description": "Lunch"}
Modified: {"description": "Expensive Dinner"}
```
**Result**: Request accepted, replay protection blocks duplicates

#### D. Add Extra Fields
```json
Original: {"payer": "alice", "amount": 50.00, "description": "Lunch"}
Modified: {"payer": "alice", "amount": 50.00, "description": "Lunch", "extra": "hack"}
```
**Result**: Extra fields ignored by server (input validation)

#### E. Remove Required Fields
```json
Original: {"payer": "alice", "amount": 50.00, "description": "Lunch"}
Modified: {"payer": "alice", "amount": 50.00}
```
**Result**: `400 Bad Request` - "description is required"

---

## Test 5: Testing with Intruder (Automated Testing)

### Using Burp Suite Intruder for Fuzzing

1. **Capture Request**
   - Capture a valid expense submission
   - Send to **Intruder**

2. **Configure Attack**
   - Go to **Intruder** → **Positions**
   - Mark the amount field: `"amount": §50.00§`
   - Select attack type: **Sniper** (single payload position)

3. **Set Payloads**
   - Go to **Payloads** tab
   - Add payloads:
     ```
     0.01
     50.00
     100.00
     500.00
     1000.00
     999999.99
     ```

4. **Start Attack**
   - Click **Start attack**
   - Observe responses

5. **Analyze Results**
   - Look for:
     - `200 OK`: Valid requests
     - `400 Bad Request`: Invalid input
     - `409 Conflict`: Replay detected (if same request)
     - `401 Unauthorized`: Session expired

---

## Understanding the Protection Layers

### Layer 1: Input Validation
- **What it protects**: Invalid data types, missing fields, out-of-range values
- **Test with**: Invalid JSON, missing fields, wrong types
- **Burp Suite**: Modify request structure

### Layer 2: Replay Protection (Web API)
- **What it protects**: Duplicate requests within 5 minutes
- **Test with**: Replay exact same request
- **Burp Suite**: Send same request multiple times in Repeater

### Layer 3: Cryptographic Protection (Protocol Level)
- **What it protects**: Message modification, encryption, signatures
- **Test with**: CLI demos (`demo_modification.py`)
- **Burp Suite**: Cannot test (happens below HTTP layer)

### Layer 4: Database Tampering Detection
- **What it protects**: Direct database modifications
- **Test with**: Direct SQLite modification + integrity check
- **Burp Suite**: Cannot test (requires file system access)

---

## Expected Attack Results Summary

| Attack Type | Burp Suite Test | Expected Result | Protection Layer |
|------------|----------------|-----------------|------------------|
| **Replay** | Send same request twice | `409 Conflict` | Replay Protection |
| **Invalid Input** | Missing required field | `400 Bad Request` | Input Validation |
| **Amount Tampering** | Change amount in JSON | Accepted (but replay blocked) | Replay Protection |
| **SQL Injection** | Inject SQL in fields | `400 Bad Request` | Input Validation |
| **XSS** | Inject script tags | Sanitized/Rejected | Input Sanitization |
| **Modification (Crypto)** | N/A (below HTTP) | Rejected | AES-GCM Auth Tag |
| **Database Tampering** | N/A (requires DB access) | Detected on startup | Hash Chain |

---

## Tips for Effective Testing

1. **Use Repeater for Manual Testing**
   - Best for testing specific modifications
   - Easy to iterate and see responses

2. **Use Intruder for Automated Testing**
   - Test multiple payload variations
   - Identify edge cases

3. **Monitor Server Logs**
   - Check application logs for errors
   - Verify protection mechanisms are triggered

4. **Test Edge Cases**
   - Very large amounts
   - Very long descriptions
   - Special characters
   - Unicode characters

5. **Test Session Management**
   - Expired sessions
   - Invalid session cookies
   - Session hijacking attempts

---

## Verification Checklist

After testing, verify:

- [ ] Replay attacks are blocked (409 Conflict)
- [ ] Invalid input is rejected (400 Bad Request)
- [ ] Valid requests are accepted (200 OK)
- [ ] Session expiration is handled (401 Unauthorized)
- [ ] Rate limiting works (429 Too Many Requests)
- [ ] Database tampering is detected (integrity check)

---

## Notes

- **Web API vs Protocol Level**: The web API uses plain JSON, so modification at the HTTP level is possible. True cryptographic protection happens at the client-server protocol level (used by CLI).
- **Replay Protection**: Currently implemented at web API level using request hash deduplication (5-minute window).
- **Tampering Detection**: Requires direct database access and is detected via hash chain verification on server startup.

---

## Related Files

- `demos/demo_modification.py` - CLI modification attack demo
- `demos/demo_tampering.py` - CLI tampering attack demo
- `demos/demo_replay.py` - CLI replay attack demo
- `web_app.py` - Web application with replay protection

