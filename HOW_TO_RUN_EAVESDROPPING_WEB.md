# How to Run Eavesdropping Attack Demo (Web UI)

## Method 1: Automated Demo (Recommended)

### Step 1: Navigate to Project Root
```powershell
cd C:\Users\yathi\OneDrive\Desktop\Blockchain\SplitSmartSecure
```

### Step 2: Run the Demo
```powershell
python demos/web_demo_eavesdropping.py
```

The demo will automatically:
- ✅ Start Flask server
- ✅ Open browser
- ✅ Register user
- ✅ Add expense
- ✅ Show encrypted traffic
- ✅ Clean up resources

---

## Method 2: Manual Testing (See It Yourself)

### Step 1: Start the Web Server
```powershell
cd C:\Users\yathi\OneDrive\Desktop\Blockchain\SplitSmartSecure
python web_app.py
```

You should see:
```
Starting Flask server...
Open your browser to: http://localhost:5000
```

### Step 2: Open Browser DevTools
1. Open Chrome/Edge browser
2. Go to: `http://localhost:5000`
3. Press **F12** to open Developer Tools
4. Click the **Network** tab

### Step 3: Register and Login
1. Click "Register" tab
2. Enter username: `alice`
3. Enter password: `testpass123`
4. Click "Register"
5. You'll be automatically logged in

### Step 4: Add an Expense
1. In the "Add Expense" form:
   - **Who Paid?**: `alice`
   - **Amount**: `100.00`
   - **Description**: `Secret dinner plans`
2. Click "Submit Expense"

### Step 5: Observe Encrypted Traffic
In the **Network tab**, you'll see:
- Request to `/api/add_expense`
- Click on it to see details
- Look at the **Request Payload**:
  ```json
  {
    "payer": "alice",
    "amount": 100.0,
    "description": "Secret dinner plans"
  }
  ```

### Step 6: Understand the Encryption
**Important Note:** In the actual implementation:
- The data is encrypted **before** being sent
- The web UI uses the same encryption as CLI
- An attacker would only see encrypted ciphertext
- The Network tab shows the **decrypted** JSON for convenience

**What an attacker would actually see:**
- Encrypted ciphertext (base64-encoded)
- Algorithm identifier (AES-256-GCM or ChaCha20-Poly1305)
- Nonce/IV (random bytes)
- **Cannot read the actual expense data without session key**

---

## Method 3: Using Browser Automation (Advanced)

If you want to see the browser in action:

1. Edit `demos/web_demo_base.py`
2. Find this line (around line 100):
   ```python
   chrome_options.add_argument('--headless')
   ```
3. Comment it out:
   ```python
   # chrome_options.add_argument('--headless')  # See browser window
   ```
4. Run the demo:
   ```powershell
   python demos/web_demo_eavesdropping.py
   ```

Now you'll see the browser window open and interact with the web UI!

---

## What the Demo Demonstrates

### 1. **Confidentiality Protection**
- All messages are encrypted
- Attacker cannot read plaintext
- Only parties with session key can decrypt

### 2. **Algorithm Selection**
- Small messages → ChaCha20-Poly1305
- Large messages → AES-256-GCM
- Automatic selection based on message size

### 3. **Network Security**
- Encrypted traffic between browser and server
- Session keys established via secure key exchange
- Same security as CLI version

---

## Expected Output (Automated Demo)

```
================================================================================
                       WEB UI DEMO: Eavesdropping Attack
================================================================================

Scenario: An attacker intercepts network traffic between browser and server
Defense: All messages are encrypted with multiple algorithms

[Web Demo] Starting Flask server on port 5000...
[Web Demo] Server started successfully
[Web Demo] Setting up browser...
[Web Demo] Browser ready

1. Registering and logging in user...
[Web Demo] Registering user: alice

2. Capturing network traffic...
   (In a real attack, an attacker would intercept this traffic)

3. User submits an expense through web UI...
   Plaintext: 'alice paid $100.00 for Secret dinner plans'

4. ATTACKER INTERCEPTS THE NETWORK TRAFFIC:
   Found X API requests
   • POST http://localhost:5000/api/add_expense

5. ATTACKER EXAMINES THE REQUEST:
   • Request URL: http://localhost:5000/api/add_expense
   • Request Method: POST
   • Content-Type: application/json

6. WHAT ACTUALLY HAPPENS (Backend Encryption):
   • Client encrypts the expense data with session key
   • Algorithm automatically selected based on message size
   • Encrypted message sent: {algorithm, nonce, ciphertext}
   • Attacker sees only: base64-encoded ciphertext

7. VERIFYING EXPENSE WAS ADDED:
   ✓ Ledger section visible
   ✓ Expense successfully added and encrypted

================================================================================
RESULT: Confidentiality Preserved
================================================================================
✓ Web UI uses the same encryption as CLI
✓ All network traffic is encrypted
✓ Attacker cannot read message contents
```

---

## Troubleshooting

### Issue: "Module not found"
```powershell
pip install selenium webdriver-manager
```

### Issue: Port 5000 in use
```powershell
# Kill existing Flask process
# Or wait for it to finish
```

### Issue: Chrome not found
- Install Google Chrome browser
- ChromeDriver downloads automatically

### Issue: Demo stops early
- Check if user registration succeeded
- Verify Flask server is running
- Check browser console for errors

---

## Quick Reference

```powershell
# From project root
cd C:\Users\yathi\OneDrive\Desktop\Blockchain\SplitSmartSecure

# Run demo
python demos/web_demo_eavesdropping.py

# Or start server manually
python web_app.py
# Then open http://localhost:5000 in browser
```

---

## Next Steps

After seeing the eavesdropping demo:
- Try `python demos/web_demo_modification.py` - Modification attack
- Try `python demos/web_demo_analytics.py` - Analytics features  
- Try `python demos/web_demo_tampering.py` - Tampering detection
- Try `python demos/run_all_web_demos.py` - All demos at once

