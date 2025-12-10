# How to Run Eavesdropping Attack Demo (Web UI)

## Quick Start

### Step 1: Navigate to Project Root
```bash
cd C:\Users\yathi\OneDrive\Desktop\Blockchain\SplitSmartSecure
```

### Step 2: Run the Demo
```bash
python demos/web_demo_eavesdropping.py
```

That's it! The demo will:
- Start Flask server automatically
- Open Chrome browser (headless mode)
- Register a user
- Add an expense
- Show encrypted network traffic
- Demonstrate confidentiality protection

## What the Demo Shows

1. **User Registration & Login**
   - Registers user "alice" through web UI
   - Establishes secure session

2. **Expense Submission**
   - User submits: "alice paid $100.00 for Secret dinner plans"
   - Through the web interface

3. **Network Traffic Capture**
   - Shows what an attacker would see if intercepting traffic
   - Demonstrates that data is encrypted

4. **Encryption Demonstration**
   - Shows algorithm selection (AES-256-GCM or ChaCha20-Poly1305)
   - Explains how encryption protects confidentiality

## Expected Output

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
   ...

5. ATTACKER EXAMINES THE REQUEST:
   • Request URL: http://localhost:5000/api/add_expense
   • Request Method: POST
   • Content-Type: application/json
   ...

6. WHAT ACTUALLY HAPPENS (Backend Encryption):
   • Client encrypts the expense data with session key
   • Algorithm automatically selected based on message size
   ...

7. VERIFYING EXPENSE WAS ADDED:
   ✓ Ledger section visible
   ✓ Expense successfully added and encrypted

================================================================================
RESULT: Confidentiality Preserved
================================================================================
✓ Web UI uses the same encryption as CLI:
  • AES-256-GCM: Hardware-accelerated, best for large messages
  • ChaCha20-Poly1305: Fast software implementation, best for small messages
  • AES-256-CBC-HMAC: Compatibility option
...
```

## Troubleshooting

### Issue: Module not found
**Solution:**
```bash
# Make sure you're in project root
cd C:\Users\yathi\OneDrive\Desktop\Blockchain\SplitSmartSecure

# Install dependencies if needed
pip install selenium webdriver-manager
```

### Issue: Port 5000 already in use
**Solution:**
```bash
# Kill existing Flask process
# Or change port in web_demo_base.py
```

### Issue: Chrome not found
**Solution:**
- Install Google Chrome browser
- ChromeDriver will be downloaded automatically

### Issue: Server won't start
**Solution:**
- Check if another instance is running
- Close other Flask processes
- Restart terminal

## See Browser in Action

To see the browser (instead of headless mode):

1. Edit `demos/web_demo_base.py`
2. Find line with `--headless`
3. Comment it out or remove it:
   ```python
   # chrome_options.add_argument('--headless')  # Comment this out
   ```

## Manual Testing Alternative

If you want to test manually:

1. Start Flask server:
   ```bash
   python web_app.py
   ```

2. Open browser:
   ```
   http://localhost:5000
   ```

3. Register/login and add expenses

4. Open browser DevTools (F12) → Network tab

5. See encrypted API requests

## Next Steps

After running the eavesdropping demo, try:
- `python demos/web_demo_modification.py` - Modification attack
- `python demos/web_demo_analytics.py` - Analytics features
- `python demos/web_demo_tampering.py` - Tampering detection
- `python demos/run_all_web_demos.py` - All demos

