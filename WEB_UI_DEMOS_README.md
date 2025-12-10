# Web UI Demos

Browser automation demonstrations of SplitSmart security features through the web interface.

## Overview

These demos use Selenium to automate browser interactions and demonstrate the same security features as the CLI demos, but through the web UI.

## Prerequisites

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Chrome browser:**
   - Chrome must be installed on your system
   - ChromeDriver will be automatically downloaded by webdriver-manager

3. **Verify installation:**
   ```bash
   python -c "from selenium import webdriver; print('Selenium OK')"
   ```

## Available Demos

### 1. Eavesdropping Attack Demo
**File:** `demos/web_demo_eavesdropping.py`

**What it demonstrates:**
- How encrypted messages protect against eavesdropping
- Network traffic interception simulation
- Algorithm selection in web context
- Confidentiality protection

**Run:**
```bash
python demos/web_demo_eavesdropping.py
```

### 2. Modification Attack Demo
**File:** `demos/web_demo_modification.py`

**What it demonstrates:**
- How authentication tags detect modifications
- Message integrity protection
- Authentication failure handling
- Web UI error handling

**Run:**
```bash
python demos/web_demo_modification.py
```

### 3. Analytics Dashboard Demo
**File:** `demos/web_demo_analytics.py`

**What it demonstrates:**
- Analytics features in web UI
- Charts and visualizations
- Summary statistics
- Blockchain information display
- Security status display

**Run:**
```bash
python demos/web_demo_analytics.py
```

### 4. Tampering Detection Demo
**File:** `demos/web_demo_tampering.py`

**What it demonstrates:**
- Database tampering detection
- Hash chain verification
- Blockchain integrity checking
- Real-time tamper detection in web UI

**Run:**
```bash
python demos/web_demo_tampering.py
```

### 5. Run All Demos
**File:** `demos/run_all_web_demos.py`

**Run all web UI demos sequentially:**
```bash
python demos/run_all_web_demos.py
```

## How It Works

### Architecture

```
Web Demo Script (Selenium)
    ↓
Browser Automation (Chrome)
    ↓
Web UI (Flask + HTML/JS)
    ↓
API Endpoints (/api/*)
    ↓
SplitSmartClient (Same as CLI)
    ↓
Crypto Operations (Same as CLI)
```

### Key Components

1. **WebDemoBase** (`demos/web_demo_base.py`):
   - Base class for all web demos
   - Handles server startup/shutdown
   - Browser setup and teardown
   - Common UI interaction methods

2. **Selenium WebDriver**:
   - Automates Chrome browser
   - Interacts with web UI elements
   - Captures network traffic
   - Takes screenshots

3. **Flask Server**:
   - Runs in background subprocess
   - Serves web UI on localhost:5000
   - Same server as manual testing

## Demo Features

### What Each Demo Shows

1. **Eavesdropping Demo:**
   - User registration and login
   - Expense submission through web UI
   - Network traffic capture
   - Encryption demonstration
   - Algorithm selection

2. **Modification Demo:**
   - Legitimate expense creation
   - Attack simulation
   - Authentication failure
   - Integrity protection

3. **Analytics Demo:**
   - Multiple expense creation
   - Dashboard visualization
   - Charts and statistics
   - Blockchain information
   - Security features display

4. **Tampering Demo:**
   - Legitimate expenses
   - Database modification
   - Hash chain verification
   - Tamper detection
   - Blockchain status

## Running Demos

### Individual Demo
```bash
cd SplitSmartSecure
python demos/web_demo_eavesdropping.py
```

### All Demos
```bash
python demos/run_all_web_demos.py
```

### With Output
```bash
# Save output to file
python demos/run_all_web_demos.py > web_demos_output.txt 2>&1
```

## Troubleshooting

### Issue: Chrome/ChromeDriver not found
**Solution:**
- Install Chrome browser
- webdriver-manager will download ChromeDriver automatically
- Or manually install ChromeDriver and add to PATH

### Issue: Server won't start
**Solution:**
- Check if port 5000 is already in use
- Kill existing Flask processes
- Try different port: `WebDemoBase(port=5001)`

### Issue: Elements not found
**Solution:**
- Increase wait times in `web_demo_base.py`
- Check if web UI HTML structure changed
- Verify server is running: `curl http://localhost:5000`

### Issue: Database locked
**Solution:**
- Close any other instances using the database
- Delete `data/splitsmart.db` and restart
- Ensure only one demo runs at a time

## Comparison: CLI vs Web UI Demos

| Feature | CLI Demos | Web UI Demos |
|---------|-----------|--------------|
| **Crypto Operations** | ✅ Same | ✅ Same |
| **Security Features** | ✅ Demonstrated | ✅ Demonstrated |
| **Attack Demonstrations** | ✅ Yes | ✅ Yes |
| **UI Interaction** | ❌ CLI only | ✅ Browser automation |
| **Analytics** | ❌ No | ✅ Yes |
| **Blockchain Visualization** | ❌ No | ✅ Yes |
| **Network Traffic** | ❌ Simulated | ✅ Captured |
| **Screenshots** | ❌ No | ✅ Yes |

## Key Points

1. **Same Security:** Web UI demos use the same crypto code as CLI demos
2. **Real Browser:** Uses actual Chrome browser (headless mode)
3. **Real Server:** Launches actual Flask server
4. **Network Capture:** Can capture actual network traffic
5. **Visual Verification:** Can take screenshots and verify UI

## Extending Demos

To create a new web UI demo:

1. **Create new file:** `demos/web_demo_<name>.py`
2. **Import base class:**
   ```python
   from web_demo_base import WebDemoBase
   ```
3. **Subclass WebDemoBase:**
   ```python
   class WebMyDemo(WebDemoBase):
       def run_demo(self):
           # Your demo code
   ```
4. **Use helper methods:**
   - `start_server()` - Start Flask
   - `setup_driver()` - Setup browser
   - `register_user()` - Register user
   - `login_user()` - Login user
   - `add_expense()` - Add expense
   - `cleanup()` - Cleanup resources

## Notes

- Demos run in **headless mode** (no visible browser window)
- Set `chrome_options.add_argument('--headless')` to `False` to see browser
- Server runs on `localhost:5000` by default
- Database is shared with CLI demos (same file)
- Screenshots saved to current directory

## Integration with CLI Demos

Both CLI and Web UI demos:
- Use the same `SplitSmartClient` class
- Use the same `SplitSmartServer` class
- Use the same crypto primitives
- Share the same database
- Demonstrate the same security features

The difference is the **interface** (CLI vs Web UI), not the **security**.

---

**For more information, see:**
- `ALGORITHM_SELECTION_AND_DEMOS.md` - Algorithm selection details
- `WEB_APP_README.md` - Web application documentation
- `README.md` - Main project documentation

