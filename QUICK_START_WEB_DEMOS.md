# Quick Start: Web UI Demos

## Installation

```bash
# Install dependencies (includes Selenium)
pip install -r requirements.txt
```

**Note:** Chrome browser must be installed. ChromeDriver will be downloaded automatically.

## Run Demos

### Single Demo
```bash
# Eavesdropping attack
python demos/web_demo_eavesdropping.py

# Modification attack
python demos/web_demo_modification.py

# Analytics dashboard
python demos/web_demo_analytics.py

# Tampering detection
python demos/web_demo_tampering.py
```

### All Demos
```bash
python demos/run_all_web_demos.py
```

## What Each Demo Shows

1. **Eavesdropping** - Encrypted network traffic, algorithm selection
2. **Modification** - Authentication tag verification, integrity protection
3. **Analytics** - Dashboard features, charts, blockchain info
4. **Tampering** - Hash chain verification, tamper detection

## Requirements

- Python 3.8+
- Chrome browser installed
- All dependencies from `requirements.txt`

## Troubleshooting

**Chrome not found:** Install Chrome browser
**Port in use:** Kill existing Flask processes or change port
**Database locked:** Close other instances, delete `data/splitsmart.db`

For detailed information, see `WEB_UI_DEMOS_README.md`

