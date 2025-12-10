# Web UI Replay Attack Demo

## Quick Start

```bash
# From project root
python demos/web_demo_replay.py
```

## What It Demonstrates

This demo shows how SplitSmart protects against replay attacks through the web UI using monotonic counters.

### Attack Scenario
1. Attacker captures a valid encrypted message
2. Attacker attempts to replay the same message later
3. Server detects replay using counter check
4. Replayed message is rejected

### Defense Mechanism
- **Monotonic Counters**: Each message has a unique, incrementing counter
- **Server-Side Validation**: Server stores last counter for each user
- **Strict Ordering**: Counter must always increase
- **Automatic Rejection**: Old messages are rejected before processing

## Demo Flow

1. **User Registration**: Registers user "alice" through web UI
2. **First Expense**: User submits expense (counter = 1)
3. **Message Capture**: Attacker intercepts the encrypted message
4. **Replay Attempt**: Attacker tries to replay old message
5. **Counter Increment**: User submits another expense (counter = 2)
6. **Replay Detection**: Server detects old counter and rejects replay
7. **Protection Verification**: Demo shows counter protection in action

## Expected Output

```
================================================================================
                           WEB UI DEMO: Replay Attack
================================================================================

Scenario: An attacker captures a valid message and attempts to replay it
Defense: Monotonic counters prevent message replay

[Web Demo] Starting Flask server on port 5000...
[Web Demo] Server started successfully
[Web Demo] Setting up browser...
[Web Demo] Browser ready

1. Registering and logging in user...
[Web Demo] Registering user: alice

2. User submits a legitimate expense...
   Original: alice paid $50.00 for 'Lunch'

3. ATTACKER CAPTURES THE MESSAGE:
   - Attacker intercepts the encrypted message
   - Message contains: payer, amount, description, counter, signature
   - Counter value: 1 (first expense)

4. ATTACKER ATTEMPTS TO REPLAY THE MESSAGE:
   - Attacker resends the exact same message
   - Same counter value: 1
   - Same signature
   - Same encrypted payload

5. User submits another expense (counter increments to 2)...

6. ATTACKER TRIES TO REPLAY OLD MESSAGE:
   - Attacker sends message with counter = 1
   - Server expects counter > 2 (last counter was 2)
   - Server checks: counter (1) <= stored counter (2)
   [X] REPLAY DETECTED - Message rejected!

7. DEMONSTRATING REPLAY PROTECTION:
   - Each expense must have a counter higher than the previous
   - Server stores the last counter for each user
   - Old messages are automatically rejected
   - Counter increments: 1 -> 2 -> 3 -> ...

================================================================================
                        RESULT: Replay Protection Active
================================================================================

[OK] Web UI uses monotonic counters:
  - Each message has a unique counter value
  - Counter must be greater than previous counter
  - Server rejects messages with old counters

[OK] Replay attacks are prevented:
  - Attacker cannot replay old messages
  - Even with valid encryption, old messages rejected
  - Counter check happens before processing
```

## Key Points

### How Replay Protection Works

1. **Counter Assignment**: Each expense gets a unique counter (1, 2, 3, ...)
2. **Server Storage**: Server stores the last counter for each user
3. **Validation**: Server checks: `new_counter > stored_counter`
4. **Rejection**: If counter is old, message is rejected immediately

### Why It's Secure

- **Even with valid encryption**, old messages are rejected
- **Counter check happens before processing**
- **Strict monotonic ordering** prevents any replay
- **Server-side validation** cannot be bypassed

### Same as CLI Version

The web UI uses the **exact same replay protection** as the CLI version:
- Same counter mechanism
- Same validation logic
- Same security guarantees
- Same protection level

## Troubleshooting

### Form Not Ready
If you see "Expense form not ready", the demo will continue and explain the concept. The replay protection still works - it's just a timing issue with the browser automation.

### See Browser Window
To see the browser in action:
1. Edit `demos/web_demo_base.py`
2. Comment out: `chrome_options.add_argument('--headless')`
3. Run demo again

## Related Demos

- `web_demo_eavesdropping.py` - Eavesdropping protection
- `web_demo_modification.py` - Modification protection
- `web_demo_tampering.py` - Tampering detection
- `web_demo_analytics.py` - Analytics features

## Run All Web Demos

```bash
python demos/run_all_web_demos.py
```

This will run all web UI demos including the replay attack demo.

