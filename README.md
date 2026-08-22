# Zero-Trust Network Access Dashboard

A Flask web app implementing a simplified **zero-trust access control** system:
every device on your network must be explicitly added to an allow list
(identified by MAC address) to be marked "authorized." Anything else that
connects gets flagged in real time.

## How to run it

1. Install the one dependency:
   ```
   pip3 install -r requirements.txt
   ```

2. Run it:
   ```
   python3 app.py
   ```
   Note: this app runs on port **5001** (not 5000), so you can run it
   alongside Project 1 without conflicts.

3. Open your browser to: http://127.0.0.1:5001

4. **First run:** the app auto-creates a file called `allowed_devices.json`
   in the same folder with an example entry. This is your "trust list."

## How to add your own trusted devices

1. Open `allowed_devices.json` in any text editor
2. You'll see something like:
   ```json
   {
     "aa:bb:cc:dd:ee:ff": "Example - My Laptop"
   }
   ```
3. To find your own devices' real MAC addresses: run the app once, look at
   the dashboard table - it shows the MAC address of every device it finds,
   even ones marked "unauthorized." Copy the MAC of a device you trust.
4. Replace the example line with your real device:
   ```json
   {
     "a1:b2:c3:d4:e5:f6": "My MacBook"
   }
   ```
5. Save the file, restart the app (`Ctrl+C` then `python3 app.py` again)
6. That device now shows "authorized" instead of "unauthorized"

## Why MAC addresses instead of IP addresses

IP addresses are assigned dynamically (via DHCP) and can change every time
a device reconnects. MAC addresses are burned into the device's network
hardware and don't change. Real-world access control systems use MAC
(often combined with other signals) for this reason - it's a stable way
to recognize a specific physical device over time.

## Limitations (know these for interviews - they show maturity)

- Some modern phones use **MAC address randomization** for privacy, which
  can make them look "new" every time they connect - a known real-world
  challenge for MAC-based access control, not a bug in this code
- This is a *monitoring/flagging* system, not an *enforcement* system - it
  tells you who's unauthorized, but doesn't block them (real zero-trust
  systems integrate with router/firewall rules to actually block access -
  a natural "what I'd add next" answer in an interview)

## Putting this on your resume

**Project name:** Zero-Trust Network Access Dashboard

**Resume bullet:**
> Built a zero-trust network access control system (Python, Flask, SQLite)
> that identifies devices by MAC address and flags unauthorized connections
> in real time, distinguishing stable hardware identity from dynamic IP
> assignment.

**Interview talking points:**
- Why MAC over IP: explain the DHCP/dynamic addressing problem
- The zero-trust principle: never assume trust based on network presence alone
- What you'd add next: MAC randomization handling, actual enforcement via
  router integration, alerting (email/SMS on unauthorized connection)

**Skills demonstrated:** Python, Flask, SQLite, MAC/ARP networking
fundamentals, security access-control concepts (zero trust), system design
trade-offs
