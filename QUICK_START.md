# Mafsal — Quick Start Guide

> No technical knowledge required. Follow the steps below.

---

## What does this do?

In short: on untrusted networks — hotels, kiosks, shared offices — it
routes Firefox through a secure encrypted tunnel. Nobody on the network
can see what you are doing, no trace is left on the kiosk, and if the
tunnel breaks, Firefox **cannot** reach the internet directly.

---

## What you need

| Item | Where |
|------|-------|
| Google Colab account | colab.google.com (free) |
| Python 3.9+ | Should already be on the kiosk |
| Firefox ESR 115+ | Should already be on the kiosk |
| A 64-character hex key | You will generate it below |

---

## Step 1 — Generate a key

Paste this in a terminal and run it. Save the output.

```bash
python3 -c "import os; print(os.urandom(32).hex())"
```

Output looks like:
```
a3f1cc8d...9b4e2701
```

**Write this key down somewhere safe. You will enter it on both Colab
and the kiosk — they must be identical.**

---

## Step 2 — Set up Colab

1. Open [colab.google.com](https://colab.google.com) and create a new notebook.
2. Upload `mafsal_server.py` and `traffic_shaping.py` to Colab
   (drag-and-drop onto the folder icon in the left sidebar).
3. Open `colab_setup.py` and run the cells **in order**:

**Cell 1** — install packages (run once):
```
!pip install -q websockets cryptography
```

**Cell 2** — enter your key (paste the key from Step 1):
```python
import os
os.environ["RELAY_KEY"] = "PASTE_YOUR_KEY_HERE"
```

**Cell 3** — start the Cloudflare tunnel.
After a few seconds you will see a URL like:
```
★ Use this as COLAB_WS_URL on the kiosk:
  wss://abcd-efgh-1234.trycloudflare.com/bridge
```
**Copy this URL. It changes every Colab session.**

**Cell 4** — start the server. When you see `Server ready`, continue.

---

## Step 3 — Launch on the kiosk

Open a terminal and type (replace with your own values):

```bash
export RELAY_KEY="your-key-from-step-1"
export COLAB_WS_URL="wss://abcd-efgh-1234.trycloudflare.com/bridge"
chmod +x launch_zero_trust.sh
./launch_zero_trust.sh
```

Firefox opens automatically. You are ready.

---

## How do I know it's working?

After Firefox opens, visit any website.
If you see lines like these in the terminal, everything is working:

```
[INFO] Handshake complete — X25519 ✓ | epoch=... | HMAC ✓
[INFO] Tunnel active
[INFO] CONNECT → example.com:443
```

If the tunnel is **not** running, Firefox will show a connection error
and a blank page — this is intentional. No tunnel = no internet.

---

## When you are done

Close the terminal window where `launch_zero_trust.sh` is running
(or press Ctrl+C).

The system automatically:
- Stops the relay
- Overwrites all temporary files 3 times (shred) and deletes them
- Scrubs keys from memory
- Deletes the RAM profile

**No trace remains on the kiosk.**

---

## Frequently asked questions

**Q: What happens if I close Colab?**
Firefox will show a connection error. To reconnect, restart Colab and
repeat Step 2 (you will get a new URL).

**Q: How often should I change the key?**
Colab sessions reset approximately every 12 hours. Using a fresh key
per session provides sufficient security in practice.

**Q: I got "RELAY_KEY too short".**
The key must be at least 64 hexadecimal characters (0-9, a-f).
Re-run the command in Step 1.

**Q: Firefox opened but no sites load.**
First check that the server is running in Colab (`Server ready` visible).
Then verify you copied the URL correctly.

**Q: How secure is this?**
Each session uses a unique encryption key derived via X25519 Diffie-Hellman.
Even if the shared key is stolen, past sessions cannot be decrypted
(Forward Secrecy). Nothing is written to disk on the kiosk. If the tunnel
fails, Firefox cannot reach the internet at all.
