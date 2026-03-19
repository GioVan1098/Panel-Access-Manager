# PAM — Panel Access Manager

Secure remote-control daemon for Linux workstations, operated from an Android device.
Designed for privileged operations (iptables, systemctl, power management) with cryptographic mutual authentication and no shared secrets on the server.

---

## Variants

| Variant | Transport | Network |
|---|---|---|
| **PAM** | HTTPS direct | Trusted or cryptographically-untrusted LAN |
| **PAM-hardened** | HTTPS over WireGuard relay | Any network — public WiFi, AP isolation, mobile data |

Same daemon, same GUI, same app — only the transport layer differs.

---

## Security layers

1. **TLS 1.3** — ECDHE, AES-GCM / ChaCha20, forward secrecy
2. **mTLS** — client certificate signed by local CA; server refuses unknown devices
3. **Ed25519 command signing** — Android Keystore hardware-backed key, non-exportable
4. **Replay protection** — timestamp ±30s + one-time nonce (SQLite, survives daemon restart)
5. **Privilege isolation** — `ipt-helper` C binary with `cap_net_admin` setcap; zero sudoers
6. **Audit log** — append-only, HMAC-SHA256 per entry with server signing key

*PAM-hardened adds Layer 0: WireGuard — ChaCha20-Poly1305, Noise\_IKpsk2 protocol.*

---

## Repository structure

```
PAM_Architecture.md      full security design document (v3.0, 19 sections)
pam-daemon/
  bridge_v2.py           HTTPS daemon (mTLS, Ed25519, SQLite nonces, HMAC audit)
  ipt-helper.c           C privilege helper (setcap cap_net_admin, execv iptables)
  setup.sh               installer: CA, certs, ipt-helper, systemd services
  relay-setup.sh         VPS-side WireGuard setup (PAM-hardened only)
  gui/
    main.c               GTK3 GUI entry point
    gui_gtk.c/h          4-tab notebook: Status, Provision, Devices, Audit Log
    sys.c/h              system helpers (config, OTP, device list, audit read)
    qr.c/h               libqrencode wrapper for provisioning QR
    Makefile
pam_app/                 Flutter Android app
  lib/
    screens/             Home (commands), Provisioning (QR scan), Settings
    services/            mTLS HTTP, Ed25519 Keystore, crypto, storage
    models/              PamCommand enum, PamConfig
  android/
    MainActivity.kt      Ed25519 Keystore MethodChannel (StrongBox → TEE fallback)
```

---

## Quick start

```bash
# 1. Build and install the GUI
cd pam-daemon/gui && make && make install

# 2. Run setup (generates CA, server cert, installs ipt-helper with setcap)
cd pam-daemon && bash setup.sh

# 3. Start the daemon
systemctl --user enable --now rofi-bridge

# 4. Open the GUI, go to Provision tab, generate OTP, scan QR from Android app
pam-gui
```

For PAM-hardened (WireGuard relay):

```bash
# On the VPS
bash relay-setup.sh

# On the PC
bash setup.sh --hardened
```

---

## Requirements

**Server (PC)**
`python3` · `openssl` · `gcc` · `libgtk-3` · `libqrencode` (optional, for QR) · `wireguard-tools` (hardened only)

**Android**
API 31+ (Android 12) · hardware-backed Keystore (TEE or StrongBox)

---

## Full documentation

See `PAM_Architecture.md` for the complete security design, threat model, cryptographic choices, and deployment details.
