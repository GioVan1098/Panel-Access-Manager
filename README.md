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
6. **Audit log** — append-only, Ed25519 asymmetric signature per entry; verifiable with `audit_sign.pub` (server never needs to hold a forgeable key)

*PAM-hardened adds Layer 0: WireGuard — ChaCha20-Poly1305, Noise\_IKpsk2 protocol with per-peer pre-shared key (PSK).*

## Android client security

The Android app implements additional hardening measures independent of the network security layers:

| Feature | Mechanism | Effect |
|---|---|---|
| **Screen protection** | `FLAG_SECURE` (WindowManager) | Blocks screenshots, screen recording, screen sharing at the SurfaceFlinger compositor level — identical to the mechanism used by banking and streaming apps |
| **Biometric gate — soft-gate** | `BiometricPrompt` (BIOMETRIC\_STRONG \| DEVICE\_CREDENTIAL) | Optional per-command authentication confirmation; configurable in Settings at any time without re-provisioning; degrades gracefully based on device capability |
| **Biometric gate — hard-gate** | `BiometricPrompt` with `CryptoObject` (TEE-enforced) | Selected at provisioning time; key generated with `setUserAuthenticationRequired(true)` + `setInvalidatedByBiometricEnrollment(true)`; signing physically impossible without a fresh biometric match inside the TEE; only `BIOMETRIC_STRONG` accepted (no PIN fallback) |
| **Backup lockout** | `android:allowBackup="false"` in AndroidManifest | Prevents recovery of `flutter_secure_storage` TLS keys via Android cloud or local backup |
| **Wake-on-LAN** | UDP magic packet (port 9) sent before each command | Wakes PC from light sleep before the command arrives; configurable in Settings; PAM direct uses LAN broadcast, PAM-hardened uses WireGuard unicast to 10.0.0.2 |
| **Device integrity check** | Android Keystore `KeyInfo.securityLevel` + `Build.TAGS` | Detects absence of TEE / StrongBox and test-keys builds at provisioning time; warning dialog with user choice (non-blocking) |
| **Hardware key attestation** | Android Keystore `setAttestationChallenge()` + Google Hardware Attestation Root CA chain verification (`attestation.py`) | At provisioning, the server optionally verifies that the signing key was generated inside the device TEE or StrongBox and that the verified boot state is intact; best-effort — gracefully falls back if unavailable; configurable per deployment in `config.toml [attestation]` |

The security mode (soft-gate vs hard-gate) is chosen at first provisioning and is baked into the key flags; switching requires re-provisioning. The device integrity check does not use Google Play Integrity API — it operates entirely offline via the hardware Keystore. Key attestation is a separate, server-side verification using the Google Hardware Attestation Root CA bundle.

---

## Repository structure

```
PAM_Architecture.md      full security design document (v3.4, 20 sections + 8.6/8.7/18.6–18.10)
pam-daemon/
  bridge_v2.py           HTTPS daemon (mTLS, Ed25519 verify, SQLite nonces, Ed25519 audit, attestation)
  ipt-helper.c           C privilege helper (setcap cap_net_admin, execv iptables)
  setup.sh               installer: CA, certs, audit keys, ipt-helper, systemd services [--wol]
  relay-setup.sh         VPS-side WireGuard setup with PSK generation (PAM-hardened only)
  attestation.py         Android Key Attestation chain verifier (DER TLV parser, policy engine)
  attestation_roots.pem  Google Hardware Attestation Root CA bundle (RSA-4096 + EC P-384)
  gui/
    main.c               GTK3 GUI entry point
    gui_gtk.c/h          4-tab notebook: Status, Provision, Devices, Audit Log
    sys.c/h              system helpers (config, OTP, device list, audit read)
    qr.c/h               libqrencode wrapper for provisioning QR
    Makefile
pam_app/                 Flutter Android app
  lib/
    screens/             Home (commands + WoL), Provisioning (QR scan + security mode), Settings
    services/            mTLS HTTP, Ed25519 Keystore, crypto (soft+hard-gate), storage, WoL
    models/              PamCommand enum, PamConfig
  android/
    MainActivity.kt      Ed25519 Keystore MethodChannel (StrongBox → TEE fallback);
                         hard-gate CryptoObject; FLAG_SECURE; BiometricPrompt; integrity check
```

---

## Quick start

```bash
# 1. Build and install the GUI
cd pam-daemon/gui && make && make install

# 2. Run setup (generates CA, server cert, audit keys, installs ipt-helper with setcap)
#    Add --wol to also detect LAN MAC and enable Wake-on-LAN support
cd pam-daemon && bash setup.sh          # basic
# cd pam-daemon && bash setup.sh --wol  # with Wake-on-LAN

# 3. Start the daemon
systemctl --user enable --now rofi-bridge

# 4. Open the GUI, go to Provision tab, generate OTP, scan QR from Android app
#    The app will ask you to choose security mode (standard / hardened) at first provisioning
pam-gui
```

For PAM-hardened (WireGuard relay):

```bash
# On the VPS — generates per-peer PSKs; save the output
bash relay-setup.sh

# On the PC — enter PC_PSK from relay-setup.sh output when prompted
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
