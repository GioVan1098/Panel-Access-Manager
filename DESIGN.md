# PAM — Design Notes & Technical Rationale

This document covers the engineering decisions behind PAM: why each component was designed the way it was, what alternatives were considered, and what the trade-offs are. It is intended for engineers evaluating, auditing, or extending the system.

For the complete specification (flows, component specs, verification plan) see `PAM_Architecture.md`.

---

## Origin and motivation

PAM evolved from **rofi-bridge** (SVA), a plain HTTP daemon using a static Bearer token to forward rofi launcher commands from an Android app to a Linux desktop. That design was intentionally minimal — it worked on a trusted home LAN where the threat model was negligible.

The need for PAM arose when the scope expanded to include **privileged commands**: opening firewall ports, controlling systemd units, managing power state. A static token over HTTP is not an acceptable authenticator for operations that affect system security posture.

The starting point was a structured analysis of rofi-bridge's 20 security problems, ranging from plain HTTP transport to token storage in a world-readable config file. PAM addresses all of them.

---

## Why not existing solutions?

| Alternative | Why rejected |
|---|---|
| **SSH + phone app** | Works, but requires key management per device, no revocation UI, no audit, hard to restrict to a command whitelist |
| **Tailscale + SSH** | Third-party dependency for the overlay network; Tailscale controls the CA; not self-hosted |
| **Home Assistant** | Web framework overhead, YAML-configured automations, not designed for OS-level privileged commands |
| **Tasker + plain HTTP** | No transport security, no mutual auth, same problems as rofi-bridge |

PAM is ~1200 lines of Python and C, fully self-hosted, with an explicit security model and no external dependencies beyond the standard library.

---

## Security model

### Layer 1 — TLS 1.3

The daemon uses Python's `ssl` module with an explicit context:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version     = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4')
ctx.options            |= ssl.OP_NO_COMPRESSION | ssl.OP_SINGLE_ECDH_USE
```

Compression is disabled (CRIME). Only ECDHE ciphers — forward secrecy on every session.

### Layer 2 — mTLS (mutual TLS)

The server uses `ssl.CERT_OPTIONAL` at the socket level, enforced manually per endpoint:
- `/provision` — no client cert required (TOFU bootstrap, OTP-gated)
- `/run`, `/audit` — client cert required, checked against `clients/<device_id>/tls.crt`

This avoids a hard dependency on client cert presence at the SSL handshake level while still enforcing it for privileged endpoints.

Client certificates are signed by a local CA whose private key is **never read by the daemon**. The CA key is encrypted (PKCS#8, AES-256) and lives offline in `~/rofi-bridge-ca/ca.key.enc`. It is only decrypted interactively when provisioning a new device, then immediately re-encrypted and the plaintext shredded.

### Layer 3 — Ed25519 command signing

Every command request is signed with an Ed25519 key generated and stored in the **Android Keystore** (hardware-backed, non-exportable). The canonical payload is:

```
"<command>|<unix_timestamp>|<nonce_hex>"
```

The server stores only the corresponding public key (`clients/<device_id>/sign.pub`). A server compromise gives the attacker public keys only — no forging capability.

**Why Ed25519 over HMAC-SHA256?**
HMAC requires a shared secret. If the server stores the HMAC key, a server compromise allows an attacker to forge arbitrary commands. Ed25519 is asymmetric: the server verifies but cannot sign. This is the core design decision that distinguishes PAM from a HMAC-based system.

**Why Ed25519 over RSA/ECDSA?**
Ed25519 is available in Android Keystore from API 31 (Android 12). It is faster, produces smaller signatures (64 bytes vs ~70–72 for ECDSA P-256), and has a simpler, less footgun-prone API. The `KeyGenParameterSpec` builder for Ed25519 does not require curve selection — there is only one curve.

### Layer 4 — Replay protection

Two independent checks:

1. **Timestamp** — payload must be within ±30 seconds of server time. Requires NTP synchronisation on both sides (`setup.sh` verifies this).

2. **Nonce** — 32-byte random hex, stored in SQLite (`nonces.db`) with a UNIQUE constraint on the nonce column. An `INSERT` failure on `IntegrityError` means replay. Nonces are purged after their TTL window (5 minutes).

**Why SQLite and not in-memory LRU?**
An in-memory cache is cleared on daemon restart. An attacker who can sniff a valid packet and trigger a daemon restart (e.g. via `systemctl restart` or a power cycle) gets a ±30s replay window. SQLite survives restarts. The performance cost is one `INSERT` + one periodic `DELETE WHERE expires < now()` per request.

### Layer 5 — Privilege isolation

`ipt-helper` is a C binary (~90 lines) with `cap_net_admin+eip` applied via `setcap`. It accepts exactly three string arguments (`open` / `close` / `check`), reads the port from `config.toml`, and calls `execv("/usr/sbin/iptables", av)` — no shell, no `system()`, no argument constructed from user input.

```
sudo install -m 755 ipt-helper /usr/lib/rofi-bridge/ipt-helper
sudo setcap cap_net_admin+eip /usr/lib/rofi-bridge/ipt-helper
```

**Why setcap and not sudoers?**
A sudoers `NOPASSWD` entry is a permanent privilege grant tied to the user account. `cap_net_admin` is tied to the binary inode and is dropped after `execv`. If the binary is deleted and replaced, the capability is gone. `pam-setcap.service` (a systemd oneshot at boot) re-applies it after system package updates.

**Why not `CAP_NET_BIND_SERVICE` on the Python interpreter?**
`cap_net_bind_service` on `/usr/bin/python3` would grant that privilege to every Python script on the system. `setcap` on a minimal C binary limits the blast radius to exactly the operation needed.

### Layer 6 — Audit log

Each completed request appends a line to `audit.log` in the format:

```
{"ts": "...", "device_id": "...", "command": "...", "result": "..."}|<base64_ed25519_sig>
```

The signature after `|` is an Ed25519 signature over the JSON portion, produced with `audit_sign.key` (private, chmod 400). The corresponding `audit_sign.pub` (public, chmod 444) can be distributed to any party who needs to verify log integrity — without granting them the ability to forge entries.

**Why asymmetric over HMAC-SHA256:**
HMAC requires sharing the signing key with anyone who needs to verify. On a compromised server, the HMAC key is available to the attacker, who can forge any log entry. With Ed25519, the server holds `audit_sign.key` for signing; verification uses only `audit_sign.pub`. A server compromise gives the attacker the ability to sign future entries but does not enable retroactive forgery of entries already committed — and the public key can be held independently by a monitoring party. The `hmac` module is not imported in the daemon code at all.

---

## Provisioning design

The provisioning flow solves a bootstrap problem: the Android app needs to trust the server's TLS certificate before it has the CA cert, and the server needs the app's Ed25519 public key before it can trust any signed command.

```
PC GUI → generates 128-bit OTP (60s TTL, one-time use)
       → computes SHA-256 fingerprint of server.crt
       → writes QR: { "addr": "ip:port", "otp": "hex", "fp": "hex" }

Android → scans QR
         → generates Ed25519 keypair in Keystore
         → connects with TOFU: verifies SHA-256(server.der) == fp from QR
         → POST /provision { otp, ed25519_public_key_b64 }

Server  → verifies OTP (valid, unexpired, unused)
         → generates client TLS cert signed with local CA
         → responds: { ca_cert, client_tls_cert, client_tls_key }
         → saves { tls.crt, sign.pub } in clients/<device_id>/
         → invalidates OTP

Android → stores { ca_cert, tls_cert, tls_key } in flutter_secure_storage
         → future connections: mTLS + Ed25519 (no more TOFU)
```

The OTP in the QR is one-time and 60-second TTL. The server cert fingerprint in the QR is the TOFU anchor — it prevents a MITM from intercepting the provisioning and installing a rogue CA. After provisioning, the app uses a private `SecurityContext(withTrustedRoots: false)` that only trusts the local CA — not the Android system trust store.

The CA passphrase is typed by the user in the GUI at provisioning time. It is written transiently into `pending_otps.json` (chmod 600) alongside the OTP entry, read once by the daemon to decrypt the CA key for cert signing, then the entire OTP entry is deleted. The daemon never holds the CA key in memory beyond the single signing operation.

---

## PAM-hardened: WireGuard relay

PAM-hardened addresses the case where the PC and Android are on different networks, or on the same network with AP isolation (common in enterprise WiFi, hotels, mobile hotspots).

```
Android (10.0.0.3)
   │ WireGuard UDP/51820
   ▼
VPS (10.0.0.1) — pure routing hub, no daemon
   │ WireGuard tunnel, forward to PC peer
   ▼
PC (10.0.0.2) — daemon bound to 10.0.0.2:7443
```

The VPS is a dumb relay. It forwards WireGuard UDP packets between peers and nothing else. It never sees plaintext — the TLS connection is end-to-end between Android and PC. Compromising the VPS gives an attacker encrypted WireGuard traffic only.

The daemon binds to the PC's wg0 interface IP (`10.0.0.2`) rather than the LAN IP. The server cert SAN is `IP:10.0.0.2`. This means the cert is useless outside the WireGuard tunnel.

**Per-peer pre-shared key (PSK)**: `relay-setup.sh` generates a 256-bit PSK per peer (`wg genpsk`) and adds a `PresharedKey` line to each `[Peer]` block in `wg0.conf`. The PSK is mixed into the Noise_IKpsk2 handshake as an additional symmetric secret. If the static Curve25519 keys are ever broken (e.g., by a quantum adversary), the PSK provides a second layer: an attacker must obtain both the long-term private key AND the PSK to decrypt session traffic. The PSK does not affect tunnel performance — it is consumed during the handshake, not per-packet.

**Why not a VPN to home router instead?**
A router-based VPN (OpenVPN, WireGuard on router) gives the phone full LAN access. PAM-hardened gives the phone access only to `10.0.0.2:7443` — the single PAM port. Even within the WireGuard tunnel, all six authentication layers still apply.

**Flutter fallback (C3 fix):** if the VPS is offline, the app retries on the stored LAN IP with a 5-second timeout. This ensures PAM-hardened degrades gracefully to direct LAN when the relay is unreachable.

---

## Android client hardening

Beyond the cryptographic protocol layers, the Android app implements three independent security measures that address physical access and device integrity scenarios.

### Screen protection — FLAG_SECURE

`WindowManager.LayoutParams.FLAG_SECURE` is set in `MainActivity.onCreate()`:

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
```

This is the same mechanism used by banking apps, Netflix, and Disney+. The flag instructs SurfaceFlinger (Android's graphics compositor) to mark the Activity's layer as protected content. The Hardware Composer handles the buffer directly without going through any software capture path. Practical effects: all screenshots return a black image, screen recording captures black frames, screen sharing (Google Meet, Teams) shows a black rectangle, recent apps thumbnails are black.

Netflix adds Widevine L1 DRM on top (for encrypted video bytes in the decoder pipeline); that is specific to DRM content and not relevant for PAM. FLAG\_SECURE alone is the correct and sufficient mechanism for PAM's purpose.

The flag is applied at the Activity level, covering all screens (home, provisioning, settings). This avoids gaps that could arise from applying protection only to specific screens and leaving transitions unprotected.

### Biometric authentication gate — two modes

The app supports two biometric modes, selected once at provisioning time. The choice is baked into the Android Keystore key flags and stored in `flutter_secure_storage` as `security_mode`.

#### Soft-gate (standard mode)

The key is generated without auth requirements. `BiometricPrompt` gates the `sign()` call at the application level — if authentication succeeds, the app calls `sign()`; if cancelled, it does not. This is an application-level check in the app process, not a TEE-level lock.

Authenticators: `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`. Can be toggled in Settings at any time without re-provisioning. Correct for the primary threat model (unauthorized access on an unlocked phone on a non-rooted device).

#### Hard-gate (hardened mode)

The key is generated with `setUserAuthenticationRequired(true)`, `setUserAuthenticationValidityDurationSeconds(-1)` (per-use, not time-window), and `setInvalidatedByBiometricEnrollment(true)`. Signing is done via `CryptoObject`: a `Signature` object initialized with the private key is passed into `BiometricPrompt.authenticate()`. The TEE performs the actual signing inside `onAuthenticationSucceeded()` via `authResult.cryptoObject!!.signature!!`. The key physically cannot sign without a fresh biometric match inside the secure element.

Only `BIOMETRIC_STRONG` is accepted — Android API prohibits `DEVICE_CREDENTIAL` with `CryptoObject`. Cannot be toggled at runtime. Changing mode requires deleting the existing key and re-provisioning with the new flags. If the user adds or removes biometric enrollment, the key is invalidated.

**Security mode selection at provisioning:**

A modal dialog (non-dismissible) is shown before key generation. The choice is stored and reflected in the Settings screen as a read-only tile. The deprovision flow (`deleteKey(deviceId)` before `clearAll()`) ensures the key alias is available for deletion before `flutter_secure_storage` is wiped.

**Async MethodChannel result:**

BiometricPrompt callbacks are asynchronous. For soft-gate: `pendingSignResult`, `pendingSignAlias`, `pendingSignData`. For hard-gate: `pendingHardGateResult`, `pendingHardGateData`. Both completed in `onAuthenticationSucceeded()`. The `return@setMethodCallHandler` guard prevents the outer try-catch from resolving the Result prematurely. `BIOMETRIC_CANCELLED` is handled silently on the Dart side.

### Wake-on-LAN

When enabled (Settings toggle + MAC address, or pre-configured by `setup.sh --wol`), the app sends a 102-byte UDP magic packet (6×0xFF + target MAC×16, port 9) before each command and waits 3 seconds. PAM direct uses broadcast `255.255.255.255`; PAM-hardened uses unicast to `10.0.0.2` through the WireGuard tunnel.

This addresses the PC-sleep scenario: commands sent to a sleeping PC silently fail because the WireGuard tunnel is down. WoL wakes the PC from light sleep before the command arrives. For deep sleep (S5) over PAM-hardened, the tunnel NIC is offline and cannot receive the routed unicast — BIOS-level WoL on the LAN interface is required in that case.

### Device integrity check

At provisioning time, the app calls `checkDeviceIntegrity()` before proceeding, to inform the user of the device's security posture. The check uses Android Keystore APIs entirely — no network, no Google Play Services.

**Why Keystore Attestation over Play Integrity API:**

| | Keystore (PAM approach) | Play Integrity API |
|---|---|---|
| Requires Google Play Services | No | Yes |
| Requires internet | No | Yes |
| Trust anchor | Hardware TEE / Google device CA | Google infrastructure |
| Works on de-Googled ROMs | Yes | No |
| Works offline | Yes | No |

The Play Integrity API requires a Google account infrastructure call for every check. PAM is designed to be self-hosted with no external dependencies. An integrity check that requires phoning home to Google at every provisioning contradicts this principle.

**Implementation — what is checked:**

```kotlin
// 1. Probe TEE security level via a temp P-256 key and KeyInfo
val kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore")
kpg.initialize(KeyGenParameterSpec.Builder(tempAlias, PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(DIGEST_SHA256).build())
val keyPair = kpg.generateKeyPair()
val keyInfo = KeyFactory.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore")
    .getKeySpec(keyPair.private, KeyInfo::class.java)
// keyInfo.securityLevel: STRONG_BOX | TRUSTED_ENVIRONMENT | SOFTWARE

// 2. Probe StrongBox separately (try generation with setIsStrongBoxBacked(true))

// 3. Check build tags
val isTestKeys = Build.TAGS.contains("test-keys")
```

A temporary key is generated only for the probe and immediately deleted. The check adds no persistent state.

**Warning levels:**

- `NONE`: TEE or StrongBox present, no test-keys. No action.
- `MEDIUM`: test-keys build (possible unofficial firmware). TEE still present. Warning dialog with Continue / Cancel.
- `HIGH`: `securityLevel == SOFTWARE` (no TEE). The core security assumption of PAM — hardware-backed non-exportable signing key — is not met. Warning dialog with Proceed anyway / Cancel.

The approach is non-blocking: an informed user (e.g., one who uses Magisk deliberately) can choose to continue.

**Full hardware attestation (L-A):**

Full Android Key Attestation is implemented as an optional layer on top of `checkDeviceIntegrity()`. It triggers automatically at first provisioning whenever a new key must be generated:

1. Before key generation, the app fetches a one-time challenge via GET `/provision/challenge`. The server generates a 32-byte random nonce (TTL 120 seconds, one-time use), returns it base64-encoded, and stores it in a thread-safe in-memory map with expiry.
2. The nonce is passed to `KeyGenParameterSpec.Builder.setAttestationChallenge(nonce)` at Ed25519 key generation. Android embeds the raw nonce inside the leaf certificate of the resulting attestation chain. The chain is retrieved via `KeyStore.getCertificateChain(alias)`, leaf first.
3. The PEM-encoded certificate chain and the original base64 challenge are sent alongside the Ed25519 public key in POST `/provision` as `attestation_chain` and `attestation_challenge`.
4. The server calls `attestation.py: verify_attestation()`. The function verifies each certificate signature in the chain (leaf → root), then checks that the root fingerprint matches a trusted anchor from `attestation_roots.pem` — the Google Hardware Attestation Root CA bundle (two roots: RSA-4096 valid 2022–2042 and EC P-384 "Key Attestation CA1" valid 2025–2035). No external ASN.1 library is required — a custom DER TLV parser (BER/DER-compliant, handles long-form tags such as rootOfTrust tag 704 = `BF 85 40`) operates on the raw extension bytes.
5. The `KeyDescription` extension (OID `1.3.6.1.4.1.11129.2.1.17`) is parsed positionally: `attestationSecurityLevel` at index 1, `attestationChallenge` (OCTET STRING) at index 4 is compared against the server-issued nonce to confirm the key was generated specifically for this provisioning session, and `teeEnforced[7] → rootOfTrust[704]` yields `verifiedBootState` and `deviceLocked`.
6. Policy is configurable in `config.toml` under `[attestation]`: `require_hardware_backed` (default `true`), `reject_unverified_boot` (default `true`), `require_verified_boot` (default `false`), `require_device_locked` (default `false`).

Attestation is **best-effort and non-blocking by default**: if the challenge fetch fails, the app silently falls back to standard key generation and provisioning proceeds without attestation. Re-provisioning with an existing key of the same security mode skips attestation entirely — a key generated without an embedded challenge cannot be attested retroactively. The server ships with `enabled = false`; attestation results are recorded in the audit log entry for the provisioning event, but do not reject provisioning unless the operator enables enforcement in `config.toml`.

---

## Android Keystore: implementation notes

Ed25519 in the Android Keystore requires API 31+. The implementation:

```kotlin
val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build()
// Attempt StrongBox (dedicated secure enclave), fall back to TEE
try {
    kpg.initialize(spec.withStrongBox()); kpg.generateKeyPair()
} catch (e: StrongBoxUnavailableException) {
    kpg.initialize(spec); kpg.generateKeyPair()
}
```

The private key never leaves the Keystore. Signing is performed inside the secure element: the Dart layer sends the canonical payload string over a `MethodChannel`, the Kotlin layer signs it and returns the Base64 signature.

The public key is exported as DER-encoded X.509 SubjectPublicKeyInfo, wrapped in PEM (`BEGIN PUBLIC KEY` / `END PUBLIC KEY`). Python's `cryptography` library reads it with `load_pem_public_key()` and verifies with `pub.verify(sig_bytes, payload_bytes)`.

Android Keystore keys are not included in Android backups. `android:allowBackup="false"` in `AndroidManifest.xml` additionally excludes all app data (including `flutter_secure_storage` TLS keys) from cloud and local backups. Phone loss means re-provisioning (generate new keypair, new client cert). The lost device is revoked from the GUI (`clients/<device_id>/` deleted, serial appended to `revoked.txt`), and the daemon restarted. Re-provisioning takes under two minutes.

**Deprovision order**: when deprovisioning from Settings, `deleteKey(deviceId)` must be called before `_storage.clearAll()`. The `device_id` (used as the Keystore key alias) is stored in `flutter_secure_storage`; calling `clearAll()` first would wipe the alias, making the Keystore key orphaned and uncleanable.

---

## Known limitations

| # | Limitation | Impact | Mitigation |
|---|---|---|---|
| R3 | ~~Android backup TLS key recovery~~ | ~~Resolved~~ | `android:allowBackup="false"` — app excluded from all backups (L-B, v3.2) |
| R7 | NTP drift or misconfigured clock | Timestamp validation fails, legitimate requests rejected | `setup.sh` checks for active timesyncd/chronyd |
| R8 | PC sleep breaks WireGuard keepalive | Commands to sleeping PC silently fail | Wake-on-LAN now implemented (L-E, v3.2): magic packet sent before each command; deep sleep over WG tunnel still unsolved |
| R9 | Ed25519 keys non-exportable from Keystore | Phone loss requires re-provisioning | Revoke from GUI, re-provision in ~2 minutes |
| R10 | Physical server compromise | Attacker gets `server.key`, `ca.crt`, client public keys | Forward secrecy protects past traffic; CA offline limits damage |
| R11 | TEE-less device (securityLevel = SOFTWARE) | Ed25519 key stored in process memory, extractable with root | `checkDeviceIntegrity()` warns at provisioning; user can abort; five other layers remain intact |

None of these are considered blocking for the target use case (single trusted device, home/office network, known physical environment).

---

## Stack summary

| Component | Technology | Rationale |
|---|---|---|
| Daemon | Python 3, stdlib `ssl` + `http.server` | No framework overhead; full control over TLS context and mTLS enforcement |
| GUI | C + GTK3 | Native, minimal dependencies; consistent with existing rofi-bridge GUI |
| Android app | Flutter + Dart | Cross-platform baseline; single codebase if iOS support is added later |
| Keystore bridge | Kotlin MethodChannel | Direct AndroidKeyStore access; no third-party crypto library |
| Privilege helper | C + setcap | Minimal binary; capability tied to inode, not user account |
| Nonce store | SQLite | Persistent across restarts; single-file, no daemon required |
| Audit signing | Ed25519 (`audit_sign.key`/`audit_sign.pub`) | Asymmetric: sign with private key, verify with public key independently |
| Key attestation | `attestation.py` + `attestation_roots.pem` | Custom DER TLV parser; `cryptography` library only (no pyasn1); Google Hardware Attestation Root CA bundle |
| CA | openssl CLI | Transparent, auditable; no custom PKI library |
| Overlay (hardened) | WireGuard (kernel) | ~4k LOC, formally verified Noise protocol, kernel-native performance |
