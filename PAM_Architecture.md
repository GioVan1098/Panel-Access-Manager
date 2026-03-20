# PAM — Panel Access Manager
## Technical Architecture & Security Design Document

**Version**: 3.1 (Android Client Security Hardening)
**Date**: 2026-03-20
**Status**: Architecture finalized — implementation complete
**Origin project**: rofi-bridge (SVA) → evolved into PAM

**Changelog v3.1**: Added Section 20 — Android Client Security Hardening. Three measures implemented: FLAG_SECURE (screen protection), BiometricPrompt soft-gate (optional per-command authentication), device integrity check via Keystore KeyInfo.securityLevel + Build.TAGS (non-blocking, warning levels NONE/MEDIUM/HIGH). Updated Known Limitations (Section 12) with R11 (TEE-less device). Implementation complete, commit 636b0e7.

**Changelog v3.0**: Fixed logical error in WireGuard topology (daemon endpoint is PC wg0 IP 10.0.0.2, not VPS 10.0.0.1). Added nonce cache persistence (SQLite, C1). Added setcap systemd guard (C2). Added Flutter fallback logic hardened→LAN (C3). Added NTP prerequisite (C4). Added PC sleep, client key loss, port conflict residual risks (C5/C6/C7). Added Section 18 (Implementation Pitfalls) and Section 19 (Comparison with existing solutions).

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Origin & Context](#2-origin--context)
3. [rofi-bridge v1 — Baseline Analysis](#3-rofi-bridge-v1--baseline-analysis)
4. [Threat Model](#4-threat-model)
5. [Security Analysis — All 20 Problems](#5-security-analysis--all-20-problems)
6. [Design Evolution — Two Models Compared](#6-design-evolution--two-models-compared)
7. [Final Architecture — Model 2 (Full Asymmetric)](#7-final-architecture--model-2-full-asymmetric)
8. [All Operational Flows](#8-all-operational-flows)
9. [Component Specifications](#9-component-specifications)
10. [Cryptographic Choices — Rationale](#10-cryptographic-choices--rationale)
11. [Key & Secret Storage Model](#11-key--secret-storage-model)
12. [Accepted Residual Risks](#12-accepted-residual-risks)
13. [Verification Plan](#13-verification-plan)
14. [Deployment Variants — PAM vs PAM-hardened](#14-deployment-variants--pam-vs-pam-hardened)
15. [Network Threat Categories](#15-network-threat-categories)
16. [PAM-hardened Architecture — WireGuard Relay](#16-pam-hardened-architecture--wireguard-relay)
17. [Untrusted Network Mitigations](#17-untrusted-network-mitigations)
18. [Implementation Notes — Critical Pitfalls](#18-implementation-notes--critical-pitfalls)
19. [Comparison with Existing Solutions](#19-comparison-with-existing-solutions)
20. [Android Client Security Hardening](#20-android-client-security-hardening)

---

## 1. Project Overview

**PAM (Panel Access Manager)** is a secure remote-control daemon for Linux workstations, designed to allow a trusted Android device to execute privileged commands (including sudo-capable operations) on the host machine. PAM is published in two deployment variants: **PAM** (direct LAN connection) and **PAM-hardened** (WireGuard relay for untrusted or open networks).

### Core Requirements

| Requirement | Description |
|---|---|
| **Remote control** | Android app sends commands; daemon executes them on the PC |
| **Privileged operations** | Some commands require elevated privileges (iptables, systemctl) |
| **Encrypted transport** | All traffic must be encrypted — sudo commands cannot traverse plain HTTP |
| **Mutual authentication** | Both server and client must prove identity cryptographically |
| **Zero shared secrets on server** | A server compromise must not give the attacker forging capability |
| **Hardware-backed client keys** | Client private key must not be extractable, even on a rooted device |
| **Network agnostic (hardened)** | PAM-hardened must function on any network including public WiFi with AP isolation |

### Deployment Variants

| Variant | Transport | Network | Bind address | Server SAN |
|---|---|---|---|---|
| **PAM** | HTTPS direct | Trusted LAN or cryptographically untrusted LAN | `<LAN_IP>:7443` | `IP:<LAN_IP>, DNS:hostname.local` |
| **PAM-hardened** | HTTPS over WireGuard tunnel | Any network — exposed, attacked, open public WiFi | `10.0.0.2:7443` (wg0 PC) | `IP:10.0.0.2` |

**Note**: the daemon code (`bridge_v2.py`), the GTK GUI, and the Flutter app are **identical** across variants. The only differences are the WireGuard tunnel layer and the IP binding.

### Technology Stack

| Layer | Technology |
|---|---|
| **Daemon** | Python 3 — `http.server` + `ssl` (native, no external web framework) |
| **Android app** | Flutter (Dart) |
| **Local GUI manager** | C + GTK3 (compiled, `gui_gtk.c`) |
| **Privilege helper** | C binary (`ipt-helper`) with `setcap cap_net_admin` |
| **Crypto library (server)** | Python `ssl` module + `cryptography` (PyCA) |
| **Crypto library (client)** | Android Keystore API (hardware-backed) + Dart `cryptography` |
| **Certificate infrastructure** | OpenSSL (setup only), self-signed CA |
| **VPN tunnel (hardened)** | WireGuard (Linux kernel module + wireguard-tools) |
| **Relay (hardened)** | Oracle Cloud Free Tier — ARM Ampere A1 (4 OCPU, 24GB RAM) |

---

## 2. Origin & Context

PAM evolved from **rofi-bridge**, a simple LAN remote launcher that allowed an Android phone (Samsung S24 Ultra) to trigger items from a Rofi nested menu on an Arch Linux workstation over HTTP.

### rofi-bridge Original Purpose

- Start applications, scripts, or system commands from the Android phone
- Operate as a systemd user service with mDNS (zeroconf) discovery
- Use a Bearer token stored in `config.toml` for auth
- Run commands via `sh -c` using entries from `~/.config/rofi-menu/config.json`

### Why PAM Was Necessary

The requirement to add privileged operations (firewall management, daemon control) to the remote panel raised an immediate security concern: **sudo-capable commands cannot be sent over plain HTTP**. Even on a trusted LAN, the traffic is visible to any device on the same WiFi segment (no AP isolation required for ARP spoofing). A motivated attacker with access to the same network could:

- Intercept the Bearer token via passive sniffing
- Use the captured token to trigger commands indefinitely
- With elevated commands in scope: open firewall holes, stop daemons, escalate privileges

This triggered a complete security redesign rather than incremental patching.

### Why a Hardened Variant Was Added

After the LAN-only design was finalized, the question arose: what if the network itself cannot be trusted? Home networks can be assumed cooperative, but many real scenarios involve networks where other devices are potentially hostile, where the infrastructure (router, switch, AP) may be compromised or misconfigured, or where open public WiFi with AP isolation is the only available connectivity. The answer was PAM-hardened: a WireGuard overlay tunnel through a personal relay, making the underlying network irrelevant to the security model.

---

## 3. rofi-bridge v1 — Baseline Analysis

### Architecture

```
Android (Flutter) ──[HTTP :7070, plain]──► Python daemon (bridge.py)
                                              │
                                              └── subprocess: sh -c <menu_command>
```

### Authentication

```python
def auth_ok(self):
    return self.headers.get("Authorization", "") == f"Bearer {TOKEN}"
```

Simple string equality comparison. Token stored in plaintext `~/.config/rofi-bridge/config.toml`.

### Key Limitations

| Issue | Impact |
|---|---|
| Plain HTTP | All traffic visible to LAN sniffers |
| Bearer token in plaintext TOML | Token exposed if file is read |
| `==` comparison | Timing attack on token |
| `sh -c` execution | Command injection vector if input is not fully controlled |
| Token never expires | Captured token gives permanent access |
| No audit log | No visibility into command history |
| Bind: 0.0.0.0 | Exposed on all network interfaces |
| mDNS announces service | Reveals daemon presence to all LAN devices |

---

## 4. Threat Model

### Assets to Protect

1. **Command execution integrity** — only the authorized phone can trigger commands
2. **Privilege non-escalation** — network access must not grant more than specific whitelisted privileges
3. **Traffic confidentiality** — commands, responses, and auth material must not be readable in transit
4. **Client key confidentiality** — even if the server is fully compromised, the client must not be impersonatable
5. **Network-layer isolation (hardened)** — on untrusted networks, the underlying IP layer must not carry readable data

### Network Threat Categories

| Category | Description | Example |
|---|---|---|
| **Trusted LAN** | Home network under full infrastructure control | Home router with known devices, no guest access |
| **Untrusted/Exposed LAN** | Network with other devices of unknown trust, potential for ARP spoofing, MITM, or active scanning | Corporate WiFi, shared apartment network, any network with unknown participants |
| **Open public network** | No encryption at WiFi layer, AP isolation typically enabled (devices cannot reach each other), infrastructure fully untrusted | Public WiFi hotspots, coffee shops, airports, hotel networks |

### Attacker Profiles

| Attacker | Capability | Goal |
|---|---|---|
| **LAN passive** | tcpdump on same WiFi | Capture token/commands |
| **LAN active** | ARP spoofing, MITM | Intercept/modify traffic |
| **Server compromise** | Read all files in `~/.config/rofi-bridge/` | Steal credentials, forge requests |
| **Device compromise** | Root the Android phone | Extract signing keys |
| **Physical** | Physical access to PC | Access disk, read key files |
| **Open network / AP isolation** | Device on same open WiFi but AP-isolated; cannot reach other devices directly | Cannot connect to daemon at all (no direct IP path) — solved only by PAM-hardened |
| **Network infrastructure** | Compromised router, rogue DHCP, DNS spoofing | Redirect connections, intercept unprotected traffic |
| **VPS relay (hardened)** | Full compromise of Oracle Free Tier relay VPS | Read relayed traffic — mitigated: WireGuard encrypts end-to-end, VPS sees only UDP ciphertext |

### Non-goals (Out of Scope)

- Protection against a fully compromised OS kernel on either end
- Formal cryptographic proof of security properties
- Resistance to a compromised WireGuard endpoint — if the VPS relay is owned and WireGuard keys extracted, the tunnel confidentiality is lost (risk accepted and documented in Section 12)

---

## 5. Security Analysis — All 20 Problems

---

### 5.1 — sudoers NOPASSWD with Wildcard

**Problem**

The initial design planned to add sudoers rules for iptables commands using wildcards:
```
giovanni ALL=(ALL) NOPASSWD: /usr/sbin/iptables -I INPUT *
```

The `*` in sudoers is not a regex — it matches any string, including strings with additional arguments. An attacker controlling the daemon input could inject:
- `iptables -I INPUT 1 -j ACCEPT` → accept all inbound traffic
- `iptables -I INPUT -m nfqueue --queue-num 0 -j NFQUEUE` → redirect packets to attacker-controlled process
- `iptables -F` → flush entire firewall ruleset

Even without intent, the wildcard transforms a narrow privilege grant into a broad attack surface.

**Solution**

A dedicated compiled C binary (`ipt-helper`) with `setcap cap_net_admin+eip` replaces sudoers entirely.

```c
int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    int port = read_port_from_config(); // reads config file, NOT argv
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (strcmp(argv[1], "open")  == 0)
        execv("/usr/sbin/iptables",
              (char*[]){"iptables","-I","INPUT","1","-p","tcp","--dport",port_str,"-j","ACCEPT",NULL});
    if (strcmp(argv[1], "close") == 0)
        execv("/usr/sbin/iptables",
              (char*[]){"iptables","-D","INPUT","-p","tcp","--dport",port_str,"-j","ACCEPT",NULL});
    if (strcmp(argv[1], "check") == 0)
        execv("/usr/sbin/iptables",
              (char*[]){"iptables","-C","INPUT","-p","tcp","--dport",port_str,"-j","ACCEPT",NULL});
    return 1;
}
```

```bash
sudo setcap cap_net_admin+eip /usr/lib/rofi-bridge/ipt-helper
```

**How It Works**

`setcap` assigns a specific Linux capability to a specific binary inode. `CAP_NET_ADMIN` permits network operations (iptables, interface management, routing) without root. The kernel verifies the binary by inode at execution time. The capability cannot be inherited by child processes started by the helper (because `execv` replaces the process image and the capability set is bounded). The helper accepts only three literal strings and reads the port from config — no argv injection is possible.

**Why This Choice**

`setcap` is the correct Unix model for granting specific privileges to specific programs. sudoers was designed for granting commands to users, not for whitelisting arguments — its wildcard semantics are documented as dangerous. With `setcap`: the privilege is in the binary, scoped to the binary, and disappears when the binary is removed. `setup.sh --uninstall` removes `ipt-helper` → zero privileged trace.

---

### 5.2 — Android 14+ Rejects User-Installed CA Certs in Apps

**Problem**

Since Android 7 (API 24), CA certificates installed by the user via "Settings → Security → Credentials" are **not trusted by apps** for network connections by default. This was Google's deliberate decision to prevent MITM via rogue CAs installed by malware or MDM profiles. Result: the Flutter app would fail with `CERTIFICATE_VERIFY_FAILED` even if the user correctly installed the CA.

**Solution**

Never install the CA in the Android system store. Instead, load it programmatically into a private `SecurityContext` in Dart:

```dart
final caCertPem = await secureStorage.read(key: 'ca_cert');
final context = SecurityContext(withTrustedRoots: false); // empty system CA store
context.setTrustedCertificatesBytes(utf8.encode(caCertPem!));

// mTLS: load client cert and key
final clientCert = await secureStorage.read(key: 'tls_cert');
final clientKey  = await secureStorage.read(key: 'tls_key');
context.useCertificateChainBytes(utf8.encode(clientCert!));
context.usePrivateKeyBytes(utf8.encode(clientKey!));

final client = HttpClient(context: context);
```

`withTrustedRoots: false` means the **only** trusted CA is ours. No system CAs, no user CAs — exclusively the daemon's CA.

**How It Works**

Dart/Flutter exposes the BoringSSL TLS library directly via `dart:io`. The `SecurityContext` is a completely separate trust store from the Android system store. The OS is not involved in certificate validation — the connection uses our private store. This also enables mTLS without Android-level configuration.

**Why This Choice**

Bypassing the Android system trust store is not a workaround — it is the correct model for applications managing their own PKI. This also solves problem 5.4 (CA as global trust) since the CA is never installed system-wide. The CA lives only in the app's `flutter_secure_storage` and is destroyed when the app is uninstalled.

---

### 5.3 — CA Private Key Co-Located with Server

**Problem**

If the CA private key (`ca.key`) is stored in `~/.config/rofi-bridge/` alongside the server key, a compromised machine gives an attacker both keys. With the CA key, they can issue fraudulent certificates signed by our CA and perform MITM attacks on the provisioned Android app — including impersonating other HTTPS services if the CA were installed system-wide (mitigated by problem 5.2).

**Solution**

The CA key is used only at cert generation time. After setup, it is encrypted and moved to a separate offline location:

```bash
# Generate CA key
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -out ca.crt -days 3650 -subj "/CN=rofi-bridge-CA"

# Encrypt and move offline
openssl pkcs8 -in ca.key -topk8 -out ~/rofi-bridge-ca/ca.key.enc \
    -passout pass:"$(openssl rand -base64 32)"
shred -u ca.key   # securely delete plaintext version
# ca.key.enc stored in ~/rofi-bridge-ca/ — NOT in ~/.config/rofi-bridge/
```

The daemon's operational directory (`~/.config/rofi-bridge/`) never contains `ca.key`. It contains only `server.key`, `server.crt`, `ca.crt`, and client public keys — none of which can issue new certificates.

**How It Works**

Separation of concerns: the CA key is a **signing secret** used infrequently (initial setup, device provisioning, cert rotation). The daemon uses only the server certificate. If `~/.config/rofi-bridge/` is fully exfiltrated, the attacker gets `server.key` (serious but limited: they can impersonate the current server) but cannot issue new forged certificates.

**Why This Choice**

This mirrors the real-world CA model: Root CA keys are kept offline (air-gapped in serious deployments). The difference between "server compromised" and "CA compromised" is fundamental: in the first case, rotate server cert and re-provision; in the second case, the entire trust infrastructure must be rebuilt. Keeping the CA key offline dramatically limits blast radius.

---

### 5.4 — System-Installed CA = Global Trust on Android

**Problem**

Installing `ca.crt` as a system CA on Android means it can sign certificates for **any domain** — google.com, banking sites, everything. If `ca.key` leaks, an attacker can MITM all HTTPS traffic on the phone until the user removes the CA.

**Solution**

Fully resolved by problem 5.2. The CA is never installed in the Android system store. Additionally, certificate pinning is applied:

```dart
client.badCertificateCallback = (X509Certificate cert, String host, int port) {
    // During provisioning bootstrap: accept ONLY if server fingerprint matches QR
    final expected = provisioningData.serverFingerprint;
    return _sha256Fingerprint(cert) == expected;
};
```

Post-provisioning, the custom `SecurityContext` with our CA enforces trust only for connections from our app to our daemon. No system-wide impact, ever.

**Why This Choice**

The CA's scope must exactly match the scope of the application. Installing it system-wide would violate the principle of least privilege at the PKI level. App-scoped trust via `SecurityContext` achieves the security goal (our daemon is authenticated) without expanding it (other HTTPS services remain unaffected).

---

### 5.5 — Token Without Expiry + Timing Attack

**Problem**

The original Bearer token approach has two flaws:
1. The token never expires — a captured token grants permanent access
2. `if token == provided_token` leaks information via response timing — an attacker measuring response latency can determine how many leading characters match, enabling character-by-character brute force

**Solution**

The token is entirely replaced by **Ed25519 asymmetric signing** (see problem 5.8 / section 6). For the audit log HMAC (which still uses a shared key), `hmac.compare_digest()` is used:

```python
import hmac
# Constant-time comparison — immune to timing attacks
if not hmac.compare_digest(expected_sig.encode(), provided_sig.encode()):
    return 401
```

For command authentication, no shared secret exists on the server at all — timing attacks against a secret that doesn't exist are moot.

**How It Works**

`hmac.compare_digest()` processes both strings in constant time regardless of how many characters match. The function is specifically designed to prevent timing side channels per RFC 6151. The Ed25519 approach eliminates the entire class of "shared secret interception" attacks since the server stores only the public key.

---

### 5.6 — IP-Bound Certificate Breaks on DHCP Reassignment

**Problem**

A certificate with `CN=192.168.1.100` fails validation when the local IP changes. DHCP can reassign IPs after router reboot, resulting in a permanently broken TLS connection with no obvious error message to the user.

**Solution**

Server certificate uses **Subject Alternative Names (SAN)** with multiple entries, plus an mDNS hostname:

```bash
cat > san.ext << EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1  = $(ip route get 8.8.8.8 | awk '{print $7; exit}')
IP.2  = 127.0.0.1
DNS.1 = rofi-bridge.local
DNS.2 = $(hostname).local
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -extfile san.ext -extensions v3_req -out server.crt -days 365
```

The Android app connects to `rofi-bridge.local` (mDNS-resolved), not to the IP. The cert is valid for the hostname. If the IP changes, mDNS resolves to the new IP transparently; the cert remains valid.

**Backup**: Certificate pinning (problem 5.4) pins the server's public key fingerprint, not the IP or hostname — validation succeeds regardless of IP changes.

**How It Works**

mDNS (Avahi on Linux) announces `rofi-bridge.local → current LAN IP` to all devices on the local segment. The announcement is updated whenever the IP changes (Avahi monitors interface changes). The app always connects to the same logical address while the physical IP is abstracted away.

**Note — PAM-hardened**: This problem is also solved structurally by the WireGuard overlay. The daemon binds to `10.0.0.2` (the PC's WireGuard interface IP) — a stable, static IP that never changes regardless of what the underlying physical network assigns. The VPS routes packets between WireGuard peers; the daemon itself runs on the PC, not on the relay.

---

### 5.7 — Daemon Bound to 0.0.0.0

**Problem**

Binding to all interfaces exposes the daemon on: WiFi, Ethernet, Docker bridges, VPN tunnels, loopback. A Docker container on the same machine, or a client connected via VPN, can reach the daemon even if the LAN is protected.

**Solution**

Dynamic binding to the detected LAN IP:

```python
def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

LAN_IP = get_lan_ip()
server = HTTPSServer((LAN_IP, PORT), Handler, ssl_context)
```

Additionally bound to loopback (`127.0.0.1`) for local GUI interactions, creating two separate server instances.

**PAM-hardened**: Daemon binds to the PC's WireGuard interface IP (`10.0.0.2`). Only devices inside the WireGuard tunnel — routed through the VPS — can reach it. The VPS (10.0.0.1) is the routing hub only; it runs no application-layer services.

**How It Works**

The kernel TCP stack filters inbound connections by destination IP against the bound interface. A packet arriving on `docker0` destined for `192.168.1.100` is discarded because the socket is bound to `192.168.1.100` on the LAN interface, not on `docker0`.

**Why This Choice**

Defense in depth: even if the firewall fails, the daemon is not physically reachable on non-LAN interfaces. Reduces attack surface without any functional impact — the Android app is always on the LAN.

---

### 5.8 — No Mutual TLS (Server Only Authenticates)

**Problem**

With standard TLS (one-way), any device on the LAN can establish a TLS connection with the daemon and reach the authentication layer. The server proves its identity to the client (via certificate), but the client proves nothing to the server at the transport layer. This exposes the authentication logic to:
- Brute force attempts
- Protocol fuzzing
- Parser exploitation
- Timing attacks against authentication code

**Solution**

**Mutual TLS (mTLS)**: both parties present certificates during the TLS handshake.

```python
# Daemon
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('server.crt', 'server.key')
ctx.load_verify_locations('ca.crt')
ctx.verify_mode = ssl.CERT_REQUIRED  # reject connections without client cert
```

```dart
// Flutter app
final context = SecurityContext(withTrustedRoots: false);
context.setTrustedCertificatesBytes(caCertBytes);
context.useCertificateChainBytes(clientCertBytes);
context.usePrivateKeyBytes(clientKeyBytes);
```

The TLS handshake fails at the kernel/TLS layer if the client does not present a certificate signed by our CA. No application code is reached, no HTTP request is parsed, no authentication logic is executed.

**How It Works**

In mTLS, the TLS handshake adds two steps compared to standard TLS:
1. Server sends `Certificate Request` to client
2. Client sends its certificate → server verifies signature chain against CA
3. Client sends `CertificateVerify` → proves possession of the private key (signs handshake hash)

This occurs before any HTTP byte is transmitted. An attacker without the client certificate receives `alert: certificate_required` and the TCP connection closes.

**Why This Choice**

mTLS provides the strongest possible transport-layer authentication. It operates in cryptographic hardware/OS primitives, not in application code — immune to logic bugs in the daemon's authentication handler. The client certificate is something the device physically **has** (second factor, complementing what it **knows** — the signing key for Ed25519).

---

### 5.9 — mDNS Reveals Service Presence to All LAN Devices

**Problem**

`_rofi-bridge._tcp.local` is visible to all devices on the LAN segment. Compromised IoT devices, guest network devices (if segmentation fails), or any passive listener can discover the daemon's IP and port.

**Solution**

Two complementary approaches:
1. **DHCP reservation** (primary): Configure the router to always assign the same IP to the machine's MAC address. Store IP in app during provisioning. Disable mDNS entirely.
2. **Non-descriptive mDNS name** (if mDNS kept): `_http._tcp.local` with a generic instance name — provides auto-discovery without announcing capability.

**On untrusted/exposed networks**: mDNS is disabled entirely (see Section 17). The IP address is embedded manually in the provisioning QR. This also eliminates the mDNS multicast traffic as a network fingerprint.

**Why This Choice**

Service discovery revealing the daemon's presence is an acceptable risk given the authentication model (mTLS + Ed25519 signing). The real protection is in the cryptographic layers, not in obscurity. However, disabling mDNS and using DHCP reservation is preferred as it also solves problem 5.6 (IP changes) without cert complexity.

---

### 5.10 & 5.11 — Weak TLS Version and Cipher Suites / No Forward Secrecy

**Problem**

Python's `ssl.SSLContext` by default:
- Accepts TLS 1.0 and 1.1 (vulnerable to BEAST, POODLE, CRIME)
- Includes RSA key exchange cipher suites without forward secrecy: if `server.key` is captured in the future, all recorded past traffic can be decrypted offline

**Solution**

Explicit TLS hardening:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers(
    'ECDHE-ECDSA-AES256-GCM-SHA384:'
    'ECDHE-RSA-AES256-GCM-SHA384:'
    'ECDHE-ECDSA-CHACHA20-POLY1305:'
    'ECDHE-RSA-CHACHA20-POLY1305:'
    '!aNULL:!eNULL:!EXPORT:!MD5:!RC4:!3DES:!SHA1'
)
ctx.options |= (
    ssl.OP_NO_SSLv2     |
    ssl.OP_NO_SSLv3     |
    ssl.OP_NO_TLSv1     |
    ssl.OP_NO_TLSv1_1   |
    ssl.OP_NO_COMPRESSION |   # CRIME attack
    ssl.OP_SINGLE_ECDH_USE    # fresh ECDH key per session
)
```

**How It Works — Forward Secrecy**

With ECDHE (Elliptic Curve Diffie-Hellman Ephemeral), each TLS session generates a temporary key pair. The session secret derives from these ephemeral keys via ECDH, not from `server.key`. After the session, ephemeral keys are destroyed. Even if `server.key` is captured years later, past sessions cannot be decrypted — the ephemeral keys no longer exist.

AES-GCM and ChaCha20-Poly1305 are AEAD (Authenticated Encryption with Associated Data) ciphers — they guarantee both confidentiality and integrity. A modified packet in transit is detected and the connection is dropped.

**Why This Choice**

Forward secrecy is a non-negotiable property for a system passing sudo commands. The principle: past communications must remain confidential even if current keys are compromised. ECDHE provides this. RSA key exchange does not. This is also why TLS 1.3 (which mandates forward secrecy) is preferred over 1.2.

---

### 5.12 — Private Keys Unprotected on Disk

**Problem**

`server.key` in `~/.config/rofi-bridge/` is readable by any process running as the same user — browsers, Electron apps, malicious scripts with directory traversal. File permissions (`chmod 400`) help but do not prevent access by processes running as that user.

**Solution**

Two-level approach:

**Level 1 — File permissions**: `chmod 400` for both `server.key` and any private key files. Minimum necessary.

**Level 2 — Linux Kernel Keyring**: Load `server.key` into the kernel keyring at daemon startup, keep only the decrypted key in kernel memory:

```python
import keyutils

# First startup (or after rotation): load from disk
with open('server.key', 'rb') as f:
    key_data = f.read()
keyutils.add_key('user', 'rb-server-key', key_data,
                  keyutils.KEY_SPEC_USER_KEYRING)

# Subsequent startups: read from kernel keyring (not from disk file)
key_data = keyutils.read_key(keyutils.KEY_SPEC_USER_KEYRING, 'rb-server-key')
```

The key lives in kernel memory, not in a file. It does not appear in `/proc`, is inaccessible via `open()/read()` syscalls by other processes, and is automatically lost on reboot (requiring re-load from the encrypted disk copy on next startup).

**Why This Choice**

The Linux Kernel Keyring is used by LUKS for disk encryption keys, by Kerberos for session keys, and by NFS for credentials. It is the kernel-native secret store. Reducing the attack surface from "readable file" to "kernel memory object accessible only via dedicated syscall" significantly raises the bar for exfiltration.

---

### 5.13 — QR Code Exposes the Token

**Problem**

The original QR code contained `{ ip, port, token }`. The token is the master secret. A photographed QR code, a screen recording, or a screenshot gives permanent access with no expiry.

**Solution**

**OTP Provisioning Flow**: the QR never contains the token or any long-lived secret. It contains a one-time provisioning code:

```python
import secrets, time

class ProvisioningStore:
    def __init__(self):
        self._pending = {}  # { otp: expires_at }

    def generate(self):
        otp = secrets.token_hex(16)  # 128-bit random
        self._pending[otp] = time.time() + 60  # 60-second TTL
        return otp

    def consume(self, otp):
        entry = self._pending.pop(otp, None)  # one-time: removed on first use
        if not entry or time.time() > entry:
            return False
        return True
```

**QR contains**: `{ address, otp, server_cert_fingerprint }`

The `server_cert_fingerprint` (SHA-256 of the server cert's DER encoding) solves the bootstrap trust problem (see problem 5.19) without including any secret.

**Why This Choice**

Separation of secret lifecycles: the OTP is ephemeral (60 seconds, one use). Long-lived secrets (client key pair, mTLS cert) are provisioned over the encrypted channel after OTP verification. The QR code becomes worthless 60 seconds after display. This mirrors authenticator app QR codes (e.g., TOTP setup), which contain only seeds for key derivation, not the keys themselves.

---

### 5.14 — No Certificate Revocation

**Problem**

If a client certificate is compromised, there is no mechanism to invalidate it. The cert remains valid for its entire lifetime with no CRL or OCSP infrastructure.

**Solution**

**Serial number blacklist** maintained in daemon memory, persisted to disk:

```python
REVOKED_SERIALS_FILE = CONFIG_DIR / 'revoked.txt'
revoked = set()

def load_revoked():
    if REVOKED_SERIALS_FILE.exists():
        revoked.update(REVOKED_SERIALS_FILE.read_text().split())

def revoke(serial: str):
    revoked.add(serial)
    with open(REVOKED_SERIALS_FILE, 'a') as f:
        f.write(serial + '\n')

def verify_client_cert(cert_pem: bytes) -> bool:
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial = str(cert.serial_number)
    return serial not in revoked
```

**Revocation in GUI GTK**: "Revoke Device" button → lists provisioned devices by device ID, removes the device's directory from `clients/<device_id>/`, adds their cert serial to `revoked.txt`. Next connection attempt fails at the mTLS verification step.

**Why This Choice**

CRL and OCSP are infrastructures designed for public CAs serving millions of certificates. For a personal LAN tool with 1-5 client devices, a serial blacklist is functionally equivalent and dramatically simpler. The fundamental revocation action is immediate (directory deletion + serial blacklist), not dependent on CRL distribution delays.

---

### 5.15 — No Audit Log

**Problem**

No visibility into command history. If the Ed25519 signing key is compromised and commands are executed by an attacker, there is no forensic record.

**Solution**

Append-only HMAC-signed audit log:

```python
import json, time, hmac, hashlib

AUDIT_KEY = secrets.token_bytes(32)  # generated at setup, stored separately

def audit(device_id: str, command: str, result: str, client_cert_serial: str):
    entry = {
        "ts":     time.time(),
        "device": device_id,
        "cmd":    command,
        "result": result,
        "serial": client_cert_serial,
    }
    line = json.dumps(entry, separators=(',', ':'))
    sig  = hmac.new(AUDIT_KEY, line.encode(), hashlib.sha256).hexdigest()
    with open(AUDIT_LOG, 'a') as f:
        f.write(f"{line} sig={sig}\n")
```

Each log line is HMAC-signed with a dedicated audit key. Modification of any log line invalidates its signature, detectable by a verification pass.

**Why This Choice**

Non-repudiation and forensics. With Ed25519 command signing, each request is already signed by the client — the audit log records that signature alongside the execution result. This provides a cryptographically verifiable record: the entry proves that `device_id`'s signing key was used for `command` at `timestamp`.

---

### 5.16 — No Rate Limiting

**Problem**

Unlimited connection attempts enable brute-force attacks against authentication, DoS via connection exhaustion, and protocol fuzzing without consequence.

**Solution**

In-memory rate limiter with IP-based tracking and progressive banning:

```python
from collections import defaultdict
from time import time

class RateLimiter:
    def __init__(self, max_req=10, window_s=60, max_failures=3, ban_s=3600):
        self.requests = defaultdict(list)
        self.failures = defaultdict(int)
        self.banned   = {}
        self._max_req  = max_req
        self._window   = window_s
        self._max_fail = max_failures
        self._ban_dur  = ban_s

    def is_allowed(self, ip: str) -> bool:
        now = time()
        if ip in self.banned and now < self.banned[ip]:
            return False
        self.requests[ip] = [t for t in self.requests[ip] if now - t < self._window]
        if len(self.requests[ip]) >= self._max_req:
            return False
        self.requests[ip].append(now)
        return True

    def record_failure(self, ip: str):
        self.failures[ip] += 1
        if self.failures[ip] >= self._max_fail:
            self.banned[ip] = time() + self._ban_dur

    def record_success(self, ip: str):
        self.failures[ip] = 0
```

TLS-layer rate limiting: max 5 simultaneous incomplete TLS handshakes accepted.

**On untrusted/exposed and open networks**: an additional **global** TLS handshake rate limit is added — max 5 completed handshakes per second across all IPs, regardless of source. This counters port-scan tools and TLS probe floods from multiple sources that would bypass per-IP limits. See Section 17 for full details.

**Nonce cache implementation requirement**: The nonce cache must be persisted to disk (SQLite). An in-memory-only implementation creates a replay attack window: if the daemon restarts (system update, crash, reboot), the cache is lost. An attacker who captured a valid signed request before the restart can replay it within the ±30s timestamp window after restart. SQLite persistence closes this gap — nonces are written to disk on arrival and purged at startup only after TTL expiry. See Section 18 for implementation details.

---

### 5.17 — NOPASSWD Permanent Even When Daemon is Stopped

**Problem**

A sudoers rule persists system-wide regardless of whether the daemon is running. Any process running as the same user can execute those privileged commands at any time.

**Solution**

Fully resolved by the `setcap` approach (problem 5.1). With `setcap cap_net_admin+eip` on `ipt-helper`, there is no sudoers rule at all. The privilege is in the binary. Removing the binary removes the privilege. `setup.sh --uninstall` → `rm /usr/lib/rofi-bridge/ipt-helper` → zero privileged trace.

---

### 5.18 — CA Persists on Android After Decommissioning

**Problem**

A system-installed CA cert on Android remains after the daemon is decommissioned, indefinitely extending the trust surface.

**Solution**

Fully resolved by problems 5.2 and 5.4. The CA is never installed in the Android system store. It lives exclusively in the app's `flutter_secure_storage`. When the app is uninstalled, `flutter_secure_storage` is destroyed with it — CA cert, TLS client cert, TLS client key: all gone.

---

### 5.19 — CA Distribution Chicken-and-Egg Problem

**Problem**

To trust the server's self-signed cert, the app needs `ca.crt`. But how to securely transfer `ca.crt` to the app before trust is established? Any unsecured channel (HTTP, email) exposes the distribution to MITM.

**Solution**

The `server_cert_fingerprint` in the QR code acts as a bootstrap trust anchor:

```
QR → app → first HTTPS connection with fingerprint pinning (TOFU)
                      ↓
         GET /provision with valid OTP
                      ↓
         Server returns { ca_cert, tls_cert, tls_key } over the fingerprint-pinned channel
                      ↓
         App now has ca_cert → switches to full CA validation
```

```dart
// First connection: pin to fingerprint from QR (no CA needed)
client.badCertificateCallback = (cert, host, port) =>
    _sha256(cert.der) == qrData.serverFingerprint;

// After provisioning: use CA (no more bad cert callback)
final context = SecurityContext(withTrustedRoots: false);
context.setTrustedCertificatesBytes(storedCaCert);
```

The fingerprint is 32 bytes (SHA-256) — 43 base64 characters — trivially fitting in a QR code. This is the SSH host key model applied to HTTPS.

**Why This Choice**

Trust On First Use (TOFU) with physical verification: the QR code is displayed on the PC screen and scanned by the phone in physical proximity. The fingerprint in the QR makes the channel tamper-evident: an attacker intercepting the connection cannot substitute their own certificate because the fingerprint wouldn't match. Physical proximity at provisioning time is the root of trust.

---

### 5.20 — Bearer Token as Single Point of Failure

**Problem**

All security relies on a single shared secret. Its capture, derivation, or leakage compromises the entire system permanently.

**Solution**

Replaced by the full asymmetric model (see section 6). The token is eliminated entirely. Authentication relies on:
- mTLS client certificate (device identity, transport layer)
- Ed25519 command signature (per-command authorization, application layer)

The server stores only public keys. There is no shared secret. Zero information on the server can be used to forge client requests.

---

## 6. Design Evolution — Two Models Compared

### Model 1: HMAC-Based (Considered, Rejected)

```
Server storage: { HMAC token (secret), client TLS cert (public), audit HMAC key (secret) }

Per-request authentication:
  payload   = f"{timestamp}:{nonce}:{command}"
  signature = HMAC-SHA256(token, payload)
  Server verifies: HMAC-SHA256(stored_token, payload) == signature
```

**Flaw**: The server stores the HMAC token — a secret that can forge any request. A full server compromise gives the attacker permanent ability to impersonate the client. The server is simultaneously the authentication verifier AND custodian of the authentication secret.

### Model 2: Full Asymmetric / Ed25519 (Chosen)

```
Server storage: { client TLS cert (public), Ed25519 public key (public) }
  → ZERO secrets on server

Per-request authentication:
  payload   = f"{timestamp}:{nonce}:{command}"
  signature = Ed25519_sign(private_key, payload)    # private key never leaves Android Keystore
  Server verifies: Ed25519_verify(stored_public_key, payload, signature)
```

**Property**: A complete server dump (all files, all memory) contains zero information that can forge a client request. The client's private key lives in the Android Keystore — hardware-backed, non-exportable on Android 9+.

### Head-to-Head Comparison

| Property | Model 1 (HMAC) | Model 2 (Ed25519) |
|---|---|---|
| Server stores secret | ✗ Yes (token) | ✓ No (public keys only) |
| Server compromise → forge requests | ✗ Yes | ✓ No |
| Client private key leaves device | ✗ Yes (token on both sides) | ✓ Never |
| Hardware-backed client key | ✗ No | ✓ Yes (Android Keystore) |
| Per-command non-repudiation | ✗ No | ✓ Yes |
| Multi-device: individual revocation | ✗ Shared token | ✓ Independent key pairs |
| Performance overhead | ~nanoseconds | ~microseconds (Ed25519 is fastest signing algo) |
| Implementation complexity | Lower | Slightly higher |

**Decision**: Model 2. The server storing zero secrets is a fundamental security property — not a marginal improvement. For a tool passing sudo commands, the cost of slightly higher implementation complexity is entirely justified.

### Why Ed25519 over RSA and ECDSA

| Algorithm | Key size | Signature size | Notes |
|---|---|---|---|
| **RSA-2048** | 2048 bits | 256 bytes | Slow, large, no advantage over ECC for new code |
| **ECDSA P-256** | 256 bits | ~72 bytes | Vulnerable to nonce reuse (PSK3 attack — Sony PS3 incident). Requires cryptographically perfect RNG for every signature |
| **Ed25519** | 256 bits | 64 bytes | Deterministic nonce (derived from key + message via SHA-512). Cannot fail due to RNG weakness. Fastest signing. Clear constant-time implementation |

Ed25519 uses `nonce = H(private_key_seed || message)` — the nonce is deterministic and cryptographically derived, not generated by an RNG at signature time. Nonce reuse is mathematically impossible. This eliminates the ECDSA P-256 catastrophic failure mode.

---

## 7. Final Architecture — Model 2 (Full Asymmetric)

### Security Stack (per request)

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Transport                                            │
│  TLS 1.3 preferred (1.2 minimum), ECDHE-only cipher suites      │
│  AES-256-GCM or ChaCha20-Poly1305 (AEAD)                       │
│  Forward secrecy: session keys derived from ephemeral ECDHE     │
│  No compression (CRIME), fresh ECDH key per session             │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2 — Device Identity (mTLS)                               │
│  Client presents client_tls.crt signed by CA                   │
│  Server verifies signature chain → CA cert                      │
│  Checks serial number against revocation list                   │
│  Extracts device_id from cert Subject CN                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3 — Command Authorization (Ed25519)                      │
│  payload = f"{unix_ts}:{nonce}:{command_enum}"                  │
│  signature = Ed25519_sign(app_signing.key, payload)             │
│  Server: Ed25519_verify(clients/<device_id>/sign.pub, sig)      │
│  Client private key: Android Keystore hardware-backed           │
│  Server stores: public key only (zero secrets)                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4 — Replay Protection                                    │
│  Timestamp: must be within ±30 seconds of server time           │
│  Nonce: 32-byte random, checked against LRU cache (5-min window)│
│  Both embedded in signed payload — tampering detected by sig    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5 — Privilege Execution                                  │
│  ipt-helper C binary: cap_net_admin+eip via setcap              │
│  Accepts only: "open" | "close" | "check"                       │
│  Reads port from config, NOT from arguments                     │
│  execv() — no shell, no metacharacters, no wildcard             │
│  Other commands: subprocess with explicit argv array (no sh -c) │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6 — Observability                                        │
│  Audit log: append-only, HMAC-SHA256 per line                   │
│  Records: timestamp, device_id, command, result, cert serial    │
│  Rate limiter: 10 req/min per IP, ban after 3 failures (1h)    │
└─────────────────────────────────────────────────────────────────┘
```

### PAM-hardened: Additional Outer Layer

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 0 — WireGuard Tunnel (PAM-hardened only)                 │
│  ChaCha20-Poly1305 + Poly1305 MAC                               │
│  Noise_IKpsk2 handshake protocol                                │
│  Perfect forward secrecy: new ephemeral keys every 3 minutes    │
│  Android WireGuard app → Oracle Free Tier VPS → PC wg0          │
│  TLS over WireGuard: double encryption, neither layer visible   │
│  to relay infrastructure                                        │
└─────────────────────────────────────────────────────────────────┘
        ↓ wraps →
┌─────────────────────────────────────────────────────────────────┐
│  Layers 1–6 (identical to PAM)                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Server Storage — Zero Secrets

```
~/.config/rofi-bridge/
├── server.key              ← server's own TLS private key (not a client secret)
├── server.crt              ← server TLS cert (SAN: hostname.local, LAN IP)
├── ca.crt                  ← CA public cert (not secret)
├── revoked.txt             ← serial number blacklist
├── audit.log               ← append-only HMAC-signed log
├── pending_otps.json       ← active OTPs (TTL 60s, one-time)
└── clients/
    └── <device_id>/
        ├── tls.crt         ← (PUBLIC) client TLS cert for mTLS verification
        └── sign.pub        ← (PUBLIC) Ed25519 public key for command verification

~/rofi-bridge-ca/
└── ca.key.enc              ← (OFFLINE) CA private key, AES-256 encrypted
                              Never loaded by daemon. Used only for cert issuance.
```

A full exfiltration of `~/.config/rofi-bridge/` gives the attacker:
- `server.key` → can impersonate the server (mitigated by cert pinning on client)
- `ca.crt` → useless without `ca.key.enc`
- `clients/*/tls.crt`, `clients/*/sign.pub` → public keys, cryptographically useless for forging

**Zero forging capability from server compromise alone.**

---

## 8. All Operational Flows

### 8.1 — Setup Flow (PAM — one-time)

```
setup.sh executes:

Step 1: Certificate Authority
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -key ca.key -out ca.crt -days 3650
      -subj "/CN=PAM-CA-$(hostname)"
  # Sign server cert with PLAINTEXT ca.key BEFORE encrypting (see Step 2).
  # After signing: encrypt, then shred plaintext.
  openssl pkcs8 -in ca.key -topk8 -v2 aes256 -out ~/rofi-bridge-ca/ca.key.enc
  shred -u ca.key
  # ca.key.enc → OFFLINE, never read by daemon

Step 2: Server Certificate (with SAN)
  # NOTE: sign with plaintext ca.key while it still exists (before Step 1 shred).
  # For --regenerate-server-cert (key already encrypted), setup.sh decrypts to a
  # temporary file (mktemp, chmod 600), signs, then shreds the temp file.
  LAN_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
  HOSTNAME=$(hostname)
  openssl genrsa -out server.key 2048
  openssl req -new -key server.key -out server.csr
      -subj "/CN=rofi-bridge/O=PAM"
  # Generate san.ext: [SAN] subjectAltName=IP:$LAN_IP,DNS:$HOSTNAME.local
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key
      -CAcreateserial -extfile san.ext -extensions SAN
      -out server.crt -days 365
  # (ca.key still plaintext here — shred happens at end of Step 1)

Step 3: Privilege Helper
  gcc -O2 -o ipt-helper ipt-helper.c
  sudo install -m 755 ipt-helper /usr/lib/rofi-bridge/ipt-helper
  sudo setcap cap_net_admin+eip /usr/lib/rofi-bridge/ipt-helper
  # Zero sudoers modifications

Step 4: Server Key → Kernel Keyring
  keyctl add user rb-server-key "$(cat server.key)" @u
  # server.key remains on disk as encrypted backup
  # daemon reads from keyring at startup

Step 5: Systemd Service
  install ~/.config/systemd/user/rofi-bridge.service
  systemctl --user enable --now rofi-bridge
  # Service binds to LAN_IP:7443
```

---

### 8.2 — Setup Flow (PAM-hardened — relay-setup.sh, additive)

```
relay-setup.sh Phase A — VPS Oracle Free Tier (run once on the VPS):

  1. apt install wireguard
  2. VPS_PRIV=$(wg genkey)
     VPS_PUB=$(echo $VPS_PRIV | wg pubkey)
  3. cat > /etc/wireguard/wg0.conf << EOF
     [Interface]
     Address    = 10.0.0.1/24
     ListenPort = 51820
     PrivateKey = $VPS_PRIV

     [Peer]                          # PC
     PublicKey  = <PC_PUBKEY>
     AllowedIPs = 10.0.0.2/32

     [Peer]                          # Android (AllowedIPs per device)
     PublicKey  = <ANDROID_PUBKEY>
     AllowedIPs = 10.0.0.3/32
     EOF
  4. systemctl enable --now wg-quick@wg0
  5. ufw allow 51820/udp          # WireGuard
     ufw allow from 10.0.0.0/24  # PAM traffic inside tunnel
     ufw deny 7443                # no direct TCP 7443 from outside
  6. sysctl net.ipv4.ip_forward=1  # enable routing between wg peers

relay-setup.sh Phase B — PC (part of setup.sh --hardened):

  1. PC_PRIV=$(wg genkey)
     PC_PUB=$(echo $PC_PRIV | wg pubkey)
  2. cat > /etc/wireguard/wg0.conf << EOF
     [Interface]
     Address    = 10.0.0.2/32
     PrivateKey = $PC_PRIV

     [Peer]                          # VPS relay
     PublicKey  = <VPS_PUBKEY>
     Endpoint   = <VPS_PUBLIC_IP>:51820
     AllowedIPs = 10.0.0.0/24
     PersistentKeepalive = 25
     EOF
  3. systemctl enable --now wg-quick@wg0
  4. # Generate server cert with SAN IP = 10.0.0.2 (PC wg0 IP — the daemon endpoint)
     #   IP.1=10.0.0.2, IP.2=127.0.0.1
     #   No mDNS DNS entries (mDNS disabled in hardened mode)
  5. systemctl --user enable --now rofi-bridge  # binds 10.0.0.2 (PC wg0 interface)

Android App:
  - Install WireGuard app
  - Configure peer: endpoint = <VPS_PUBLIC_IP>:51820, AllowedIPs = 10.0.0.0/24
  - AllowedIPs routes PAM traffic through tunnel; all other traffic goes direct (split tunnel)
  - VPS routes inner IP packets: 10.0.0.3 (Android) → 10.0.0.2 (PC daemon) via IP forwarding
  - After WireGuard connected: provisioning and runtime address = 10.0.0.2:7443
```

**Traffic path (PAM-hardened)**:
```
Android app
    │  (WireGuard UDP encrypted)
    ↓
Oracle Free Tier VPS  ←── relay, sees only WireGuard UDP
    │  (WireGuard UDP encrypted, different session)
    ↓
PC wg0 interface (10.0.0.2)
    │  (HTTPS decrypted here, inside WireGuard)
    ↓
bridge_v2.py daemon
```

The VPS sees:
- WireGuard handshakes (Noise_IKpsk2, public keys)
- Encrypted UDP datagrams — zero knowledge of TLS, HTTPS, or commands

The daemon receives:
- Standard HTTPS on wg0 — identical to PAM direct

---

### 8.3 — Provisioning Flow (once per device)

```
PC — GUI GTK:
  1. Generates OTP: 128-bit random, TTL=60s, stored in pending_otps.json
  2. Computes server_cert_fingerprint = SHA-256(server.crt in DER format)
  3. Displays QR containing:
     PAM:         { "addr": "192.168.1.100:7443", "otp": "<hex>", "fp": "<b64>" }
     PAM-hardened:{ "addr": "10.0.0.2:7443",      "otp": "<hex>", "fp": "<b64>" }
  4. QR refreshes every 55 seconds (countdown shown)
  5. (Untrusted network mode): manual confirmation dialog displayed — admin must
     explicitly click "Accept Provisioning" after QR scan before OTP is activated

Android App:
  5. Scans QR → extracts { addr, otp, fp }
  6. Generates Ed25519 key pair IN Android Keystore:
     KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
     → private key: hardware-backed, non-exportable, stays in Keystore forever
     → public key: exportable, will be sent to server
  7. Opens HTTPS connection to addr with CERTIFICATE PINNING on fp:
     badCertificateCallback = (cert, _, _) => sha256(cert.der) == fp
     (Trust On First Use — fingerprint from QR is the bootstrap trust anchor)
  8. POST /provision
     mTLS: NO client cert yet (first connection, cert not yet issued)
     Body: { "otp": "<hex>", "sign_pub": "<Ed25519 public key, base64>" }

Server (/provision handler):
  9. Verifies OTP: exists in pending_otps.json AND not expired
  10. Removes OTP from pending_otps.json (one-time use enforced)
  11. Generates device_id = SHA-256(sign_pub)[:16]
  12. Generates client TLS key pair + certificate:
      openssl genrsa -out clients/<device_id>/tls.key 2048
      openssl req -new -key clients/<device_id>/tls.key \
          -out clients/<device_id>/tls.csr \
          -subj "/CN=<device_id>/O=PAM-client"
      # ca.key.enc decrypted to temp file using passphrase from pending_otps.json,
      # used for signing, then shredded immediately.
      openssl x509 -req -in clients/<device_id>/tls.csr \
          -CA ca.crt -CAkey <tmp_ca_key> \
          -CAcreateserial -days 365 \
          -out clients/<device_id>/tls.crt
      shred -u <tmp_ca_key>
  13. Saves sign.pub to clients/<device_id>/sign.pub
  14. Responds with:
      { "ca_cert": "<ca.crt PEM>",
        "tls_cert": "<client tls.crt PEM>",
        "tls_key": "<client tls.key PEM>" }

App:
  15. Stores in flutter_secure_storage:
      "ca_cert"  → ca.crt PEM
      "tls_cert" → tls.crt PEM
      "tls_key"  → tls.key PEM
      "server_addr" → addr
  16. Switches to full CA validation (removes fingerprint pinning callback)
  17. All future connections use mTLS + Ed25519 signing
```

---

### 8.4 — Runtime Request Flow (every command)

```
Android App:
  nonce     = SecureRandom.nextBytes(32).toHex()
  timestamp = unix_seconds_now()
  command   = CommandEnum.CHECK_PORT  (enum, not free string)
  payload   = "$timestamp:$nonce:$command"
  signature = KeyStore.sign("rofi-bridge-signing-key", payload.toUtf8())
              → Ed25519_sign(hardware_private_key, payload)

  POST https://rofi-bridge.local:7443/run         (PAM)
  POST https://10.0.0.2:7443/run                  (PAM-hardened)
    TLS: custom SecurityContext with ca_cert → validates server cert
    mTLS: presents tls_cert + proves possession of tls_key
    Body: { "payload": payload, "sig": signature_b64 }

Server:
  1. TLS handshake: validates client tls.crt against ca.crt (mTLS)
     → Extracts device_id from cert Subject CN
     → Checks serial against revoked.txt → if revoked: close connection
  2. Rate limiter check(ip) → if exceeded: 429 Too Many Requests
  3. Parses body: { payload, sig }
  4. Splits payload: timestamp, nonce, command
  5. Validates timestamp: |now - timestamp| <= 30s → else 401
  6. Validates nonce: not in nonce_cache → else 401 (replay attack)
     Adds nonce to nonce_cache (LRU, 5-min TTL)
  7. Validates command: command in CommandWhitelist → else 400
  8. Loads sign.pub from clients/<device_id>/sign.pub
  9. Ed25519_verify(sign.pub, payload.encode(), sig_bytes)
     → if invalid: rate_limiter.failure(ip) + 401
  10. rate_limiter.success(ip)
  11. Executes command:
      IPTABLES_CHECK → /usr/lib/rofi-bridge/ipt-helper check
      IPTABLES_OPEN  → /usr/lib/rofi-bridge/ipt-helper open
      IPTABLES_CLOSE → /usr/lib/rofi-bridge/ipt-helper close
      DAEMON_STATUS  → systemctl --user is-active rofi-bridge
      DAEMON_START   → systemctl --user start rofi-bridge
      DAEMON_STOP    → systemctl --user stop rofi-bridge
      DAEMON_RESTART → systemctl --user restart rofi-bridge
  12. audit.log: { ts, device_id, command, result, cert_serial }
  13. Returns: { "result": "ok", "data": ... }
```

---

### 8.5 — Revocation Flow

```
GUI GTK — "Revoke Device":
  1. Lists directories in clients/
  2. For each: reads tls.crt → extracts device_id (CN), serial number
  3. User selects device to revoke
  4. Server:
     a. Appends serial to revoked.txt
     b. rm -rf clients/<device_id>/
  5. Next connection attempt from that device:
     → mTLS: serial found in revoked.txt → connection closed
     → Device must be re-provisioned from scratch

GUI GTK — "Revoke & Regenerate All":
  1. Generates new CA (new ca.key.enc in ~/rofi-bridge-ca/)
  2. Generates new server.key + server.crt
  3. rm -rf clients/  (all device registrations invalidated)
  4. Clears revoked.txt
  5. Restarts daemon with new certs
  6. All existing provisioned devices rejected at mTLS
  7. All devices must re-provision with new QR
```

---

## 9. Component Specifications

### 9.1 — bridge_v2.py (Daemon)

| Property | Value |
|---|---|
| **Protocol** | HTTPS (native Python `ssl`) |
| **Port** | 7443 (PAM) / 7443 on wg0 (PAM-hardened) / 443 optional (untrusted networks) |
| **Bind address** | LAN IP + 127.0.0.1 (PAM) / wg0 IP + 127.0.0.1 (PAM-hardened) |
| **TLS version** | 1.2 minimum, 1.3 preferred |
| **Cipher suites** | ECDHE+AES-GCM, ECDHE+ChaCha20 only |
| **mTLS** | `ssl.CERT_REQUIRED` |
| **Auth** | Ed25519 signature verification (PyCA `cryptography` library) |
| **Command execution** | `subprocess` with explicit `argv` list (no `sh -c`) |
| **Rate limiting** | 10 req/60s per IP, ban 1h after 3 failures; global 5 handshakes/s (untrusted mode) |
| **Nonce cache** | SQLite persistent (`nonces.db`), 5-minute TTL, purged on startup; survives daemon restart |
| **Audit log** | Append-only, HMAC-SHA256 per line |
| **Dependencies** | `zeroconf` (optional, PAM only), `cryptography`, `tomllib` (stdlib 3.11+) |

**Endpoints**:

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | none | Liveness check (returns 200 + version) |
| `/provision` | POST | OTP (first-time, no mTLS) | Device provisioning |
| `/run` | POST | mTLS + Ed25519 | Execute whitelisted command |
| `/config` | GET | mTLS + Ed25519 | Return rofi menu config JSON |
| `/audit` | GET | mTLS + Ed25519 | Return last 50 audit log lines |

---

### 9.2 — ipt-helper (C binary with setcap)

| Property | Value |
|---|---|
| **Language** | C (no external dependencies) |
| **Capability** | `CAP_NET_ADMIN` via `setcap cap_net_admin+eip` |
| **Accepted arguments** | `"open"` \| `"close"` \| `"check"` (exactly, no other) |
| **Port source** | Read from `~/.config/rofi-bridge/config.toml` at startup |
| **Execution** | `execv("/usr/sbin/iptables", explicit_argv)` — no shell |
| **Install path** | `/usr/lib/rofi-bridge/ipt-helper` |
| **Build** | Compiled by `setup.sh`, `gcc -O2 -Wall` |
| **Capability guard** | `pam-setcap.service` (systemd oneshot, `Before=rofi-bridge.service`) |

**pam-setcap.service** — ensures `setcap` survives system updates that may reinstall or overwrite the binary:

```ini
[Unit]
Description=PAM ipt-helper capability guard
Before=rofi-bridge.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'getcap /usr/lib/rofi-bridge/ipt-helper | grep -q cap_net_admin || setcap cap_net_admin+eip /usr/lib/rofi-bridge/ipt-helper'
RemainAfterExit=yes

[Install]
WantedBy=default.target
```

This runs at every boot before the daemon starts. If a system update replaces `ipt-helper` without the capability (e.g., package reinstall), the guard re-applies it. Without this, `ipt-helper` silently loses `CAP_NET_ADMIN` and the daemon fails to execute firewall commands with no clear error message.

---

### 9.3 — gui_gtk (C + GTK3)

Existing file: `gui_gtk.c` (already split across `main.c`, `sys.c`, `sys.h`, `qr.h`, `qr.c`, `gui_gtk.h`, `gui_gtk.c`).

**New panels to add**:

| Panel | Description |
|---|---|
| **Provisioning** | "New Device" button → generates OTP + shows QR (60s countdown) |
| **Device List** | Lists clients/<device_id>/ with cert expiry, last seen |
| **Revoke Device** | Per-device revocation with confirmation dialog |
| **Revoke & Regenerate** | Full PKI regeneration with warning dialog |
| **Audit Log** | Scrollable view of last 50 audit.log lines, auto-refresh |
| **Manual Confirm** | Confirmation pop-up for untrusted network provisioning mode |

---

### 9.4 — Flutter App (Android)

**Key changes from v1**:

| Feature | v1 | v2 |
|---|---|---|
| Transport | HTTP | HTTPS (custom SecurityContext) |
| Auth | Bearer token | Ed25519 signature (Android Keystore) |
| Client cert | None | mTLS client cert (flutter_secure_storage) |
| CA trust | System Android store | App-private SecurityContext only |
| Token in QR | Yes (permanent exposure) | No — OTP provisioning |
| Key generation | Server generates, sends to app | App generates Ed25519 in Keystore |
| WireGuard (hardened) | N/A | WireGuard app + peer config for relay tunnel |

**Android Keystore usage**:
```dart
// Key generation (once, during provisioning)
final keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
keyPairGenerator.initialize(
    KeyGenParameterSpec.Builder("pam-signing-key",
        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
    .setUserAuthenticationRequired(false)  // or true for biometric
    .build()
);
final keyPair = keyPairGenerator.generateKeyPair();
// → private key: hardware-backed, non-exportable
// → public key: send to server during provisioning
```

**PAM-hardened fallback logic** — if the WireGuard tunnel is unavailable (VPS down, no internet), the app attempts to fall back to direct LAN connection:

```dart
Future<HttpClient> _resolveClient() async {
  if (_config.mode == PamMode.hardened) {
    // Try hardened endpoint (10.0.0.2 via WireGuard)
    try {
      final client = _buildClient();
      await client.getUrl(Uri.parse('https://10.0.0.2:7443/health'))
          .timeout(const Duration(seconds: 5));
      return client;
    } on TimeoutException {
      // WireGuard tunnel unavailable → fall back to stored LAN IP
    } on SocketException {
      // No route through tunnel → fall back
    }
  }
  // PAM direct or hardened fallback: use stored LAN IP
  return _buildClient();
}
```

The stored LAN IP is the address captured during provisioning, saved in `flutter_secure_storage` alongside the certs. Fallback is attempted once; if both fail, the user sees an explicit connection error. Fallback requires the device to be on the same LAN as the PC (home network) — it is not available on public WiFi.

---

### 9.5 — setup.sh

**Responsibilities**:
1. Prerequisite check: NTP synchronization active (`systemctl is-active systemd-timesyncd || chrony`)
2. CA generation + encryption + offline storage
3. Server cert generation with SAN
4. ipt-helper compilation + `setcap` installation
5. `pam-setcap.service` installation + enable
6. Server key loading into Linux Kernel Keyring
7. Systemd user service installation + startup
8. Initial health check verification

**NTP prerequisite check** — the timestamp ±30s replay window requires synchronized clocks on both sides. If NTP is not active at setup time, setup.sh exits with a clear error:

```bash
if ! systemctl is-active --quiet systemd-timesyncd && ! systemctl is-active --quiet chronyd; then
    echo "ERROR: No NTP service active. Run: systemctl enable --now systemd-timesyncd" >&2
    exit 1
fi
```

**Flags**:
- `setup.sh` — fresh PAM installation (LAN IP bind)
- `setup.sh --hardened` — PAM-hardened (wg0 bind 10.0.0.2, SAN IP=10.0.0.2, mDNS disabled)
- `setup.sh --regenerate-server-cert` — new server cert (CA unchanged)
- `setup.sh --regenerate-all` — new CA + server cert (all devices must re-provision)
- `setup.sh --uninstall` — removes all components

**Idempotency**: all operations check for existing state before executing. Re-running `setup.sh` on an already-configured system does not overwrite existing certs or configs unless `--regenerate-*` flags are used.

---

### 9.6 — relay-setup.sh (PAM-hardened only)

**Responsibilities**:
1. WireGuard key pair generation for VPS and PC
2. WireGuard configuration on VPS (`/etc/wireguard/wg0.conf`)
3. WireGuard configuration on PC (`/etc/wireguard/wg0.conf`)
4. UFW rules on VPS (allow UDP/51820, deny TCP/7443 from outside, allow from 10.0.0.0/24)
5. IP forwarding enable on VPS (`net.ipv4.ip_forward=1`)
6. systemd WireGuard service activation on both ends
7. Connectivity verification (`wg show`, `ping 10.0.0.1` from PC to VPS, `ping 10.0.0.2` from VPS to PC)

**Oracle Free Tier selection rationale**:

| Property | Value / Reasoning |
|---|---|
| **Instance** | ARM Ampere A1 — 4 OCPU, 24GB RAM (free tier) |
| **Purpose** | WireGuard relay only — resource usage near zero |
| **Cost** | Free — Oracle Always Free tier |
| **Limitation** | No SLA, no guaranteed uptime, Oracle may reclaim idle accounts |
| **Acceptable use** | Development, personal testing, non-production deployment |
| **Production alternative** | Hetzner CX22 ~3.79€/month (SLA 99.9%, GDPR EU, x86) |
| **WireGuard on ARM** | Excellent: WireGuard is a kernel module, ARM crypto extensions used |

---

## 10. Cryptographic Choices — Rationale

| Algorithm | Where Used | Why |
|---|---|---|
| **Ed25519** | Command signing (client → server) | Deterministic nonce (cannot fail due to RNG). Fastest signing. 64-byte signatures. No parameter choices. Constant-time implementation standard |
| **ECDSA P-256** | TLS client/server certificates | Widely supported, good performance. Using for TLS (not direct signing) mitigates nonce-reuse risk since TLS manages nonces |
| **AES-256-GCM** | TLS session data | AEAD: confidentiality + integrity in one primitive. Hardware acceleration on most CPUs |
| **ChaCha20-Poly1305** | TLS fallback (no AES-NI) + WireGuard | AEAD alternative for devices without AES hardware acceleration. WireGuard mandates ChaCha20-Poly1305 exclusively |
| **ECDHE (P-256)** | TLS key exchange | Forward secrecy: session keys ephemeral, not derived from long-term keys |
| **Noise_IKpsk2** | WireGuard handshake | WireGuard's handshake protocol: static + ephemeral keys, identity hiding, forward secrecy every 3 minutes |
| **SHA-256** | Fingerprinting, HMAC, audit | Collision-resistant, preimage-resistant, widely implemented |
| **HMAC-SHA256** | Audit log line signing | Symmetric (audit key stays on server), fast, verifiable |
| **4096-bit RSA** | CA key only | CA key used rarely; larger RSA is acceptable since it's an offline key |

### WireGuard Cryptographic Properties

WireGuard uses a fixed, opinionated cryptographic suite with no negotiation:
- **Static key exchange**: Curve25519 ECDH
- **Session key derivation**: ChaCha20-Poly1305 AEAD
- **Handshake**: Noise_IKpsk2 (static identity + ephemeral + optional pre-shared key)
- **Key rotation**: New session keys every 3 minutes (180 seconds) automatically
- **No cipher negotiation**: zero downgrade attack surface

This is in contrast to TLS which negotiates cipher suites (and can be downgraded if misconfigured). WireGuard's simplicity is a security feature: the attack surface is the Noise protocol implementation, not a cipher negotiation state machine.

---

## 11. Key & Secret Storage Model

### What Lives Where

| Secret | Location | Accessible By | Protection |
|---|---|---|---|
| `ca.key.enc` | `~/rofi-bridge-ca/` | Only during cert issuance | AES-256 encrypted, passphrase required |
| `server.key` | `~/.config/rofi-bridge/` (disk) + Kernel Keyring (runtime) | Daemon process | `chmod 400` + Kernel Keyring API (not file-accessible) |
| `server.crt` | `~/.config/rofi-bridge/` | Daemon, anyone with access | Not secret — public cert |
| `ca.crt` | `~/.config/rofi-bridge/` | Daemon, anyone | Not secret — public cert |
| `clients/<id>/sign.pub` | `~/.config/rofi-bridge/clients/` | Daemon | Not secret — public key |
| `clients/<id>/tls.crt` | `~/.config/rofi-bridge/clients/` | Daemon | Not secret — public cert |
| `audit_hmac_key` | `~/.config/rofi-bridge/audit.key` | Daemon | `chmod 400` |
| **Ed25519 private key** | **Android Keystore (hardware-backed)** | **Only via Keystore API** | **Never exported, hardware-protected on Android 9+** |
| `tls_key` (client) | `flutter_secure_storage` | App only | Android Keystore-backed encryption |
| `tls_cert` (client) | `flutter_secure_storage` | App only | Android Keystore-backed encryption |
| `ca_cert` (client) | `flutter_secure_storage` | App only | Android Keystore-backed encryption |
| WireGuard private key (PC) | `/etc/wireguard/wg0.conf` | root only | `chmod 600`, owned root:root |
| WireGuard private key (VPS) | `/etc/wireguard/wg0.conf` | root only | `chmod 600`, owned root:root |

### Server Compromise Impact Analysis

| What attacker gets | What they can do |
|---|---|
| `server.key` | Impersonate the server to new clients (mitigated by cert pinning). Cannot forge client requests. |
| `ca.crt` | Nothing — public certificate |
| `clients/*/sign.pub` | Nothing — public keys cannot sign |
| `clients/*/tls.crt` | Nothing — public certificates |
| `audit.log` | Read command history (confidentiality concern, not integrity) |
| `audit.key` | Forge audit log entries (but not retroactively without detection) |
| **Everything combined** | **Cannot forge a single authenticated command to themselves** |

---

## 12. Accepted Residual Risks

### R1 — Physical Machine Compromise

**Risk**: Attacker with physical access can read `server.key` from disk, install keyloggers, or read kernel memory (if root).

**Mitigation**: Forward secrecy protects past TLS sessions. Kernel Keyring makes `server.key` harder to exfiltrate at rest. Hardware disk encryption (LUKS) is recommended as a complementary control.

**Accepted**: Physical access to a machine is game-over for almost any security model. PAM does not attempt to solve this.

---

### R2 — Android Device Rooting (Android Keystore without Strongbox)

**Risk**: On Android 9+ devices without a dedicated Strongbox HSM chip, the Ed25519 private key is hardware-backed but theoretically extractable by a highly privileged root exploit targeting the TEE (Trusted Execution Environment).

**Mitigation**: Android Keystore with `setIsStrongBoxBacked(true)` on devices supporting Strongbox (Android 10+, Pixel 3+, Samsung Galaxy S10+) provides hardware security module protection. The key is generated inside the HSM and never enters the normal execution environment. On non-Strongbox devices, the risk is theoretical and requires a sophisticated TEE exploit.

**Accepted**: The vast majority of modern mid-range and flagship Android devices support Strongbox. This is the state of the art for mobile key protection.

---

### R3 — Offline Brute Force of `tls_key` from Unencrypted Android Backup

**Risk**: If an unencrypted Android backup is obtained, `flutter_secure_storage` contents may be recoverable, including the TLS client key.

**Mitigation**: Recommend enabling Android encrypted backups. The Ed25519 key in the Android Keystore is **not included in Android backups** by design. The TLS client key compromise enables mTLS impersonation but still requires an Ed25519 signature for each command — defense in depth applies.

**Accepted**: Encrypted backups are a user responsibility. The critical Ed25519 key is protected by the Keystore backup exclusion.

---

### R4 — Network Time Attacks

**Risk**: If the attacker can manipulate the server's system clock, the ±30s timestamp window for replay protection is shifted, potentially allowing replayed requests within the shifted window.

**Mitigation**: NTP synchronization with a trusted server. The timestamp window is small (30s) and requires active manipulation during a very narrow window.

**Accepted**: NTP attack requires control of the network or DNS — which is already accounted for in the network threat model. On such a network, PAM-hardened's WireGuard tunnel isolates the traffic anyway.

---

### R5 — VPS Relay Compromise (PAM-hardened)

**Risk**: The Oracle Free Tier VPS relay is an internet-facing server. A full compromise of the VPS (root access, kernel exploit) gives the attacker access to the WireGuard configuration, including the VPS WireGuard static private key.

**With VPS private key, attacker capabilities**:
- Decrypt WireGuard tunnel: can see the inner TLS handshake ciphertext
- Cannot decrypt the inner TLS layer: TLS uses a separate key hierarchy
- Cannot forge commands: Ed25519 private key never leaves the Android Keystore
- Cannot impersonate the server: does not have `server.key` (lives on the PC)

**What the VPS sees even under normal operation**:
- WireGuard UDP packets — encrypted, no payload visibility
- Source IPs and timing — traffic metadata
- Total bytes transferred — coarse command frequency inference

**Mitigation**:
- WireGuard provides forward secrecy (3-minute key rotation): past recorded traffic cannot be decrypted retroactively even with VPS key compromise
- Inner TLS provides a separate independent encryption layer
- The VPS runs WireGuard only — no web services, minimal attack surface
- Oracle Free Tier ARM: automatic security updates on Ubuntu LTS recommended

**Accepted**: The VPS relay is not in the trust chain for command authentication — it is only a routing layer. Compromise of the relay does not compromise command integrity, only potentially traffic metadata. For scenarios where relay confidentiality is critical, a self-hosted VPS (Hetzner CX22) provides stronger guarantees.

---

### R6 — Open Network — AP Isolation Bypass (PAM only)

**Risk**: On networks with AP isolation (typical of public WiFi), devices cannot reach each other directly. PAM (LAN-direct) simply does not function on such networks — connections time out.

**Resolution**: This is not a security risk — it is an operational limitation. PAM-hardened solves it structurally: all traffic goes through the WireGuard relay, bypassing AP isolation entirely. The relay is reachable from any network (internet-facing VPS).

**Accepted for PAM**: PAM is documented as LAN-only. PAM-hardened is the correct variant for open networks.

---

### R7 — Clock Drift / NTP Unavailability

**Risk**: Replay protection relies on a ±30-second timestamp window validated against server time. If the PC clock drifts significantly (e.g., after a long sleep, VM suspension, or NTP outage) or the Android device clock is wrong, legitimate commands will be rejected with timestamp errors. Conversely, if both clocks drift in the same direction by more than 30 seconds, a recorded replay attack may fall outside the current valid window — but only until clocks resync.

**Resolution**:
- `setup.sh` verifies that `systemd-timesyncd` or `chronyd` is active before completing setup. Setup exits with an explicit error if no NTP service is running.
- The daemon logs timestamp rejection events to the audit log with the received and server timestamps, enabling diagnosis.
- Android's clock is managed by the OS via NTP on any internet connection. No application-level action needed.

**Residual risk**: In offline or air-gapped environments without NTP, the ±30s window must be widened manually or the timestamp check relaxed. This is an operational configuration decision and is outside the default threat model.

---

### R8 — PC Sleep and WireGuard Tunnel Interruption (PAM-hardened)

**Risk**: When the PC enters sleep or suspend, the WireGuard interface goes down. The VPS relay continues to accept packets from Android but they are not forwarded to the PC (route is unreachable). The VPS does not know the PC is offline until the WireGuard keepalive interval expires (default: 25 seconds). Commands sent during this window are silently dropped — no error is returned to the app.

**Resolution (partial)**:
- The Flutter app implements a 5-second health check timeout (`GET /health`) before sending any command. If the health check fails, the app displays an explicit "daemon unreachable" error rather than silently losing the command.
- Wake-on-LAN (WoL) can be configured as a complement: the app sends a WoL magic packet to the PC's MAC address before attempting the health check. This requires the PC to have WoL enabled in BIOS/UEFI and a network adapter that supports it.

**Accepted limitation**: Full reliability against sleep interruption requires hardware-level WoL support. This cannot be solved in software alone. The health check provides user-visible feedback instead of silent failure.

---

### R9 — Android Device Loss / Key Non-Exportability

**Risk**: Ed25519 signing keys are generated inside the Android Keystore with hardware backing (available on Android 9+, Strongbox on Android 10+). Hardware-backed keys are deliberately non-exportable and are explicitly excluded from Android backup mechanisms (including Google Backup, ADB backup, and OEM cloud backups). If the device is lost, stolen, or factory-reset, the signing key is permanently destroyed.

**Resolution**:
- This is an intentional security property, not a flaw. A non-exportable key cannot be stolen from a backup.
- Recovery procedure: revoke the lost device from the GTK GUI (`Revoke Device` → removes `clients/<device_id>/`). Re-provision a new device through the normal provisioning flow (new OTP QR on the GUI, new key pair generated on the replacement device).
- The provisioning flow is designed to be repeatable and takes under two minutes.

**Accepted limitation**: There is no backup for the signing key. This is the correct trade-off: exportable keys provide no meaningful security improvement over symmetric tokens, negating the entire asymmetric model. Users should be informed of this at provisioning time.

---

### R10 — Physical Server Compromise

**Risk**: An attacker with physical access to the PC can read `~/.config/rofi-bridge/server.key`, `ca.crt`, and all client public keys. With `server.key` they can impersonate the server in future connections (partially mitigated by the app's CA pinning — the existing app installation would reject a new server cert). They cannot forge commands without the client's Ed25519 private key (hardware-backed, non-exportable).

**Resolution**: Forward secrecy ensures past traffic cannot be decrypted even with `server.key`. The CA key is encrypted offline in `~/rofi-bridge-ca/ca.key.enc` and never loaded by the daemon. Client credentials on the server are public keys only — a server dump gives zero forging capability.

---

### R11 — TEE-less Device (securityLevel = SOFTWARE)

**Risk**: On a device without a Trusted Execution Environment (emulators, some older or budget devices, certain custom ROMs), `KeyInfo.securityLevel` returns `SOFTWARE`. The Ed25519 private key is stored inside the Android process memory, not in a hardware enclave. On a rooted device, this key is potentially extractable, which undermines the "hardware-backed non-exportable key" guarantee that is foundational to PAM's asymmetric security model.

**Resolution**:
- `checkDeviceIntegrity()` detects this condition at provisioning time and shows a `warning_level = HIGH` dialog, informing the user that the signing key will not have hardware protection.
- The user can choose to abort provisioning on this device.
- If the user proceeds despite the warning (e.g., acceptable risk for their threat model), the remaining five protocol layers (TLS, mTLS, replay protection, privilege isolation, audit) remain intact.
- In case of suspected key compromise, the device is revoked immediately from the GTK GUI.

**Accepted limitation**: PAM cannot enforce hardware-backed keys. The requirement for API 31+ (minSdk=31 in build.gradle) ensures that TEE is present on the vast majority of compliant Android 12+ devices (Google's Android CDD has mandated TEE since Android 6.0). The software-only path is a documented edge case for non-CDD-compliant devices.

---

## 13. Verification Plan

### 13.1 — TLS Security

```bash
# Verify no plain HTTP is accepted
curl http://rofi-bridge.local:7443/health  # must fail (connection refused or reset)

# Verify TLS version enforcement
openssl s_client -connect rofi-bridge.local:7443 -tls1 2>&1 | grep -c "handshake failure"  # must be 1
openssl s_client -connect rofi-bridge.local:7443 -tls1_1 2>&1 | grep -c "handshake failure"  # must be 1
openssl s_client -connect rofi-bridge.local:7443 -tls1_2 2>&1 | grep "Cipher"  # must show ECDHE

# Verify mTLS is enforced
curl -k https://rofi-bridge.local:7443/run  # must fail with 400/SSL error (no client cert)
```

### 13.2 — mTLS Functionality

```bash
# Verify valid client cert succeeds TLS layer
openssl s_client -connect rofi-bridge.local:7443 \
    -cert clients/<device_id>/tls.crt \
    -key clients/<device_id>/tls.key \
    -CAfile ca.crt 2>&1 | grep "Verify return code: 0"

# Verify revoked cert is rejected
# After revoking a device:
openssl s_client -connect rofi-bridge.local:7443 \
    -cert <revoked_cert> -key <revoked_key> -CAfile ca.crt 2>&1 | grep "revoked"
```

### 13.3 — Ed25519 Verification

```bash
# Verify unsigned request is rejected
curl -k --cert tls.crt --key tls.key https://rofi-bridge.local:7443/run \
    -d '{"payload":"ts:nonce:check_port","sig":"invalidsig"}' # must return 401

# Verify replay is rejected
# Send same valid signed request twice → second must return 401 (nonce reused)
```

### 13.4 — Privilege Isolation

```bash
# Verify ipt-helper capability
getcap /usr/lib/rofi-bridge/ipt-helper  # must show cap_net_admin+eip

# Verify no sudoers modifications
sudo cat /etc/sudoers.d/rofi-bridge 2>&1  # must return "no such file"
grep -r "rofi-bridge" /etc/sudoers.d/ 2>&1  # must return nothing

# Verify ipt-helper rejects arbitrary arguments
/usr/lib/rofi-bridge/ipt-helper "open; echo INJECTED"  # must return 1 (no execution)
/usr/lib/rofi-bridge/ipt-helper ""  # must return 1
```

### 13.5 — Audit Log Integrity

```bash
# Verify HMAC signatures on all log lines
python3 -c "
import json, hmac, hashlib
key = open('audit.key','rb').read()
for line in open('audit.log'):
    parts = line.rsplit(' sig=', 1)
    body, sig = parts[0], parts[1].strip()
    expected = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, sig), f'TAMPERED: {body}'
print('All log lines verified.')
"
```

### 13.6 — End-to-End Functional Test (PAM)

```bash
# Full flow: provisioning → command → audit
# 1. Open provisioning panel in GTK GUI → scan QR with phone
# 2. Verify device appears in clients/ directory
# 3. Send CHECK_PORT command from app → verify response
# 4. tcpdump -i wlan0 port 7443 → verify zero readable content
# 5. Revoke device → verify next app connection fails
# 6. cat audit.log → verify entry recorded for step 3
```

### 13.7 — PAM-hardened Verification

```bash
# Step 1: Verify WireGuard tunnel is established
wg show  # on both VPS and PC: must show handshake timestamp within last ~3 minutes

# Step 2: Verify routing through tunnel
ping -c 3 10.0.0.1  # from PC to VPS wg0 interface — must reach relay
ping -c 3 10.0.0.2  # from VPS to PC wg0 interface — must reach daemon host

# Step 3: Verify daemon is reachable through tunnel
curl --cacert ca.crt https://10.0.0.2:7443/health  # must return 200 (daemon on PC wg0)

# Step 4: Verify TLS traffic invisible to relay
# On VPS:
tcpdump -i eth0 port 51820 -c 20  # must show only UDP packets, zero readable TLS
tcpdump -i wg0  -c 20             # must show TLS handshake bytes — no application data

# Step 5: Functional test from open/public network
# Disconnect from home network → connect to open WiFi
# Enable WireGuard on Android → verify tunnel connects
# Send command from app → must succeed identically to LAN mode

# Step 6: Verify AP isolation bypass
# On open WiFi where direct ping to PC IP fails:
# ping <PC_LAN_IP>  # must time out (AP isolation)
# PAM-hardened command from app  # must still succeed (via VPS relay)
```

---

## 14. Deployment Variants — PAM vs PAM-hardened

### Overview

Both variants share 100% of the application code. The daemon (`bridge_v2.py`), the GTK GUI (`gui_gtk.c`), and the Flutter app are identical. The difference is in the transport substrate and the IP binding.

### Decision Matrix

| Scenario | Recommended variant |
|---|---|
| Home network with known devices, router under control | PAM |
| Network with potentially hostile devices (ARP spoofing possible) | PAM (crypto model handles it) or PAM-hardened for extra isolation |
| Network with AP isolation — devices cannot reach each other | **PAM-hardened required** |
| Open public WiFi — untrusted infrastructure | **PAM-hardened required** |
| Stable IP desired regardless of DHCP behavior | PAM-hardened (10.0.0.2 never changes) |
| No internet connectivity on PC at setup time | PAM |
| Minimal infrastructure, no cloud dependency | PAM |
| Maximum network-layer isolation | PAM-hardened |

### Technical Differences

| Property | PAM | PAM-hardened |
|---|---|---|
| **Daemon bind** | `<LAN_IP>:7443` | `10.0.0.2:7443` (wg0 PC side) |
| **Server SAN** | `IP:<LAN_IP>, DNS:rofi-bridge.local` | `IP:10.0.0.2` |
| **Client connects to** | `rofi-bridge.local:7443` or `<LAN_IP>:7443` | `10.0.0.2:7443` (PC wg0, via WireGuard tunnel) |
| **mDNS** | Optional | Disabled |
| **Port** | 7443 | 7443 (inside tunnel) |
| **External infra** | None | Oracle Free Tier VPS (WireGuard relay) |
| **AP isolation resilience** | No | Yes |
| **IP stability** | DHCP-dependent (mitigated by SAN+mDNS) | Always 10.0.0.2 (WireGuard static allocation) |
| **Tunnel overhead** | None | ~60 bytes UDP WireGuard header per packet |
| **Setup complexity** | Low | Medium (relay-setup.sh on VPS) |

### Key Insight: Why PAM Still Works on Untrusted LANs

The question "is the LAN trusted?" is mostly irrelevant to the security model. The cryptographic stack (TLS 1.3 + mTLS + Ed25519) protects against:

- **Passive sniffing**: TLS encrypts everything
- **Active MITM**: mTLS requires valid client cert; server cert fingerprint prevents substitution
- **Replay attacks**: timestamp ± 30s + one-time nonce
- **Forging commands**: Ed25519 private key in Android Keystore

What an untrusted LAN cannot do: decrypt, forge, replay, or impersonate — regardless of ARP spoofing, MITM tools, or rogue DHCP.

What an untrusted LAN **can** do that PAM-hardened solves:
1. **Block TCP/7443** — corporate firewalls, captive portals, or hostile infrastructure may block non-standard ports. Port 443 option mitigates this; PAM-hardened uses WireGuard UDP/51820.
2. **AP isolation** — prevents direct IP reachability. PAM cannot connect at all. PAM-hardened routes through the relay.
3. **mDNS suppression** — some APs filter multicast. Daemon not discoverable. Mitigated by manual IP in QR.

---

## 15. Network Threat Categories

### Category 1: Trusted LAN

**Definition**: Network where the user controls or fully trusts the infrastructure (router, switch, AP, all connected devices).

**Typical scenario**: Home network with router under user control, known connected devices.

**Threat surface**: Low. Physical LAN attacks require access to the network or a compromised device.

**PAM configuration**:
- Port 7443
- mDNS enabled (convenience)
- Manual provisioning confirmation: optional
- Global TLS handshake rate limit: standard (5 simultaneous)

**Residual threats accepted**: Compromised IoT device on same segment could attempt TLS connections. mTLS rejects all without valid client cert. Rate limiter bounds connection exhaustion.

---

### Category 2: Untrusted/Exposed LAN

**Definition**: Network shared with devices of unknown trust level. Other users may be present. Infrastructure (router, AP) may be compromised or misconfigured. Active network attacks (ARP spoofing, MITM) are possible.

**Typical scenario**: Shared apartment WiFi, office network with guests, any network with multiple users not under your control.

**Threat surface**: Medium-high.
- **Passive sniffing**: Attacker captures all WiFi frames (trivial on open networks without 802.11 encryption, harder but not impossible on WPA2 networks with known PSK)
- **ARP spoofing**: Attacker sends crafted ARP replies, routing traffic through their machine
- **Rogue DHCP**: Attacker serves different gateway/DNS, enabling redirect or DNS spoofing
- **Port scanning**: Active discovery of daemon presence, protocol probing

**Why PAM's crypto model handles it**:

| Attack | Defense |
|---|---|
| Passive sniffing | TLS 1.3 AEAD encryption — zero readable content |
| ARP MITM | mTLS: attacker has no valid client cert → TLS handshake fails before HTTP |
| MITM + cert substitution | Server cert fingerprint in provisioning QR → TOFU prevents substitution |
| Port scanning → TLS probe | mTLS: every connection attempt without valid cert closes immediately |
| DNS spoofing (hostname redirect) | mTLS + cert fingerprint: wrong cert → rejected |

**Additional operational mitigations (see Section 17)**:
- Port 443 (blends with normal HTTPS traffic, less likely to be blocked or inspected)
- mDNS disabled (IP in QR, no service announcement)
- Manual provisioning confirmation (operator physically confirms each device)
- Global TLS handshake rate limit (counters distributed port scan + probe floods)

---

### Category 3: Open Public Network

**Definition**: Network with zero infrastructure trust. WiFi without authentication (open SSID) or with shared PSK. AP isolation typically enabled (devices cannot reach each other). Unknown number of other users. Captive portal possible.

**Typical scenario**: Airport WiFi, coffee shop hotspot, hotel network, any public access point.

**Threat surface**: High.
- All Category 2 threats apply
- **AP isolation**: Devices on the same WiFi cannot initiate TCP connections to each other → PAM direct cannot connect at all
- **Port blocking**: Captive portals and network gateways often block all ports except 80, 443, sometimes 53 → TCP/7443 unreachable
- **Deep packet inspection**: Some operators inspect or throttle non-standard traffic
- **Rogue AP**: Attacker creates lookalike SSID, all traffic through attacker hardware

**PAM direct: Not functional** — AP isolation alone prevents direct connection.

**PAM-hardened: Fully functional**:

| Threat | Mitigation |
|---|---|
| AP isolation | All traffic goes through WireGuard relay (internet-reachable VPS) — AP isolation bypassed |
| Port blocking | WireGuard UDP/51820 often passes; relay can also expose TCP/443 forwarding to daemon |
| DPI | WireGuard traffic looks like encrypted UDP — no TLS fingerprint; inner TLS further obscures payload |
| Rogue AP | WireGuard authenticates relay by static public key (Curve25519) hardcoded at setup time; MITM cannot substitute — Noise_IK handshake provides identity binding |
| Network metadata | Attacker sees UDP traffic to VPS IP. Cannot determine commands, timing only |

**Provisioning on open networks**: Provisioning must happen on a trusted network (home LAN or via phone hotspot), since the provisioning QR is physically scanned and requires proximity. After provisioning, operation on any network is possible.

---

## 16. PAM-hardened Architecture — WireGuard Relay

### Why WireGuard

WireGuard was chosen over alternative VPN technologies:

| Technology | Reason not chosen |
|---|---|
| **OpenVPN** | Large codebase (100k+ LOC), TLS/PKI complexity, configuration-heavy, higher overhead |
| **IPSec/IKEv2** | Complex negotiation protocol, configuration error-prone, many cipher choices (attack surface) |
| **SSH tunnel** | Not designed as persistent tunnel, no UDP support, not suitable as always-on service |
| **SOCKS5 proxy** | No encryption at tunnel layer, proxy only |
| **Tailscale/ZeroTier** | Third-party control plane (trust dependency on vendor), closed provisioning |
| **WireGuard** | ✓ ~4,000 LOC kernel module. Fixed crypto (no negotiation). Noise protocol formally verified. Kernel-native performance. Stateless design (no connection state to track). Built-in key rotation |

### WireGuard Cryptographic Model

```
Handshake (Noise_IKpsk2):
  Initiator (Android/PC) → Responder (VPS):
    msg1 = Encrypt(ephemeral_pub || Encrypt(static_pub || hash))
  Responder → Initiator:
    msg2 = Encrypt(ephemeral_pub || Encrypt(empty || hash))
  Result: shared_session_key = ECDH(eph_i, eph_r) + ECDH(eph_i, static_r) + ECDH(static_i, eph_r)

Session data:
  Each packet: ChaCha20-Poly1305(session_key, counter, payload)
  Counter: monotonically increasing (anti-replay)

Key rotation:
  New handshake every 180 seconds (3 minutes) or after 2^60 packets
  Old session keys discarded → forward secrecy enforced
```

**Identity binding**: The VPS public key is hardcoded in the PC and Android WireGuard configurations at setup time. Even if the VPS IP changes or DNS is spoofed, the handshake fails if the responder doesn't hold the corresponding private key. This is stronger than certificate pinning for the relay layer.

### Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Internet                                         │
│                                                                         │
│  Android phone                Oracle Free Tier VPS           PC         │
│  ┌──────────────┐             ┌─────────────────┐   ┌──────────────┐   │
│  │ WireGuard    │──UDP/51820──►│ wg0: 10.0.0.1   │   │ wg0: 10.0.0.2│  │
│  │ 10.0.0.3/32  │             │ Routes:          │◄──│ Peer: VPS    │  │
│  │ Peer: VPS    │             │ 10.0.0.0/24      │   │ AllowedIPs   │  │
│  │ AllowedIPs   │             │ (kernel routing) │   │ 10.0.0.0/24  │  │
│  │ 10.0.0.0/24  │             └─────────────────┘   └──────────────┘  │
│  │              │                      │                    │           │
│  │ Flutter app  │────────────────────────────────────────────►          │
│  │ HTTPS→       │    WireGuard tunnel (E2E encrypted)       │           │
│  │ 10.0.0.2:7443│                                     bridge_v2.py      │
│  └──────────────┘                                    bound: 10.0.0.2    │
└─────────────────────────────────────────────────────────────────────────┘
```

**Routing logic**:
- Android WireGuard `AllowedIPs = 10.0.0.0/24` — only PAM traffic goes through tunnel; all other traffic (internet browsing) bypasses WireGuard (split tunnel)
- VPS routes packets between wg peers (kernel IP forwarding): `10.0.0.3 → 10.0.0.2`
- PC daemon bound to `10.0.0.2` — only reachable through WireGuard tunnel; LAN-facing interface does not expose the daemon

### Oracle Free Tier Selection

Oracle Cloud Free Tier was selected as the relay infrastructure for the PAM-hardened variant:

**Why Oracle Free Tier is acceptable for this use case**:
1. **WireGuard relay is stateless and minimal**: The VPS is a pure routing node. No data is stored. No long-lived service state. If the VPS is reclaimed, the tunnel drops and the daemon is unreachable — inconvenient but not a security event.
2. **Cost**: Zero. For development, testing, and personal use, free infrastructure is appropriate.
3. **ARM Ampere A1**: WireGuard is a Linux kernel module — ARM crypto extensions (NEON, ARMv8 crypto instructions) accelerate ChaCha20-Poly1305. Relay overhead is negligible.
4. **Redundancy**: For production use, a Hetzner CX22 (€3.79/month, SLA 99.9%) is the correct choice. The PAM-hardened design is relay-agnostic — changing VPS providers requires regenerating WireGuard keys and re-distributing peer configs.

**Limitations accepted**:
- No SLA — Oracle may reclaim idle accounts
- No guaranteed uptime
- Not suitable for production deployments where availability is required

---

## 17. Untrusted Network Mitigations

These mitigations apply to **PAM on untrusted/exposed networks** and are part of `setup.sh --untrusted-mode`. They do not change the cryptographic model — the crypto already handles untrusted networks. They reduce operational fingerprint and add depth against active scanning.

---

### 17.1 — Port 443 Instead of 7443

**Problem**

TCP/7443 is a non-standard port that:
- Is trivially identifiable as a custom HTTPS service via port scan
- Is frequently blocked by corporate firewalls and captive portals
- Creates a distinctive network fingerprint visible to passive observers

**Solution**

Bind daemon to TCP/443 on untrusted networks:

```python
# In bridge_v2.py, configurable via config.toml
PORT = int(config.get("port", 7443))  # default 7443; use 443 for untrusted mode
```

**Setup**: `setup.sh --untrusted-mode` sets `port = 443` in config.toml and adjusts `ipt-helper` accordingly. Binding to port 443 as a non-root user requires either `setcap cap_net_bind_service` on the Python interpreter (not recommended) or a kernel-level redirect via iptables:

```bash
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 7443
# Or: CAP_NET_BIND_SERVICE on the service binary
```

**How It Works**

Port 443 traffic is indistinguishable from standard HTTPS to a passive observer. Deep packet inspection would reveal the mTLS handshake (client cert extension), but this is encrypted in the TLS record layer after the initial hello — not visible as plaintext. The daemon's ALPN can be set to `h2` to further blend with standard HTTPS.

**Why This Choice**

Reducing operational fingerprint on untrusted networks decreases the likelihood of active targeting. A port 7443 service is obviously custom and invites probing; port 443 is expected to carry HTTPS traffic and blends into background noise.

**Port Conflicts**

Port 443 may already be bound by another service on the same machine — common examples: Home Assistant (default port 8123 or 443 via reverse proxy), Nextcloud, Plex, or any other HTTPS server. If a service already listens on TCP/443, `setup.sh --untrusted-mode` will detect the conflict and abort with an explicit error.

Options when port 443 is unavailable:

1. **Use port 8443**: Non-standard HTTPS port, less commonly blocked than 7443, still blends as HTTPS traffic. Set `port = 8443` in config.toml. Slightly higher fingerprinting risk than 443 but avoids all conflicts. **This is the recommended option when port 443 is unavailable.**
2. **nginx TCP stream passthrough**: nginx listens on port 443 and forwards raw TCP to PAM on 7443. The TLS session is end-to-end between Android and PAM — nginx is a transparent pipe. mTLS is fully preserved.

```nginx
# /etc/nginx/nginx.conf — add at top level, OUTSIDE the http {} block
# Requires ngx_stream_core_module (standard since nginx 1.9.0)
stream {
    server {
        listen 443;
        proxy_pass 127.0.0.1:7443;
    }
}
```

> **WARNING — do NOT use HTTP `proxy_pass` (layer 7) with PAM.**
> An `http { location / { proxy_pass https://127.0.0.1:7443; } }` block terminates the TLS session at nginx. nginx opens a *separate* TLS connection to the backend — the Android client certificate is never forwarded to the daemon. The daemon sees nginx's certificate instead, breaking device identity verification (Layer 2 — mTLS) and the entire `device_id` extraction chain. The system silently degrades to Layer 3 only (Ed25519 signature), which violates the defence-in-depth model.

**Limitation of stream passthrough**: because nginx does not inspect TLS, it cannot route by SNI. Port 443 can only forward to one backend. If multiple services must share port 443, use port 8443 for PAM instead.

The default recommendation for untrusted-mode on a dedicated machine is port 443 (iptables redirect). On a machine running other HTTPS services, **8443 is the preferred alternative**.

---

### 17.2 — mDNS Disabled

**Problem**

mDNS multicast announcements (`_rofi-bridge._tcp.local`) are broadcast to the entire LAN segment. On untrusted networks, this:
- Reveals the daemon's presence, IP, and port to all devices
- Identifies the machine as running PAM specifically
- Provides a ready target for automated scanners

**Solution**

Disable `zeroconf` / Avahi entirely in untrusted mode:

```python
# In bridge_v2.py
if not config.get("mdns_enabled", True):
    # Skip Zeroconf registration entirely
    zeroconf_instance = None
```

The provisioning QR embeds the IP address directly:
```python
addr = config.get("server_addr")  # manually configured, e.g., "192.168.1.100:443"
qr_payload = json.dumps({"addr": addr, "otp": otp, "fp": fingerprint})
```

**How It Works**

Without mDNS registration, the daemon has zero network-discoverable presence beyond TCP SYN responses on its bound port. The IP must be known in advance (from QR provisioning or manual configuration). This converts the service from "discoverable" to "known endpoint only."

**Why This Choice**

On a trusted home network, mDNS convenience outweighs the minimal fingerprint risk. On an untrusted network, the convenience is irrelevant (the IP will be embedded in the QR at provisioning time anyway) while the fingerprint risk is material.

---

### 17.3 — Manual Provisioning Confirmation

**Problem**

On untrusted networks, an attacker who obtains a valid OTP (via QR photograph, screen recording, or camera shoulder-surfing) within the 60-second TTL window could initiate a provisioning request from their own device. The server cannot distinguish between the intended phone and the attacker's device at the OTP verification stage.

**Solution**

GUI GTK shows a **confirmation dialog** that the operator must explicitly dismiss before the OTP is activated:

```
Provisioning Request Received
──────────────────────────────
Device ID:  a3f2c91b7d8e4012
Public Key: Ed25519 0x4a3f...9d2c
Remote IP:  192.168.1.47
Timestamp:  2026-03-17 15:23:07

[ ACCEPT ]   [ REJECT ]
```

The OTP is generated and the QR is displayed, but the `/provision` endpoint does not process any incoming request until the operator clicks Accept. The provisioning handler:

```python
class ProvisioningStore:
    def __init__(self):
        self._pending  = {}  # otp → expires_at
        self._accepted = set()  # otp → operator confirmed

    def await_confirmation(self, otp: str):
        # Called after /provision request received — blocks until GUI confirms
        self._pending_confirm[otp] = threading.Event()
        return self._pending_confirm[otp].wait(timeout=30)

    def confirm(self, otp: str):  # called by GUI Accept button
        if otp in self._pending_confirm:
            self._pending_confirm[otp].set()
```

**How It Works**

The provisioning flow becomes a two-phase commit:
1. App sends `/provision` request (OTP + public key)
2. Server suspends handler, notifies GUI
3. Operator reviews device_id and public key in GUI, clicks Accept or Reject
4. Server resumes handler and completes or rejects provisioning

**Why This Choice**

Physical proximity at provisioning time is the root of trust. The confirmation dialog enforces this: the operator must see who is being provisioned. On trusted home networks, this extra step can be disabled (`confirm_provisioning = false` in config). On untrusted networks, it closes the OTP-interception attack vector entirely.

---

### 17.4 — Global TLS Handshake Rate Limit

**Problem**

Per-IP rate limiting (problem 5.16) is effective against attacks from a single source. On untrusted or open networks, an attacker may distribute probing across many source IPs — or the daemon may be reachable by many unknown devices, each triggering TLS handshakes. TLS handshake is computationally expensive on the server side (asymmetric crypto operations). A flood of incomplete handshakes can exhaust CPU without triggering the per-IP limiter.

**Solution**

A **global** handshake rate limit, independent of source IP:

```python
import time, threading

class GlobalHandshakeLimiter:
    def __init__(self, max_per_second: int = 5):
        self._max = max_per_second
        self._times = []
        self._lock  = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._times = [t for t in self._times if now - t < 1.0]
            if len(self._times) >= self._max:
                return False
            self._times.append(now)
            return True

# In TCP accept loop:
if not global_hs_limiter.allow():
    conn.close()  # drop before SSL wrap — no handshake resources consumed
    continue
```

**How It Works**

The accept loop checks the global limiter **before** calling `ssl.wrap_socket()`. A rejected connection sees a TCP RST or FIN with no TLS bytes sent — zero server-side crypto cost. This caps the total handshake load regardless of the number of source IPs involved.

**Why This Choice**

TLS 1.3 handshakes on a modern CPU take ~0.5-2ms server-side (ECDHE + certificate verification). At 5 handshakes/second, worst case CPU load from handshakes is ~1%. At 100 handshakes/second (distributed scan), it becomes ~10-20% CPU load just for rejected connections. The global limiter caps this at 5/s = negligible overhead, regardless of attack distribution. On trusted networks, the limit can be relaxed or removed.

---

---

## 18. Implementation Notes — Critical Pitfalls

This section documents implementation-time failure modes that are not obvious from the architecture description but have caused silent failures or security gaps in practice. Each pitfall includes the symptom, root cause, and the mitigation already incorporated in this design.

---

### 18.1 — Nonce Cache Volatility

**Symptom**: After a daemon restart, replayed commands from within the previous ±30s window are accepted.

**Root cause**: An in-memory nonce cache (dict, LRU, or deque) is cleared on every process exit. An attacker who captures a valid signed request can restart the daemon (requires local access or a crash trigger) and replay it within the timestamp window.

**Mitigation in this design**: The nonce cache is stored in SQLite (`nonces.db`) in the same directory as server keys. Every accepted nonce is written to the database before the command is executed. On startup, the daemon purges entries older than 5 minutes (TTL) and loads the remaining valid set into memory. The in-memory cache is authoritative at runtime; the database is the persistence layer.

```python
# On nonce check (simplified)
def check_and_store_nonce(nonce: str, ts: float) -> bool:
    with sqlite3.connect(NONCE_DB) as db:
        try:
            db.execute("INSERT INTO nonces (nonce, ts) VALUES (?, ?)", (nonce, ts))
            db.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate — replay

# On startup
def purge_expired_nonces():
    cutoff = time.time() - 300  # 5 minutes
    with sqlite3.connect(NONCE_DB) as db:
        db.execute("DELETE FROM nonces WHERE ts < ?", (cutoff,))
        db.commit()
```

The `nonces` table has a UNIQUE constraint on the `nonce` column. Insertion failure indicates a replay.

---

### 18.2 — setcap Fragility After System Updates

**Symptom**: After a system package update that replaces the `ipt-helper` binary, iptables commands silently fail. The daemon starts successfully but cannot open or close ports.

**Root cause**: Linux capabilities (`cap_net_admin+eip`) are stored as extended attributes on the binary inode. When a package manager overwrites the binary with a new inode (even if the content is identical), the extended attributes are gone. The daemon does not detect this at startup — it only fails when `ipt-helper` is actually invoked.

**Mitigation in this design**: `pam-setcap.service` is a systemd oneshot unit that runs at every boot, before `rofi-bridge.service`. It checks whether the capability is present and re-applies it if not:

```ini
[Unit]
Description=PAM ipt-helper capability guard
Before=rofi-bridge.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'getcap /usr/lib/rofi-bridge/ipt-helper | grep -q cap_net_admin || setcap cap_net_admin+eip /usr/lib/rofi-bridge/ipt-helper'
RemainAfterExit=yes

[Install]
WantedBy=default.target
```

`setup.sh` installs and enables this unit as part of the setup procedure. This makes setcap application idempotent across system updates.

---

### 18.3 — CA Key Online During Runtime

**Symptom**: If `ca.key` remains accessible on the filesystem while the daemon is running, a compromise of the daemon process yields the CA key, allowing issuance of arbitrary client certificates.

**Root cause**: The CA key is only needed during provisioning (to sign client TLS certificates). Keeping it readable by the daemon process at runtime is unnecessary privilege.

**Mitigation in this design**: `setup.sh` signs the server certificate with the plaintext CA key *before* encrypting it, then immediately encrypts (`openssl pkcs8 -topk8 -v2 aes256`) and moves the encrypted file to `~/rofi-bridge-ca/ca.key.enc`, outside the daemon's working directory. The plaintext key is shredded (`shred -u ca.key`). Provisioning operations (signing new client certs) are performed by `gui_gtk.c`, which prompts for the CA key passphrase at provisioning time. The daemon (`bridge_v2.py`) never reads or needs the CA key.

---

### 18.4 — Server Certificate SAN Mismatch

**Symptom**: TLS handshake fails with `certificate verify failed: hostname mismatch` on the Android app, even though the CA is trusted.

**Root cause**: TLS clients verify that the server certificate's Subject Alternative Names include the address they connected to. If the SAN lists a hostname (`rofi-bridge.local`) but the app connects by IP, or lists a different IP than the one used, verification fails.

**Requirements**:
- **PAM**: SAN must include both `DNS:rofi-bridge.local` (for mDNS) and `IP:<LAN_IP>` (for direct IP connections and untrusted mode where mDNS is disabled).
- **PAM-hardened**: SAN must include `IP:10.0.0.2` (PC WireGuard interface). The LAN IP is not used because the app connects through the tunnel to the WireGuard address.

`setup.sh` generates the SAN extension automatically based on the detected LAN IP and hostname. The `--hardened` flag switches the SAN to `IP:10.0.0.2`. Regenerating the server certificate (and re-provisioning all clients) is required whenever the machine's IP changes.

---

### 18.5 — Port 443 Binding Without Capability

**Symptom**: Daemon fails to start with `PermissionError: [Errno 13] Permission denied` when `port = 443` is set in config.toml.

**Root cause**: On Linux, binding to ports below 1024 requires `CAP_NET_BIND_SERVICE`. The Python interpreter does not have this capability by default. Running the daemon as root to work around this is not acceptable.

**Mitigation in this design**: `setup.sh --untrusted-mode` installs an iptables PREROUTING/OUTPUT redirect rule that maps TCP/443 to TCP/7443, so the daemon continues to bind on 7443 and the kernel redirects traffic transparently:

```bash
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 7443
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 7443
```

These rules are persisted via `iptables-save` or `nftables` equivalent and restored at boot. This avoids granting `CAP_NET_BIND_SERVICE` to the Python process.

---

## 19. Comparison with Existing Solutions

This section compares PAM with commonly used alternatives for remote execution from a mobile device. The comparison is based on the specific requirements: low-latency command dispatch, zero-install infrastructure, hardware-backed authentication, and operation on untrusted networks.

---

### 19.1 — Comparison Table

| Criterion | PAM | SSH + Key | Tailscale + SSH | Home Assistant | Tasker + HTTP |
|---|---|---|---|---|---|
| **Authentication** | mTLS + Ed25519 HW Keystore | SSH key (software, exportable) | SSH key + Tailscale ACL | Username/password or token | Bearer token or none |
| **Key storage** | Android Keystore (hardware-backed, non-exportable) | Filesystem (exportable) or software keychain | Filesystem (exportable) | Credential store (varies) | Plaintext or base64 |
| **Transport** | TLS 1.3, ECDHE, forward secrecy | SSH (OpenSSH cipher negotiation) | Wireguard (Tailscale) + SSH | HTTPS (Let's Encrypt) | HTTP or HTTPS |
| **mTLS** | Yes — bidirectional cert verification | No | No | No | No |
| **Replay protection** | Timestamp + persistent nonce cache (SQLite) | Implicit (SSH session state) | Implicit (SSH session state) | No | No |
| **Audit log** | Append-only, HMAC per line, server signing key | sshd logs (not integrity-protected) | sshd logs | HA logs (not integrity-protected) | None |
| **Privilege model** | setcap on C binary, zero sudoers | Full shell access by default | Full shell access by default | Root/sudo via scripts | subprocess.Popen |
| **Command whitelist** | Enum-validated, zero free-form execution | None — arbitrary shell access | None — arbitrary shell access | Configurable automations | None |
| **AP isolation bypass** | PAM-hardened: WireGuard relay | No (requires direct access) | Yes (Tailscale relay network) | Requires public exposure | No |
| **Mobile client** | Custom Flutter app, purpose-built | SSH client app (Termius, JuiceSSH, etc.) | Tailscale app + SSH client | HA mobile app | Tasker plugin |
| **Infrastructure** | Self-hosted daemon + optional VPS relay | Self-hosted SSH server | Tailscale relay network (SaaS) | Self-hosted HA instance | Self-hosted HTTP server |
| **Setup complexity** | High (CA, certs, setcap, provisioning) | Low (ssh-keygen, authorized_keys) | Medium (Tailscale account + install) | High (HA install + automations) | Low (HTTP server + token) |
| **Open source / self-contained** | Yes — no external SaaS dependencies in PAM | Yes | Partially (Tailscale relay is proprietary SaaS) | Yes | Yes |
| **Network exposure** | Port 7443/443 on LAN only (or WG tunnel) | Port 22 on LAN (or internet if forwarded) | WireGuard to Tailscale relays | Port 8123/443 on LAN or internet | Port varies |

---

### 19.2 — SSH + Key

**Why it is not used**: SSH gives unrestricted shell access. There is no built-in command whitelist, no per-command audit log with cryptographic integrity, no hardware-backed key requirement, and no replay protection beyond TCP session state. An SSH key stored in a software keychain on Android is exportable from a rooted device. SSH also exposes a full interactive shell — the threat model is significantly broader than a whitelist of discrete commands.

**Where SSH is appropriate**: When full remote shell access is the requirement (development, system administration). PAM is not a replacement for SSH — it is a purpose-built command dispatcher with a narrower, more constrained interface.

---

### 19.3 — Tailscale + SSH

**Strengths**: Tailscale provides a WireGuard-based overlay network with MagicDNS, handles NAT traversal automatically (including AP isolation bypass via DERP relays), and integrates with ACL policies. The VPN layer is solid.

**Why it is not used**:
- Tailscale relay infrastructure is proprietary SaaS. The DERP relay layer is partially open source but the coordination server is not. Traffic metadata is visible to Tailscale.
- Still provides full SSH shell access — same command-whitelist and audit concerns as plain SSH.
- Requires a Tailscale account and an internet-facing coordination server. PAM-hardened requires only a standard VPS and standard WireGuard (kernel module, no SaaS dependency).
- Key management is handled by Tailscale's PKI, not hardware-backed device keys.

**Where Tailscale is appropriate**: When the goal is secure remote access to a home network for general use. PAM-hardened solves a narrower problem (authenticated command dispatch) with stronger guarantees on the authentication layer.

---

### 19.4 — Home Assistant

**Strengths**: Mature ecosystem, mobile app, support for complex automations, active community.

**Why it is not used**: Home Assistant is a home automation platform, not a command dispatcher. Using it as a remote execution layer for arbitrary system commands (iptables, network management) requires running scripts or shell commands as automations — which reintroduces unconstrained execution. Authentication in HA uses long-lived access tokens stored in the mobile app credential store, not hardware-backed keys. There is no per-command signing. Audit logging is a general-purpose event log, not an integrity-protected record.

**Where Home Assistant is appropriate**: Home automation use cases (lights, sensors, smart devices). For system-level command dispatch with a strong security model, it is not the right layer.

---

### 19.5 — Tasker + HTTP

**Why it is not used**: No authentication model beyond a bearer token in plaintext or base64. No mTLS. No command signing. No replay protection. Intended for local automation, not for use over untrusted networks. Mentioned only for completeness — not a serious alternative for the threat model addressed by PAM.

---

### 19.6 — Design Rationale Summary

PAM occupies a specific position: it is the correct tool when the requirement is **authenticated, audited, whitelisted command dispatch from a mobile device**, with a threat model that includes:

- Untrusted LAN or public WiFi (PAM-hardened)
- Hardware-backed device authentication with non-exportable keys
- Zero trust at every layer — no shared secrets, no implicit trust from network position
- Minimal privilege — the daemon cannot execute arbitrary code, only a fixed enum of commands
- Cryptographic audit trail — log entries are signed, not just recorded

No existing off-the-shelf tool satisfies all of these simultaneously. SSH provides shell access but not the constrained interface. Tailscale provides the network layer but not the authentication model. Home Assistant provides the mobile UX but not the security model. PAM is a purpose-built composition of well-established primitives (TLS, mTLS, Ed25519, WireGuard, SQLite) assembled to address a specific threat model.

---

---

## 20. Android Client Security Hardening

This section documents the three client-side security measures implemented in `MainActivity.kt` and the Dart layer (commit 636b0e7, 2026-03-20). These measures are independent of and complementary to the six network security layers.

---

### 20.1 — Screen Protection (FLAG_SECURE)

**Problem addressed**: the provisioning screen displays a QR code containing the OTP and server fingerprint. A screenshot, screen recording, or screen sharing session that captures this screen exposes a short-lived but sensitive provisioning token. The home screen reveals the available command set.

**Solution**: `WindowManager.LayoutParams.FLAG_SECURE` is set in `MainActivity.onCreate()`, before the Flutter engine initializes. This marks the Activity's graphics layer as protected content at the SurfaceFlinger (compositor) level.

Effects:
- Screenshots: black image
- Screen recording via MediaProjection API: black frames
- Screen sharing in video calls: receiver sees a black rectangle
- Recent apps thumbnail: black image

The flag propagates to all screens (home, provisioning, settings) because it is set at the Activity level, not per-screen. No screen transition can leave the app unprotected.

**Relationship to Widevine DRM**: Widevine L1 adds a Protected Memory Path for encrypted video bytes in the hardware decoder pipeline. It is specific to DRM content and irrelevant to PAM. FLAG_SECURE is the correct and sufficient mechanism.

---

### 20.2 — Biometric Authentication Gate

**Problem addressed**: if an unauthorized person obtains physical access to an unlocked phone, they can send commands without any authentication barrier beyond the mTLS and Ed25519 layers, which are transparent to the user at the UI level.

**Solution**: optional per-command authentication via `BiometricPrompt`. Configurable in the Settings screen. When enabled, every command tap triggers a system biometric prompt before the Ed25519 signing operation is called.

**Implementation — soft-gate approach**:

The key is generated without `setUserAuthenticationRequired(true)`. The BiometricPrompt appears before the sign call; if authentication succeeds, `sign()` is called. This is a soft-gate (application-level) rather than a hard-gate (TEE-level with CryptoObject).

Rationale for soft-gate:
1. The biometric option can be enabled/disabled at any time without re-provisioning the device. A hard-gate would require regenerating the key and re-provisioning.
2. If the biometric sensor becomes temporarily unavailable, the user can disable the option and continue. With a hard-gate, the key would be inaccessible until the sensor recovers.
3. For the threat model addressed (unauthorized access on an unlocked phone on a non-rooted device), soft-gate provides equivalent practical protection.

**Authenticators**:

```
BIOMETRIC_STRONG | DEVICE_CREDENTIAL
```

BIOMETRIC\_STRONG is required (hardware-backed fingerprint or 3D face recognition). DEVICE\_CREDENTIAL (PIN/password/pattern) is the automatic fallback when strong biometric is unavailable or fails. BIOMETRIC\_WEAK (2D face recognition) is explicitly excluded.

**Availability checking**:

`getBiometricAvailability()` queries `BiometricManager.canAuthenticate()` for each authenticator type and returns a structured map. The Settings screen displays a status string tailored to the specific unavailability reason (NO\_HARDWARE / HW\_UNAVAILABLE / NONE\_ENROLLED / SECURITY\_UPDATE\_REQUIRED).

**Async result pattern**:

BiometricPrompt callbacks execute on the main executor asynchronously relative to the MethodChannel call. The `MethodChannel.Result` object is stored in instance fields `pendingSignResult`, `pendingSignAlias`, `pendingSignData` and completed in `onAuthenticationSucceeded()`. A `return@setMethodCallHandler` guard in the channel handler prevents the outer try-catch from completing the Result before the async callback fires.

---

### 20.3 — Device Integrity Check

**Problem addressed**: PAM's security model assumes that the Android Keystore is hardware-backed (TEE or StrongBox). On a device without TEE (securityLevel = SOFTWARE), the Ed25519 private key is stored in the Android process and is potentially extractable with root access. Additionally, a device with an unlocked bootloader and unofficial firmware may have a modified system. The user should be informed of these conditions at provisioning time.

**Solution**: `checkDeviceIntegrity()` is called before proceeding with provisioning. It returns `{security_level, has_strong_box, is_test_keys, warning_level}`. If `warning_level != NONE`, a dialog is shown with appropriate text. The user can choose to cancel or continue.

**Why not Google Play Integrity API**:

Play Integrity API provides three verdict levels (MEETS\_BASIC\_INTEGRITY, MEETS\_DEVICE\_INTEGRITY, MEETS\_STRONG\_INTEGRITY) but requires Google Play Services, an active internet connection, and a call to Google's infrastructure. PAM is a fully self-hosted system with no external service dependencies. An integrity check that requires phoning home to Google at provisioning time contradicts this design principle. Additionally, Play Integrity does not work on de-Googled devices or AOSP builds without GApps.

The Keystore-based check operates entirely offline via local hardware APIs and is sufficient for the stated purpose.

**Implementation**:

```kotlin
// Probe TEE security level
val kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore")
kpg.initialize(KeyGenParameterSpec.Builder(tempAlias, PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(DIGEST_SHA256).build())
val keyInfo = KeyFactory.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore")
    .getKeySpec(kpg.generateKeyPair().private, KeyInfo::class.java)

// keyInfo.securityLevel:
// SECURITY_LEVEL_STRONG_BOX          → dedicated secure element
// SECURITY_LEVEL_TRUSTED_ENVIRONMENT → TEE in main processor
// SECURITY_LEVEL_UNKNOWN_SECURE      → treated as TRUSTED_ENVIRONMENT
// (other)                            → SOFTWARE (no TEE)
```

A separate probe attempts key generation with `setIsStrongBoxBacked(true)` to detect StrongBox presence. Both temporary keys are deleted immediately after the probe.

**Warning levels**:

| Condition | warning_level | Implication |
|---|---|---|
| TEE or StrongBox, no test-keys | NONE | Normal operation |
| test-keys in Build.TAGS | MEDIUM | Unofficial firmware; TEE still present and key is hardware-backed |
| securityLevel = SOFTWARE | HIGH | No TEE; signing key is software-only; extractable with root |

**Limitation — full attestation chain**:

The current implementation does not perform a full `setAttestationChallenge()` attestation. Full attestation would read `verifiedBootState` and `bootloaderLocked` from the ASN.1 extension in the attestation certificate chain, providing a stronger root-of-trust guarantee. This requires server-side verification of the certificate chain against the Google device attestation root CA. Not implemented in v1; documented as a future extension.

---

### 20.4 — Interaction Between the Three Measures

FLAG\_SECURE is always active, unconditionally, from the moment the Activity starts. It requires no configuration and has no interaction with authentication state.

The biometric gate is checked per-command, only when the preference is enabled. It reads from EncryptedSharedPreferences (Jetpack, key in Android Keystore). The gate is independent of FLAG\_SECURE and of the integrity check.

The integrity check runs once at provisioning, before any cryptographic operation. It has no effect on runtime command sending. The result of the check is not persisted — each provisioning session runs a fresh check.

---

### 20.5 — Residual Risk (added to Section 12)

**R11 — TEE-less device (securityLevel = SOFTWARE)**:

If `checkDeviceIntegrity()` reports `warning_level = HIGH` and the user proceeds, the Ed25519 private key is stored in the Android process memory and is accessible to a process with root privileges. This undermines the "hardware-backed non-exportable key" guarantee that is central to PAM's security model. Mitigation: the warning dialog makes this explicit. Revoking the device from the server immediately removes its access regardless of key state.

---

*Document generated from security analysis sessions, 2026-03-17.*
*Version 1.0: Core architecture (20 security problems, full asymmetric model).*
*Version 2.0: Extended with deployment variants, network threat categories, PAM-hardened WireGuard architecture, untrusted network mitigations.*
*Version 3.0 (2026-03-18): WireGuard topology correction (PC wg0 = 10.0.0.2, VPS = 10.0.0.1 routing hub only). Added: nonce cache SQLite persistence (C1), pam-setcap.service guard (C2), Flutter VPS fallback logic (C3), NTP prerequisite check (C4), PC sleep/WoL limitation (R8), Android key non-exportability (R9), port 443 conflict handling and 8443 alternative (Section 17.1), Section 18 (Implementation Pitfalls), Section 19 (Comparison with existing solutions).*
*Version 3.1 (2026-03-20): Android client security hardening — FLAG_SECURE, BiometricPrompt soft-gate, device integrity check (Section 20). Updated version and status in header. Added R11 (TEE-less device) to residual risks.*
