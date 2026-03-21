# PAM — Panel Access Manager

PAM is an application for controlling a Linux computer from an Android phone, including from public networks or away from home. Wake the machine, open or close the firewall, restart a service, shut it down — one tap, no passwords stored anywhere, no third-party cloud involved.

---

## The starting point

Existing remote control tools — TeamViewer, AnyDesk, and the rest — all work the same way: there's a shared secret (a password, a shared key) sitting on both the phone and the computer. Steal the computer, and you already have what you need to impersonate the owner.

PAM works differently: **the computer knows none of the phone's secrets**. It only knows the phone's "identity value" — a public piece of data, useless on its own. The only sensitive piece, the one that actually authorises commands, lives inside the phone's hardware security chip. It's generated there, it stays there, and it cannot be extracted by any means, including physical access to the device.

---

## How it works

The first time, a QR code is shown on the PC — valid for 60 seconds, one use only. The app scans it, the phone's chip generates its "authority value" internally and shares only the public counterpart with the PC. The PC issues a digital identity document for that specific phone — think of it as a personalised badge — and from that point the two recognise each other. The QR is burned.

Every time a command is sent, the phone's chip signs it with that authority value, an operation that requires the user's biometrics (fingerprint or face). The signature is unique to that exact command at that exact moment: capturing and resending it does nothing. The PC checks the signature, the identity, the timestamp, and whether the message has already been received. If everything lines up, the command runs. Otherwise it's rejected.

---

## Security

| | |
|---|---|
| Encrypted channel | All traffic between phone and PC is unreadable to anyone on the same network |
| Mutual recognition | The PC verifies the phone, and the phone verifies it's talking to the right PC — through a verification code established at setup |
| Hardware signature | Every command is signed inside the phone's chip. Without the user's biometrics, nothing gets signed |
| One-time codes | Every message carries a single-use code: intercepting and replaying it has no effect |
| Time window | Only messages timestamped within 30 seconds are accepted — protects against anyone trying to delay or replay captured traffic |
| Signed audit log | Every operation is logged with a signature produced by a key the service itself doesn't hold — the log can't be tampered with even by someone with server access |
| No shared secrets | The PC holds nothing that would allow impersonating the phone |
| Screen protection | The app blocks screenshots, screen recording, and screen sharing — same mechanism used by banking apps |

---

## Two versions

**PAM** is for home networks or trusted environments. A single setup script handles everything automatically in a few minutes.

**PAM-hardened** works from anywhere — public Wi-Fi, mobile data, restrictive corporate networks. Traffic goes through a cloud relay server (an inexpensive or free VPS) acting as a bridge between phone and PC. The bridge sees only encrypted data — it can't read anything or impersonate either side. The connection to the bridge is itself protected by a second encryption layer, the same one used by modern VPNs. Two tunnels, no readable traffic at any point.

---

## Who it's for

Anyone running Linux machines independently — enthusiasts, homelab operators, IT professionals — who wants serious remote control without depending on external service accounts, without recurring costs, and without their data passing through someone else's infrastructure.

---

## Under the hood

Android app in Flutter, PC service in Python 3, graphical interface in C with GTK3. The hardened variant uses WireGuard for the tunnel. The relay server can be any Linux VPS, including free tiers.
