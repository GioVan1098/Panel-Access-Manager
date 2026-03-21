#!/usr/bin/env python3
"""
bridge_v2.py — PAM daemon

HTTPS server with mTLS, Ed25519 command verification,
SQLite nonce cache (replay-safe across restarts), and HMAC audit log.

Start: python3 bridge_v2.py
       (managed by systemd user service rofi-bridge.service)
"""

import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import sqlite3
import ssl
import subprocess
import shutil
import sys
import tempfile
import threading
import time
from typing import Optional

try:
    import tomllib           # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

try:
    from attestation import verify_attestation, AttestationResult
    _ATTESTATION_AVAILABLE = True
except ImportError:
    _ATTESTATION_AVAILABLE = False

# ── Paths ──────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
HOME         = os.path.expanduser("~")
CONFIG_DIR   = os.path.join(HOME, ".config", "rofi-bridge")
CONFIG_FILE  = os.path.join(CONFIG_DIR, "config.toml")
NONCE_DB       = os.path.join(CONFIG_DIR, "nonces.db")
AUDIT_LOG      = os.path.join(CONFIG_DIR, "audit.log")
AUDIT_SIGN_KEY = os.path.join(CONFIG_DIR, "audit_sign.key")
PENDING_OTPS = os.path.join(CONFIG_DIR, "pending_otps.json")
SERVER_KEY   = os.path.join(CONFIG_DIR, "server.key")
SERVER_CRT   = os.path.join(CONFIG_DIR, "server.crt")
CA_CRT       = os.path.join(CONFIG_DIR, "ca.crt")
CA_KEY_ENC   = os.path.join(HOME, "rofi-bridge-ca", "ca.key.enc")
CLIENTS_DIR  = os.path.join(CONFIG_DIR, "clients")
REVOKED_FILE = os.path.join(CONFIG_DIR, "revoked.txt")
IPT_HELPER   = "/usr/lib/rofi-bridge/ipt-helper"

VERSION = "2.1.0"

# ── Constants ──────────────────────────────────────────────────────────
CHALLENGE_TTL    = 120   # seconds: attestation challenge expiry
TIMESTAMP_WINDOW = 30    # seconds: replay window
NONCE_TTL        = 300   # seconds: nonce expiry
RATE_LIMIT_REQ   = 10    # requests per window
RATE_LIMIT_WIN   = 60    # seconds
BAN_AFTER        = 3     # auth failures before ban
BAN_DURATION     = 3600  # ban duration in seconds
HS_LIMIT_PER_SEC = 5     # global TLS handshake limit (untrusted mode)

# ── Whitelisted commands ───────────────────────────────────────────────
# Each value is the argv list passed to subprocess — no shell, no injection.
COMMANDS: dict[str, list[str]] = {
    "lock":            ["loginctl", "lock-session"],
    "suspend":         ["systemctl", "suspend"],
    "reboot":          ["systemctl", "reboot"],
    "shutdown":        ["systemctl", "poweroff"],
    "wifi_on":         ["nmcli", "radio", "wifi", "on"],
    "wifi_off":        ["nmcli", "radio", "wifi", "off"],
    "volume_up":       ["pactl", "set-sink-volume", "@DEFAULT_SINK@", "+5%"],
    "volume_down":     ["pactl", "set-sink-volume", "@DEFAULT_SINK@", "-5%"],
    "mute":            ["pactl", "set-sink-mute",   "@DEFAULT_SINK@", "toggle"],
    "iptables_check":  [IPT_HELPER, "check"],
    "iptables_open":   [IPT_HELPER, "open"],
    "iptables_close":  [IPT_HELPER, "close"],
    "daemon_status":   ["systemctl", "--user", "is-active",  "rofi-bridge"],
    "daemon_start":    ["systemctl", "--user", "start",      "rofi-bridge"],
    "daemon_stop":     ["systemctl", "--user", "stop",       "rofi-bridge"],
    "daemon_restart":  ["systemctl", "--user", "restart",    "rofi-bridge"],
}


# ── Attestation challenge store (in-memory, TTL = CHALLENGE_TTL) ───────
# Maps base64-challenge → expiry timestamp (float).
# Challenges are single-use: consumed when the client calls /provision.
_challenge_store: dict = {}
_challenge_lock = threading.Lock()


def _challenge_store_cleanup() -> None:
    """Remove expired challenges (called inline, no dedicated thread needed)."""
    now = time.time()
    expired = [k for k, exp in _challenge_store.items() if exp < now]
    for k in expired:
        del _challenge_store[k]


def issue_challenge() -> str:
    """Generate a fresh attestation challenge, store it, return base64 string."""
    raw = secrets.token_bytes(32)
    b64 = base64.b64encode(raw).decode()
    with _challenge_lock:
        _challenge_store_cleanup()
        _challenge_store[b64] = time.time() + CHALLENGE_TTL
    return b64


def consume_challenge(b64: str) -> Optional[bytes]:
    """Consume challenge if valid and not expired. Returns raw bytes or None."""
    with _challenge_lock:
        exp = _challenge_store.get(b64)
        if exp is None or exp < time.time():
            return None
        del _challenge_store[b64]
    try:
        return base64.b64decode(b64)
    except Exception:
        return None


# ── Config ─────────────────────────────────────────────────────────────
def load_config() -> dict:
    defaults: dict = {
        "port":       7443,
        "bind":       "",        # empty → detect LAN IP
        "mode":       "direct",  # "direct" | "hardened"
        "untrusted":  False,
        "mdns":       True,
    }
    if not os.path.exists(CONFIG_FILE):
        return defaults
    try:
        with open(CONFIG_FILE, "rb") as f:
            data = tomllib.load(f) if tomllib else {}
        defaults.update(data)
    except Exception as e:
        logging.warning("Config parse error: %s — using defaults", e)
    return defaults


# ── Nonce cache (SQLite — survives daemon restarts) ────────────────────
_nonce_lock = threading.Lock()


def init_nonce_db() -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with sqlite3.connect(NONCE_DB) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                ts    REAL NOT NULL
            )
        """)
        db.commit()
        # Purge expired entries at startup
        db.execute("DELETE FROM nonces WHERE ts < ?", (time.time() - NONCE_TTL,))
        db.commit()


def _nonce_cleanup_loop() -> None:
    """Background thread: periodically purge expired nonces."""
    while True:
        time.sleep(NONCE_TTL)
        try:
            with sqlite3.connect(NONCE_DB) as db:
                db.execute("DELETE FROM nonces WHERE ts < ?", (time.time() - NONCE_TTL,))
                db.commit()
        except Exception:
            pass


def check_and_store_nonce(nonce: str, ts: float) -> bool:
    """Returns True if nonce is new (not a replay)."""
    with _nonce_lock:
        try:
            with sqlite3.connect(NONCE_DB) as db:
                db.execute(
                    "INSERT INTO nonces (nonce, ts) VALUES (?, ?)", (nonce, ts)
                )
                db.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate → replay


# ── Audit log (append-only, Ed25519 signature per line) ───────────────
# Each log line: <json_entry>|<base64_ed25519_sig>
# The private key (audit_sign.key) is required to write entries.
# The public key (audit_sign.pub) is sufficient to verify them.
# If the signing key file is missing at startup, an ephemeral key is
# generated in memory (audit entries are valid but not verifiable across
# restarts until setup.sh is run to generate a persistent keypair).
_audit_lock     = threading.Lock()
_audit_sign_key: Optional[Ed25519PrivateKey] = None


def audit(device_id: str, command: str, result: str, cert_serial: str = "") -> None:
    entry = json.dumps({
        "ts":          round(time.time(), 3),
        "device_id":   device_id,
        "command":     command,
        "result":      result,
        "cert_serial": cert_serial,
    }, separators=(",", ":"))
    if _audit_sign_key is not None:
        sig = base64.b64encode(_audit_sign_key.sign(entry.encode())).decode()
    else:
        sig = "no_key"
    line = f"{entry}|{sig}\n"
    with _audit_lock:
        with open(AUDIT_LOG, "a") as f:
            f.write(line)


def read_audit(n: int = 50) -> list[str]:
    if not os.path.exists(AUDIT_LOG):
        return []
    with open(AUDIT_LOG) as f:
        return f.readlines()[-n:]


# ── Rate limiter ───────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self) -> None:
        self._lock     = threading.Lock()
        self._requests: dict[str, list[float]] = {}
        self._failures: dict[str, tuple[int, float]] = {}

    def allowed(self, ip: str) -> bool:
        with self._lock:
            ban_count, ban_until = self._failures.get(ip, (0, 0.0))
            if ban_until > time.time():
                return False
            now   = time.time()
            times = [t for t in self._requests.get(ip, []) if now - t < RATE_LIMIT_WIN]
            if len(times) >= RATE_LIMIT_REQ:
                return False
            times.append(now)
            self._requests[ip] = times
        return True

    def failure(self, ip: str) -> None:
        with self._lock:
            count, _ = self._failures.get(ip, (0, 0.0))
            count += 1
            ban_until = time.time() + BAN_DURATION if count >= BAN_AFTER else 0.0
            self._failures[ip] = (count, ban_until)

    def success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)


_rate = RateLimiter()


# ── Global TLS handshake limiter (untrusted mode) ─────────────────────
class HSLimiter:
    def __init__(self, max_per_sec: int = HS_LIMIT_PER_SEC) -> None:
        self._lock  = threading.Lock()
        self._times: list[float] = []
        self._max   = max_per_sec

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self._times = [t for t in self._times if now - t < 1.0]
            if len(self._times) >= self._max:
                return False
            self._times.append(now)
        return True


_hs = HSLimiter()


# ── Revocation ─────────────────────────────────────────────────────────
def is_revoked(serial: str) -> bool:
    if not serial or not os.path.exists(REVOKED_FILE):
        return False
    with open(REVOKED_FILE) as f:
        return serial.strip() in {ln.strip() for ln in f if ln.strip()}


# ── Ed25519 verification ───────────────────────────────────────────────
def verify_ed25519(device_id: str, canonical: str, sig_b64: str) -> bool:
    """Verify Ed25519 signature from Android Keystore.

    The public key stored in sign.pub is PEM-encoded X.509 SubjectPublicKeyInfo.
    """
    pub_path = os.path.join(CLIENTS_DIR, device_id, "sign.pub")
    if not os.path.exists(pub_path):
        return False
    try:
        with open(pub_path, "rb") as f:
            pub = load_pem_public_key(f.read())
        sig = base64.b64decode(sig_b64 + "==")  # pad if needed
        pub.verify(sig, canonical.encode())
        return True
    except (InvalidSignature, Exception):
        return False


# ── OTP management ─────────────────────────────────────────────────────
_otp_lock = threading.Lock()


def _load_otps() -> dict:
    if not os.path.exists(PENDING_OTPS):
        return {}
    try:
        with open(PENDING_OTPS) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_otps(otps: dict) -> None:
    with open(PENDING_OTPS, "w") as f:
        json.dump(otps, f)
    os.chmod(PENDING_OTPS, 0o600)


def consume_otp(otp: str) -> Optional[dict]:
    """Returns OTP info dict if valid, None otherwise. Removes OTP atomically."""
    with _otp_lock:
        otps = _load_otps()
        info = otps.get(otp)
        if not info:
            return None
        if time.time() > info.get("expires", 0):
            del otps[otp]
            _save_otps(otps)
            return None
        del otps[otp]
        _save_otps(otps)
        return info


# ── Provisioning: generate client TLS cert ────────────────────────────
def provision_client(device_id: str, ed25519_pubkey_b64: str, ca_pass: str) -> dict:
    """Generate a client TLS cert signed by the local CA.

    The CA key (ca.key.enc) is decrypted transiently using ca_pass.
    The plaintext key never touches disk — openssl reads it directly.

    Returns: {"tls_key": <pem>, "tls_crt": <pem>, "ca_crt": <pem>}
    """
    client_dir = os.path.join(CLIENTS_DIR, device_id)
    os.makedirs(client_dir, mode=0o700, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "tls.key")
        csr_path = os.path.join(tmp, "tls.csr")
        crt_path = os.path.join(tmp, "tls.crt")

        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC",
             "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key_path],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "req", "-new", "-key", key_path, "-out", csr_path,
             "-subj", f"/CN={device_id}/O=PAM-client"],
            check=True, capture_output=True,
        )
        sign_env = os.environ.copy()
        sign_env["_CAPASS"] = ca_pass
        subprocess.run(
            ["openssl", "x509", "-req", "-in", csr_path,
             "-CA", CA_CRT, "-CAkey", CA_KEY_ENC,
             "-passin", "env:_CAPASS",
             "-CAcreateserial", "-out", crt_path, "-days", "365"],
            check=True, capture_output=True, env=sign_env,
        )

        with open(key_path) as f:
            tls_key = f.read()
        with open(crt_path) as f:
            tls_crt = f.read()

        shutil.copy(crt_path, os.path.join(client_dir, "tls.crt"))

    # Save Ed25519 public key as PEM (Android Keystore returns DER X.509 SPKI)
    pub_der  = base64.b64decode(ed25519_pubkey_b64 + "==")
    b64_raw  = base64.b64encode(pub_der).decode()
    b64_wrap = "\n".join(b64_raw[i:i + 64] for i in range(0, len(b64_raw), 64))
    pem_pub  = f"-----BEGIN PUBLIC KEY-----\n{b64_wrap}\n-----END PUBLIC KEY-----\n"
    with open(os.path.join(client_dir, "sign.pub"), "w") as f:
        f.write(pem_pub)
    os.chmod(os.path.join(client_dir, "sign.pub"), 0o644)

    with open(CA_CRT) as f:
        ca_crt = f.read()

    return {"tls_key": tls_key, "tls_crt": tls_crt, "ca_crt": ca_crt}


# ── Command execution ──────────────────────────────────────────────────
def execute_command(cmd: str) -> tuple[int, str]:
    argv = COMMANDS.get(cmd)
    if not argv:
        return 400, "Unknown command"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        out = (r.stdout + r.stderr).strip()
        return r.returncode, out[:10000]
    except subprocess.TimeoutExpired:
        return 1, "Command timed out"
    except FileNotFoundError as e:
        return 1, f"Binary not found: {e}"
    except Exception as e:
        return 1, str(e)


# ── Attestation policy (read from config [attestation] section) ────────
def _attestation_policy() -> dict:
    """Return the attestation policy dict from config, with safe defaults."""
    try:
        cfg = load_config()
        raw = cfg.get("attestation", {})
        return {
            "enabled":               bool(raw.get("enabled",               False)),
            "require_hardware_backed": bool(raw.get("require_hardware_backed", True)),
            "reject_unverified_boot":  bool(raw.get("reject_unverified_boot",  True)),
            "require_verified_boot":   bool(raw.get("require_verified_boot",   False)),
            "require_device_locked":   bool(raw.get("require_device_locked",   False)),
        }
    except Exception:
        return {
            "enabled": False,
            "require_hardware_backed": True,
            "reject_unverified_boot":  True,
            "require_verified_boot":   False,
            "require_device_locked":   False,
        }


# ── HTTP request handler ───────────────────────────────────────────────
class PAMHandler(http.server.BaseHTTPRequestHandler):
    server_version = f"PAM/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # all logging goes through audit()

    def _ip(self) -> str:
        return self.client_address[0]

    def _cert(self) -> Optional[dict]:
        """Return peer cert dict if the client presented one, else None."""
        try:
            c = self.connection.getpeercert()
            return c if c else None
        except Exception:
            return None

    def _device_from_cert(self) -> tuple[Optional[str], Optional[str]]:
        """(device_id, serial) from mTLS client cert, or (None, None)."""
        c = self._cert()
        if not c:
            return None, None
        subject = {k: v for x in c.get("subject", []) for k, v in x}
        return subject.get("commonName"), str(c.get("serialNumber", ""))

    def _send_json(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not length:
                return {}
            if length > 65536:
                return None
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    # ── Routing ────────────────────────────────────────────────────────
    def do_GET(self):
        if self.path == "/health":
            self._h_health()
        elif self.path == "/provision/challenge":
            self._h_provision_challenge()
        elif self.path.startswith("/audit"):
            self._h_audit()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/provision":
            self._h_provision()
        elif self.path == "/run":
            self._h_run()
        else:
            self.send_error(404)

    # ── /health ────────────────────────────────────────────────────────
    def _h_health(self):
        self._send_json(200, {"status": "ok", "version": VERSION})

    # ── /provision/challenge ───────────────────────────────────────────
    def _h_provision_challenge(self):
        """Issue a one-time 32-byte challenge for key attestation.
        The client must pass the returned challenge as attestation_challenge
        in setAttestationChallenge() during key generation, then include
        the resulting cert chain in POST /provision.
        Challenge is valid for CHALLENGE_TTL seconds and single-use.
        """
        b64 = issue_challenge()
        self._send_json(200, {"challenge": b64})

    # ── /audit ─────────────────────────────────────────────────────────
    def _h_audit(self):
        device_id, serial = self._device_from_cert()
        if not device_id:
            self.send_error(400, "Client certificate required")
            return
        if is_revoked(serial):
            self.send_error(403, "Certificate revoked")
            return
        self._send_json(200, {"lines": read_audit(50)})

    # ── /provision ─────────────────────────────────────────────────────
    def _h_provision(self):
        body = self._read_body()
        if body is None:
            self.send_error(400, "Invalid JSON")
            return

        otp            = body.get("otp", "").strip()
        ed25519_pubkey = body.get("ed25519_pubkey", "").strip()

        if not otp or not ed25519_pubkey:
            self.send_error(400, "Missing otp or ed25519_pubkey")
            return

        # Derive device_id from Ed25519 public key
        try:
            pub_der   = base64.b64decode(ed25519_pubkey + "==")
            device_id = hashlib.sha256(pub_der).hexdigest()[:16]
        except Exception:
            self.send_error(400, "Invalid ed25519_pubkey encoding")
            return

        # ── L-A: Attestation verified BEFORE OTP consumption (Bug-08).
        # If enabled=true and no chain / module unavailable → reject (Bug-11).
        attestation_chain     = body.get("attestation_chain")      # list[str] | None
        attestation_challenge = body.get("attestation_challenge")  # base64 str | None
        policy = _attestation_policy()

        if attestation_chain is not None:
            if not attestation_challenge:
                self.send_error(400, "attestation_chain requires attestation_challenge")
                audit(device_id, "provision", "attest_missing_challenge", "")
                return

            raw_challenge = consume_challenge(attestation_challenge)
            if raw_challenge is None:
                self.send_error(400, "attestation_challenge invalid or expired")
                audit(device_id, "provision", "attest_challenge_expired", "")
                return

            if not _ATTESTATION_AVAILABLE:
                if policy["enabled"]:
                    self.send_error(403, "Attestation required but module unavailable")
                    audit(device_id, "provision", "attest_module_missing_enforced", "")
                    return
                logging.warning(
                    "attestation.py not available — skipping chain verification"
                )
                attest_status = "attest_module_unavailable"
            else:
                result = verify_attestation(attestation_chain, raw_challenge, policy)
                if not result.ok:
                    logging.warning(
                        "Attestation failed for %s: %s", device_id, result.reason
                    )
                    self.send_error(403, f"Attestation failed: {result.reason}")
                    audit(device_id, "provision", f"attest_fail:{result.reason}", "")
                    return
                attest_status = (
                    f"attest_ok:sl={result.attestation_security_level}"
                    f",vbs={result.verified_boot_state}"
                )
                logging.info(
                    "Attestation OK for %s — security_level=%d, boot_state=%d",
                    device_id, result.attestation_security_level,
                    result.verified_boot_state,
                )
        else:
            if policy["enabled"]:
                self.send_error(403, "Attestation required: no chain provided")
                audit(device_id, "provision", "attest_required_missing", "")
                return
            attest_status = "no_attestation"

        # OTP consumed after attestation passes (Bug-08: prevents burning OTP via
        # repeated bad attestation chains)
        otp_info = consume_otp(otp)
        if not otp_info:
            self.send_error(403, "Invalid or expired OTP")
            audit("provisioning", "provision", "invalid_otp", "")
            return

        ca_pass = otp_info.get("ca_pass", "")
        if not ca_pass:
            self.send_error(500, "CA passphrase not available")
            return

        try:
            certs = provision_client(device_id, ed25519_pubkey, ca_pass)
        except subprocess.CalledProcessError as e:
            logging.error("Cert generation failed: %s", e.stderr)
            self.send_error(500, "Certificate generation failed")
            audit(device_id, "provision", "cert_error", "")
            return

        audit(device_id, "provision", f"ok:{attest_status}", "")
        self._send_json(200, {
            "ca_crt":  certs["ca_crt"],
            "tls_crt": certs["tls_crt"],
            "tls_key": certs["tls_key"],
        })

    # ── /run ───────────────────────────────────────────────────────────
    def _h_run(self):
        ip = self._ip()
        if not _rate.allowed(ip):
            self.send_error(429, "Too many requests")
            return

        device_id, serial = self._device_from_cert()
        if not device_id:
            self.send_error(400, "Client certificate required")
            return
        if is_revoked(serial):
            self.send_error(403, "Certificate revoked")
            return

        body = self._read_body()
        if body is None:
            self.send_error(400, "Invalid JSON")
            return

        command   = str(body.get("command", "")).strip()
        timestamp = body.get("timestamp", 0)
        nonce     = str(body.get("nonce", "")).strip()
        sig_b64   = str(body.get("signature", "")).strip()

        if not all([command, timestamp, nonce, sig_b64]):
            self.send_error(400, "Missing required fields")
            return

        try:
            timestamp = int(timestamp)
        except (TypeError, ValueError):
            self.send_error(400, "Invalid timestamp")
            return

        # Timestamp window check
        if abs(int(time.time()) - timestamp) > TIMESTAMP_WINDOW:
            self.send_error(401, "Timestamp out of window")
            audit(device_id, command, "timestamp_fail", serial)
            return

        # Command whitelist — before sig verify and nonce consume
        if command not in COMMANDS:
            self.send_error(400, "Command not in whitelist")
            audit(device_id, command, "whitelist_fail", serial)
            return

        # Ed25519 signature — canonical: "command|timestamp|nonce"
        canonical = f"{command}|{timestamp}|{nonce}"
        if not verify_ed25519(device_id, canonical, sig_b64):
            _rate.failure(ip)
            self.send_error(401, "Signature verification failed")
            audit(device_id, command, "sig_fail", serial)
            return

        # Replay protection (SQLite-backed nonce) — AFTER sig verify to prevent nonce burning
        if not check_and_store_nonce(nonce, float(timestamp)):
            self.send_error(409, "Replay detected")
            audit(device_id, command, "replay", serial)
            return

        _rate.success(ip)

        code, output = execute_command(command)
        audit(device_id, command, f"exit:{code}", serial)
        self._send_json(200, {
            "result": "ok" if code == 0 else "error",
            "code":   code,
            "data":   output,
        })


# ── SSL-wrapping TCP server ────────────────────────────────────────────
class PAMServer(http.server.ThreadingHTTPServer):
    def __init__(self, addr, handler, ssl_ctx: ssl.SSLContext,
                 untrusted: bool = False) -> None:
        super().__init__(addr, handler)
        self._ssl_ctx   = ssl_ctx
        self._untrusted = untrusted

    def get_request(self):
        conn, addr = self.socket.accept()
        if self._untrusted and not _hs.allow():
            conn.close()
            raise OSError("Handshake rate limit exceeded")
        try:
            tls_conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            conn.close()
            raise
        return tls_conn, addr


# ── mDNS announcement (PAM direct mode only) ──────────────────────────
def start_mdns(port: int):
    try:
        import socket
        from zeroconf import Zeroconf, ServiceInfo
        ip   = socket.gethostbyname(socket.gethostname())
        info = ServiceInfo(
            "_rofi-bridge._tcp.local.",
            "rofi-bridge._rofi-bridge._tcp.local.",
            addresses=[socket.inet_aton(ip)],
            port=port,
        )
        zc = Zeroconf()
        zc.register_service(info)
        logging.info("mDNS: announced rofi-bridge._tcp.local on %s:%d", ip, port)
        return zc
    except Exception as e:
        logging.warning("mDNS unavailable: %s", e)
        return None


# ── Entry point ────────────────────────────────────────────────────────
def main() -> None:
    global _audit_sign_key

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    config    = load_config()
    port      = int(config.get("port", 7443))
    if not (1 <= port <= 65535):
        logging.error("Invalid port %d in config — using 7443", port)
        port = 7443
    bind      = str(config.get("bind", "")).strip()
    mode      = str(config.get("mode", "direct"))
    untrusted = bool(config.get("untrusted", False))

    # Resolve bind address
    if not bind:
        if mode == "hardened":
            bind = "10.0.0.2"
        else:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                bind = s.getsockname()[0]
            except Exception:
                bind = "0.0.0.0"
            finally:
                s.close()

    # Audit signing key (L-F — Ed25519, asymmetric)
    if os.path.exists(AUDIT_SIGN_KEY):
        try:
            with open(AUDIT_SIGN_KEY, "rb") as f:
                _audit_sign_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            logging.info("Audit signing key loaded from %s", AUDIT_SIGN_KEY)
        except Exception as e:
            logging.warning(
                "Failed to load audit signing key: %s — generating ephemeral key", e
            )
            _audit_sign_key = Ed25519PrivateKey.generate()
    else:
        _audit_sign_key = Ed25519PrivateKey.generate()
        logging.warning(
            "audit_sign.key not found at %s — using ephemeral key "
            "(run setup.sh to generate a persistent keypair)", AUDIT_SIGN_KEY
        )

    init_nonce_db()
    threading.Thread(target=_nonce_cleanup_loop, daemon=True).start()

    # SSL context — CERT_OPTIONAL allows /provision without a client cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(SERVER_CRT, SERVER_KEY)
    ctx.load_verify_locations(CA_CRT)
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")

    server = PAMServer((bind, port), PAMHandler, ctx, untrusted=untrusted)

    zc = None
    if mode == "direct" and not untrusted and config.get("mdns", True):
        zc = start_mdns(port)

    logging.info("PAM daemon v%s listening on %s:%d (mode=%s, untrusted=%s)",
                 VERSION, bind, port, mode, untrusted)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if zc:
            zc.close()


if __name__ == "__main__":
    main()
