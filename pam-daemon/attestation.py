#!/usr/bin/env python3
"""
attestation.py — Android Hardware Key Attestation verifier

Verifies that an Android Keystore key was generated in hardware (TEE/StrongBox)
by verifying the attestation certificate chain against the Google Hardware
Attestation Root CAs and parsing the KeyDescription extension.

No external dependencies beyond `cryptography` (already required by bridge_v2.py).

Reference: https://developer.android.com/training/articles/security-key-attestation
"""

import os
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import ObjectIdentifier

# Android KeyDescription extension OID: 1.3.6.1.4.1.11129.2.1.17
_OID_KEY_ATTESTATION = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

# Prefer the config-dir copy installed by setup.sh; fall back to script directory
_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "rofi-bridge")
_ROOTS_PEM_CONFIG = os.path.join(_CONFIG_DIR, "attestation_roots.pem")
_ROOTS_PEM_LOCAL  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attestation_roots.pem")
_ROOTS_PEM = _ROOTS_PEM_CONFIG if os.path.exists(_ROOTS_PEM_CONFIG) else _ROOTS_PEM_LOCAL

# attestationSecurityLevel / keymasterSecurityLevel enum values
SECURITY_LEVEL_SOFTWARE  = 0
SECURITY_LEVEL_TEE       = 1
SECURITY_LEVEL_STRONGBOX = 2

# VerifiedBootState enum values
VERIFIED_BOOT_VERIFIED    = 0   # GREEN  — boot chain verified
VERIFIED_BOOT_SELF_SIGNED = 1   # YELLOW — self-signed boot cert
VERIFIED_BOOT_UNVERIFIED  = 2   # ORANGE — unlocked bootloader
VERIFIED_BOOT_FAILED      = 3   # RED    — verification failed


@dataclass
class AttestationResult:
    ok: bool
    reason: str = ""
    attestation_version: int = 0
    attestation_security_level: int = -1   # see SECURITY_LEVEL_* constants
    keymaster_security_level: int = -1
    verified_boot_state: int = -1          # see VERIFIED_BOOT_* constants
    device_locked: bool = False
    challenge_ok: bool = False


# ── DER TLV parser ──────────────────────────────────────────────────────

def _read_tlv(data: bytes, pos: int):
    """Read one BER/DER TLV at position pos.
    Returns (tag_class, constructed, tag_num, value_bytes, next_pos).
      tag_class: 0=Universal 1=Application 2=Context 3=Private
    """
    if pos >= len(data):
        raise ValueError(f"end of data at pos {pos}/{len(data)}")
    b = data[pos]; pos += 1
    tag_class   = (b >> 6) & 0x3
    constructed = bool(b & 0x20)
    tag_num     = b & 0x1F
    if tag_num == 0x1F:
        # Long-form tag encoding
        tag_num = 0
        while True:
            if pos >= len(data):
                raise ValueError("truncated long-form tag")
            b = data[pos]; pos += 1
            tag_num = (tag_num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    if pos >= len(data):
        raise ValueError("missing length byte")
    b = data[pos]; pos += 1
    if b == 0x80:
        raise ValueError("indefinite length not supported")
    if b & 0x80:
        n = b & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = b
    value = data[pos:pos + length]
    return tag_class, constructed, tag_num, value, pos + length


def _iter_seq(content: bytes):
    """Yield (tag_class, constructed, tag_num, value_bytes) for each TLV in content."""
    pos = 0
    while pos < len(content):
        tc, cons, tn, val, pos = _read_tlv(content, pos)
        yield tc, cons, tn, val


def _parse_int(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=True)


def _parse_enum(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=False)


# ── Root CA loading ─────────────────────────────────────────────────────

def _load_roots() -> list:
    """Load Google Hardware Attestation root CAs from attestation_roots.pem."""
    roots: list = []
    with open(_ROOTS_PEM, "rb") as f:
        pem_data = f.read()
    marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"
    parts = pem_data.split(marker)
    for part in parts[1:]:
        end = part.find(end_marker)
        if end < 0:
            continue
        pem = marker + part[: end + len(end_marker)]
        try:
            roots.append(x509.load_pem_x509_certificate(pem))
        except Exception:
            pass
    return roots


def _fingerprint(cert) -> bytes:
    return cert.fingerprint(hashes.SHA256())


# ── Chain signature verification ────────────────────────────────────────

def _verify_cert_signature(subject_cert, issuer_cert) -> bool:
    """Return True if subject_cert's signature verifies against issuer_cert's public key."""
    pub = issuer_cert.public_key()
    sig = subject_cert.signature
    tbs = subject_cert.tbs_certificate_bytes
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, tbs, padding.PKCS1v15(), subject_cert.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, tbs, ec.ECDSA(subject_cert.signature_hash_algorithm))
        else:
            return False
        return True
    except (InvalidSignature, Exception):
        return False


# ── KeyDescription extension extraction ────────────────────────────────

def _get_key_description_bytes(cert) -> Optional[bytes]:
    """Return the DER bytes of the KeyDescription SEQUENCE from the leaf cert, or None."""
    try:
        ext = cert.extensions.get_extension_for_oid(_OID_KEY_ATTESTATION)
        raw = ext.value.value  # bytes: content of extnValue OCTET STRING = DER of KeyDescription
        # Defensive: if raw starts with OCTET STRING tag (0x04), unwrap it
        if raw and raw[0] == 0x04:
            _, _, _, raw, _ = _read_tlv(raw, 0)
        return raw
    except x509.ExtensionNotFound:
        return None
    except Exception:
        return None


# ── KeyDescription ASN.1 parsing ────────────────────────────────────────

def _parse_key_description(der: bytes) -> dict:
    """Parse KeyDescription SEQUENCE.
    Positional layout (from Android KeyMint/Keymaster ASN.1 schema):
      [0] INTEGER   attestationVersion
      [1] ENUM      attestationSecurityLevel
      [2] INTEGER   keymasterVersion
      [3] ENUM      keymasterSecurityLevel
      [4] OCTET STRING  attestationChallenge
      [5] OCTET STRING  uniqueId
      [6] SEQUENCE  softwareEnforced (AuthorizationList)
      [7] SEQUENCE  teeEnforced      (AuthorizationList)
    """
    result: dict = {}
    # Unwrap outer SEQUENCE
    tc, cons, tn, seq_val, _ = _read_tlv(der, 0)
    if not (tc == 0 and tn == 16):
        raise ValueError(f"expected Universal SEQUENCE, got class={tc} tag={tn}")
    items = list(_iter_seq(seq_val))
    if len(items) >= 1:
        result["attestation_version"]        = _parse_int(items[0][3])
    if len(items) >= 2:
        result["attestation_security_level"] = _parse_enum(items[1][3])
    if len(items) >= 3:
        result["keymaster_version"]          = _parse_int(items[2][3])
    if len(items) >= 4:
        result["keymaster_security_level"]   = _parse_enum(items[3][3])
    if len(items) >= 5:
        result["attestation_challenge"]      = bytes(items[4][3])
    if len(items) >= 6:
        result["unique_id"]                  = bytes(items[5][3])
    if len(items) >= 7:
        result["software_enforced"] = _parse_authorization_list(items[6][3])
    if len(items) >= 8:
        result["tee_enforced"]      = _parse_authorization_list(items[7][3])
    return result


def _parse_authorization_list(content: bytes) -> dict:
    """Parse the content bytes of an AuthorizationList SEQUENCE.
    Extracts rootOfTrust [704] EXPLICIT.
    """
    result: dict = {}
    for tc, cons, tn, val in _iter_seq(content):
        if tc == 2 and tn == 704:
            # EXPLICIT [704]: val is the DER of inner SEQUENCE (RootOfTrust)
            result["root_of_trust"] = _parse_root_of_trust(val)
    return result


def _parse_root_of_trust(der: bytes) -> dict:
    """Parse RootOfTrust from EXPLICIT [704] value bytes.
    RootOfTrust ::= SEQUENCE {
        verifiedBootKey   OCTET STRING,
        deviceLocked      BOOLEAN,
        verifiedBootState VerifiedBootState ENUMERATED,
        verifiedBootHash  OCTET STRING OPTIONAL
    }
    """
    result: dict = {}
    try:
        # EXPLICIT wrapper: der contains the inner SEQUENCE TLV
        tc, cons, tn, seq_val, _ = _read_tlv(der, 0)
        if tc == 0 and tn == 16:
            inner = seq_val
        else:
            inner = der  # fallback: treat der directly as sequence content
        items = list(_iter_seq(inner))
        # item[0] = verifiedBootKey  (OCTET STRING — skip)
        # item[1] = deviceLocked     (BOOLEAN)
        # item[2] = verifiedBootState (ENUMERATED)
        # item[3] = verifiedBootHash (OCTET STRING, optional)
        if len(items) >= 2:
            result["device_locked"] = bool(items[1][3][0]) if items[1][3] else False
        if len(items) >= 3:
            result["verified_boot_state"] = _parse_enum(items[2][3])
    except Exception:
        pass
    return result


# ── Main entry point ────────────────────────────────────────────────────

def verify_attestation(
    cert_pem_list: list,
    expected_challenge: bytes,
    policy: dict,
) -> AttestationResult:
    """Verify an Android Key Attestation certificate chain.

    Args:
        cert_pem_list:       PEM strings, leaf first (index 0 = leaf with KeyDescription).
        expected_challenge:  Raw bytes of the challenge nonce the server issued.
        policy:              Dict from config [attestation] section:
                               require_hardware_backed (bool, default True)
                               reject_unverified_boot  (bool, default True)
                               require_verified_boot   (bool, default False)
                               require_device_locked   (bool, default False)

    Returns:
        AttestationResult — .ok is True only if all checks pass.
    """
    res = AttestationResult(ok=False)

    if not cert_pem_list:
        res.reason = "empty attestation chain"
        return res

    # 1. Parse PEM certificates
    certs = []
    for i, pem in enumerate(cert_pem_list):
        try:
            certs.append(x509.load_pem_x509_certificate(pem.encode()))
        except Exception as e:
            res.reason = f"cert parse error at index {i}: {e}"
            return res

    # 2. Verify chain: each cert signed by the next (leaf → root)
    for i in range(len(certs) - 1):
        if not _verify_cert_signature(certs[i], certs[i + 1]):
            res.reason = f"chain signature invalid: cert[{i}] not signed by cert[{i+1}]"
            return res
    # Root must be self-signed
    if not _verify_cert_signature(certs[-1], certs[-1]):
        res.reason = "root cert is not self-signed"
        return res

    # 3. Root must be in our trusted anchor set (software attestation roots rejected)
    try:
        trusted_roots = _load_roots()
    except Exception as e:
        res.reason = f"failed to load trust anchors: {e}"
        return res

    root_fp = _fingerprint(certs[-1])
    if not any(_fingerprint(r) == root_fp for r in trusted_roots):
        res.reason = "chain root is not a trusted Google Hardware Attestation Root CA"
        return res

    # 4. Find KeyDescription extension in leaf cert
    kd_der = _get_key_description_bytes(certs[0])
    if kd_der is None:
        res.reason = "KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17) not found in leaf"
        return res

    # 5. Parse KeyDescription
    try:
        kd = _parse_key_description(kd_der)
    except Exception as e:
        res.reason = f"KeyDescription parse error: {e}"
        return res

    # 6. Challenge binding: attestationChallenge must match what server issued
    chain_challenge = kd.get("attestation_challenge", b"")
    if chain_challenge != expected_challenge:
        res.reason = (
            f"attestation challenge mismatch "
            f"(got {chain_challenge.hex()}, expected {expected_challenge.hex()})"
        )
        return res
    res.challenge_ok = True

    # 7. Populate result
    res.attestation_version        = kd.get("attestation_version", 0)
    res.attestation_security_level = kd.get("attestation_security_level", -1)
    res.keymaster_security_level   = kd.get("keymaster_security_level", -1)

    tee = kd.get("tee_enforced", {})
    rot = tee.get("root_of_trust", {})
    res.verified_boot_state = rot.get("verified_boot_state", -1)
    res.device_locked       = rot.get("device_locked", False)

    # 8. Apply policy
    req_hw    = policy.get("require_hardware_backed", True)
    rej_unver = policy.get("reject_unverified_boot", True)
    req_ver   = policy.get("require_verified_boot", False)
    req_lock  = policy.get("require_device_locked", False)

    if req_hw and res.attestation_security_level not in (
        SECURITY_LEVEL_TEE, SECURITY_LEVEL_STRONGBOX
    ):
        res.reason = (
            f"key not hardware-backed "
            f"(attestation_security_level={res.attestation_security_level})"
        )
        return res

    if rej_unver and res.verified_boot_state == VERIFIED_BOOT_UNVERIFIED:
        res.reason = "bootloader is unlocked (verifiedBootState=UNVERIFIED)"
        return res

    if req_ver and res.verified_boot_state != VERIFIED_BOOT_VERIFIED:
        res.reason = f"require_verified_boot=true but state={res.verified_boot_state}"
        return res

    if req_lock and not res.device_locked:
        res.reason = "require_device_locked=true but deviceLocked=false"
        return res

    res.ok = True
    res.reason = "ok"
    return res
