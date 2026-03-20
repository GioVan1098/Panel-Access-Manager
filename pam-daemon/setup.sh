#!/usr/bin/env bash
# setup.sh — PAM (Panel Access Manager) installer
# Run as the normal user (not root). Uses sudo only where required.
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.config/rofi-bridge"
CA_DIR="${HOME}/rofi-bridge-ca"
SERVICE_DIR="${HOME}/.config/systemd/user"
IPT_SRC="${SCRIPT_DIR}/ipt-helper.c"
IPT_BIN="/usr/lib/rofi-bridge/ipt-helper"
BRIDGE_PY="${SCRIPT_DIR}/bridge_v2.py"

# ── Defaults ──────────────────────────────────────────────────────────────
PORT=7443
HARDENED=0
UNTRUSTED=0
REGEN_CERT=0
REGEN_ALL=0
UNINSTALL=0
WOL=0

# ── Argument parsing ──────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --hardened)               HARDENED=1   ;;
        --untrusted-mode)         UNTRUSTED=1  ;;
        --regenerate-server-cert) REGEN_CERT=1 ;;
        --regenerate-all)         REGEN_ALL=1  ;;
        --uninstall)              UNINSTALL=1  ;;
        --wol)                    WOL=1        ;;
        --port=*)                 PORT="${arg#*=}" ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── Uninstall ─────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
    info "Uninstalling PAM..."

    # ── Daemon service (user) ─────────────────────────────────────────
    systemctl --user stop    rofi-bridge.service 2>/dev/null || true
    systemctl --user disable rofi-bridge.service 2>/dev/null || true
    systemctl --user daemon-reload
    rm -f "${SERVICE_DIR}/rofi-bridge.service"
    ok "rofi-bridge.service removed"

    # ── pam-setcap.service (system) ───────────────────────────────────
    sudo systemctl stop    pam-setcap.service 2>/dev/null || true
    sudo systemctl disable pam-setcap.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/pam-setcap.service
    sudo systemctl daemon-reload
    ok "pam-setcap.service removed"

    # ── ipt-helper binary ─────────────────────────────────────────────
    if [ -f "${IPT_BIN}" ]; then
        sudo rm -f "${IPT_BIN}"
        sudo rmdir "$(dirname "${IPT_BIN}")" 2>/dev/null || true
        ok "ipt-helper removed"
    fi

    # ── GUI binary ────────────────────────────────────────────────────
    if [ -f "${HOME}/.local/bin/pam-gui" ]; then
        rm -f "${HOME}/.local/bin/pam-gui"
        ok "pam-gui removed"
    fi

    # ── WireGuard (hardened mode only) ────────────────────────────────
    if [ -f /etc/wireguard/wg0.conf ]; then
        info "WireGuard configuration found — removing..."
        sudo systemctl stop    wg-quick@wg0 2>/dev/null || true
        sudo systemctl disable wg-quick@wg0 2>/dev/null || true
        sudo rm -f /etc/wireguard/wg0.conf
        ok "WireGuard wg0 removed"
    fi

    ok "PAM uninstalled."
    warn "Config and certificates retained at: ${CONFIG_DIR}/"
    warn "CA key retained at: ${CA_DIR}/"
    warn "To also remove data: rm -rf '${CONFIG_DIR}' '${CA_DIR}'"
    exit 0
fi

# ── Prerequisites ─────────────────────────────────────────────────────────
info "Checking prerequisites..."
for cmd in openssl gcc systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done
command -v setcap >/dev/null 2>&1 || \
    die "setcap not found. Install libcap (pacman -S libcap / apt install libcap2-bin)"

# NTP check — C4 fix
if systemctl is-active --quiet systemd-timesyncd 2>/dev/null || \
   systemctl is-active --quiet chronyd 2>/dev/null; then
    ok "NTP time sync: active"
else
    warn "NTP (systemd-timesyncd or chronyd) is not active."
    warn "Timestamp validation requires a synchronised clock (±30s window)."
    warn "Enable: sudo systemctl enable --now systemd-timesyncd"
fi
ok "Prerequisites OK"

# ── Directories ───────────────────────────────────────────────────────────
mkdir -p "${CONFIG_DIR}/clients"
mkdir -p "${CA_DIR}"
chmod 700 "${CA_DIR}"
chmod 700 "${CONFIG_DIR}"

# ── Detect bind IP ────────────────────────────────────────────────────────
LAN_IP=$(ip route get 8.8.8.8 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}')
[ -n "$LAN_IP" ] || die "Could not detect LAN IP. Check network connectivity."
info "Detected LAN IP: ${LAN_IP}"

if [ "$HARDENED" -eq 1 ]; then
    BIND_IP="10.0.0.2"
    MODE="hardened"
    info "Hardened mode: daemon will bind to ${BIND_IP} (WireGuard wg0)"
else
    BIND_IP="${LAN_IP}"
    MODE="direct"
fi

# ── config.toml ───────────────────────────────────────────────────────────
if [ ! -f "${CONFIG_DIR}/config.toml" ] || [ "$REGEN_ALL" -eq 1 ]; then
    info "Writing config.toml..."
    cat > "${CONFIG_DIR}/config.toml" <<TOML
port           = ${PORT}
mode           = "${MODE}"
bind_ip        = "${BIND_IP}"
untrusted_mode = $([ "$UNTRUSTED" -eq 1 ] && echo "true" || echo "false")
wol_enabled    = $([ "$WOL" -eq 1 ] && echo "true" || echo "false")
TOML
    chmod 600 "${CONFIG_DIR}/config.toml"
    ok "config.toml written"
fi

# ── CA generation ─────────────────────────────────────────────────────────
if [ ! -f "${CA_DIR}/ca.key.enc" ] || [ "$REGEN_ALL" -eq 1 ]; then
    info "Generating CA key and certificate (4096-bit RSA)..."
    openssl genrsa -out "${CA_DIR}/ca.key" 4096 2>/dev/null
    openssl req -x509 \
        -key  "${CA_DIR}/ca.key" \
        -out  "${CONFIG_DIR}/ca.crt" \
        -days 3650 \
        -subj "/CN=pam-CA/O=PAM" 2>/dev/null
    chmod 644 "${CONFIG_DIR}/ca.crt"
    ok "CA certificate generated: ${CONFIG_DIR}/ca.crt"
    # ca.key stays plaintext until we've signed the server cert (see below).
else
    ok "CA already exists (use --regenerate-all to replace)"
fi

# ── Server certificate with SAN ───────────────────────────────────────────
NEED_SERVER_CERT=0
[ ! -f "${CONFIG_DIR}/server.crt" ] && NEED_SERVER_CERT=1
[ "$REGEN_CERT" -eq 1 ]            && NEED_SERVER_CERT=1
[ "$REGEN_ALL"  -eq 1 ]            && NEED_SERVER_CERT=1

if [ "$NEED_SERVER_CERT" -eq 1 ]; then
    info "Generating server key and certificate..."
    HOSTNAME_LOCAL="$(hostname).local"
    if [ "$HARDENED" -eq 1 ]; then
        SAN_VALUE="IP:10.0.0.2,DNS:${HOSTNAME_LOCAL}"
    else
        SAN_VALUE="IP:${LAN_IP},DNS:${HOSTNAME_LOCAL}"
    fi

    openssl genrsa -out "${CONFIG_DIR}/server.key" 2048 2>/dev/null
    chmod 600 "${CONFIG_DIR}/server.key"

    openssl req -new \
        -key  "${CONFIG_DIR}/server.key" \
        -out  "${CONFIG_DIR}/server.csr" \
        -subj "/CN=rofi-bridge/O=PAM" 2>/dev/null

    # SAN extension config
    cat > "${CONFIG_DIR}/san.ext" <<EXT
[SAN]
subjectAltName  = ${SAN_VALUE}
basicConstraints = CA:FALSE
keyUsage        = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXT

    # Choose CA signing key
    if [ -f "${CA_DIR}/ca.key" ]; then
        # Plaintext key still present from this run (initial setup)
        CA_KEY_SIGN="${CA_DIR}/ca.key"
        TMP_KEY_CREATED=0
    else
        info "CA key passphrase required to sign the server certificate:"
        TMP_KEY=$(mktemp)
        chmod 600 "${TMP_KEY}"
        openssl pkcs8 -in "${CA_DIR}/ca.key.enc" -out "${TMP_KEY}" -nocrypt \
            2>/dev/null || openssl pkcs8 -in "${CA_DIR}/ca.key.enc" -out "${TMP_KEY}"
        CA_KEY_SIGN="${TMP_KEY}"
        TMP_KEY_CREATED=1
    fi

    openssl x509 -req \
        -in           "${CONFIG_DIR}/server.csr" \
        -CA           "${CONFIG_DIR}/ca.crt" \
        -CAkey        "${CA_KEY_SIGN}" \
        -CAcreateserial \
        -out          "${CONFIG_DIR}/server.crt" \
        -days 365 \
        -extfile      "${CONFIG_DIR}/san.ext" \
        -extensions   SAN 2>/dev/null

    chmod 644 "${CONFIG_DIR}/server.crt"
    rm -f "${CONFIG_DIR}/server.csr" "${CONFIG_DIR}/san.ext"

    if [ "${TMP_KEY_CREATED:-0}" -eq 1 ]; then
        { shred -u "${TMP_KEY}" 2>/dev/null || rm -f "${TMP_KEY}"; }
    fi

    ok "Server certificate generated (SAN: ${SAN_VALUE})"
fi

# ── Encrypt and shred plaintext CA key (initial setup only) ───────────────
if [ -f "${CA_DIR}/ca.key" ]; then
    echo ""
    echo -e "${YELLOW}Set a passphrase for the CA key.${NC}"
    echo -e "${YELLOW}You will need it each time you provision a new device.${NC}"
    echo ""
    openssl pkcs8 -in "${CA_DIR}/ca.key" -topk8 -v2 aes256 \
        -out "${CA_DIR}/ca.key.enc"
    chmod 600 "${CA_DIR}/ca.key.enc"
    { shred -u "${CA_DIR}/ca.key" 2>/dev/null || rm -f "${CA_DIR}/ca.key"; }
    ok "CA key encrypted: ${CA_DIR}/ca.key.enc"
    warn "Store the CA passphrase securely — it cannot be recovered."
    warn "For maximum security, move ca.key.enc to offline storage after provisioning."
fi

# ── Build and install ipt-helper ──────────────────────────────────────────
[ -f "$IPT_SRC" ] || die "ipt-helper.c not found at ${IPT_SRC}"
info "Building ipt-helper..."
gcc -O2 -Wall -o /tmp/pam-ipt-helper "$IPT_SRC" || die "Compilation failed"

info "Installing ipt-helper (requires sudo)..."
sudo install -Dm755 /tmp/pam-ipt-helper "${IPT_BIN}"
rm -f /tmp/pam-ipt-helper
sudo setcap cap_net_admin+eip "${IPT_BIN}"

# Verify capability was applied — C2 fix (will also be re-applied by pam-setcap.service at boot)
getcap "${IPT_BIN}" | grep -q cap_net_admin \
    || die "setcap verification failed for ${IPT_BIN}"
ok "ipt-helper installed with cap_net_admin: ${IPT_BIN}"

# ── Audit log signing key (L-F — asymmetric Ed25519 audit) ───────────────
# Replaces HMAC-SHA256 (shared secret in config.toml) with an Ed25519
# private key loaded into daemon memory. Log entries are signed with the
# private key; the public key is used for independent verification.
# Even if config.toml is compromised, the signing key is in a separate file.
if [ ! -f "${CONFIG_DIR}/audit_sign.key" ] || [ "$REGEN_ALL" -eq 1 ]; then
    info "Generating audit log signing key (Ed25519)..."
    openssl genpkey -algorithm ed25519 -out "${CONFIG_DIR}/audit_sign.key" 2>/dev/null
    chmod 400 "${CONFIG_DIR}/audit_sign.key"
    openssl pkey -in "${CONFIG_DIR}/audit_sign.key" -pubout \
        -out "${CONFIG_DIR}/audit_sign.pub" 2>/dev/null
    chmod 444 "${CONFIG_DIR}/audit_sign.pub"
    ok "Audit signing key:  ${CONFIG_DIR}/audit_sign.key  (private — 400)"
    ok "Audit verify key:   ${CONFIG_DIR}/audit_sign.pub  (public — 444)"
else
    ok "Audit signing key already exists (use --regenerate-all to replace)"
fi

# ── pam-setcap.service — system oneshot (C2 fix) ─────────────────────────
info "Creating pam-setcap.service (system service)..."
sudo tee /etc/systemd/system/pam-setcap.service > /dev/null <<SVC
[Unit]
Description=PAM — Re-apply ipt-helper cap_net_admin after system updates
After=local-fs.target
ConditionPathExists=${IPT_BIN}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'getcap ${IPT_BIN} | grep -q cap_net_admin || setcap cap_net_admin+eip ${IPT_BIN}'

[Install]
WantedBy=multi-user.target
SVC
sudo systemctl daemon-reload
sudo systemctl enable pam-setcap.service 2>/dev/null || true
ok "pam-setcap.service enabled (system)"

# ── rofi-bridge.service — user service ───────────────────────────────────
info "Creating rofi-bridge.service (user service)..."
mkdir -p "${SERVICE_DIR}"
cat > "${SERVICE_DIR}/rofi-bridge.service" <<SVC
[Unit]
Description=PAM — Panel Access Manager bridge daemon
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/sh -c 'getcap ${IPT_BIN} | grep -q cap_net_admin || echo "WARNING: ipt-helper missing cap_net_admin — port control disabled"'
ExecStartPre=${IPT_BIN} open
ExecStart=/usr/bin/python3 ${BRIDGE_PY}
ExecStopPost=${IPT_BIN} close
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SVC
systemctl --user daemon-reload
ok "rofi-bridge.service created (not yet enabled)"

# ── Wake-on-LAN setup (--wol flag) ───────────────────────────────────────
if [ "$WOL" -eq 1 ]; then
    info "Wake-on-LAN: detecting PC MAC address..."
    DEFAULT_IF=$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')
    LAN_MAC=""
    if [ -n "$DEFAULT_IF" ]; then
        LAN_MAC=$(ip link show "${DEFAULT_IF}" 2>/dev/null \
            | awk '/link\/ether/{print $2}' | head -1)
    fi
    if [ -n "$LAN_MAC" ]; then
        ok "PC MAC address: ${LAN_MAC}"
        echo "wol_mac = \"${LAN_MAC}\"" >> "${CONFIG_DIR}/config.toml"
    else
        warn "Could not detect MAC address automatically."
        warn "Enter it manually in the PAM app Settings → Wake-on-LAN."
    fi
    echo ""
    warn "Wake-on-LAN requires the feature to be enabled in BIOS/UEFI:"
    warn "  BIOS → Power Management → Wake-on-LAN → Enabled"
    if [ "$HARDENED" -eq 0 ]; then
        info "PAM (direct): WoL magic packet sent as broadcast 255.255.255.255:9."
    else
        info "PAM-hardened: WoL magic packet sent unicast to 10.0.0.2:9 via WireGuard."
        warn "  Limitation: works in light sleep only (WireGuard kernel module loaded)."
        warn "  Deep sleep (WG process down) prevents IP-layer delivery to the NIC."
    fi
fi

# ── Hardened mode: WireGuard setup (PC side) ─────────────────────────────
if [ "$HARDENED" -eq 1 ]; then
    echo ""
    info "─── WireGuard setup (hardened mode, PC side) ───────────────────"
    command -v wg >/dev/null 2>&1 || die "WireGuard not installed. Install: sudo pacman -S wireguard-tools"

    PC_PRIV=$(wg genkey)
    PC_PUB=$(echo "${PC_PRIV}" | wg pubkey)

    echo ""
    echo -e "${BOLD}PC WireGuard public key (add this to VPS wg0.conf as a Peer):${NC}"
    echo -e "${BLUE}${PC_PUB}${NC}"
    echo ""
    read -rp "  VPS WireGuard public key:               " VPS_PUB
    read -rp "  VPS endpoint (IP:port):                 " VPS_ENDPOINT
    read -rp "  PC_PSK from relay-setup.sh output:      " PC_PSK
    [ -n "$PC_PSK" ] || die "PC_PSK is required (generate with relay-setup.sh first)."

    sudo tee /etc/wireguard/wg0.conf > /dev/null <<WG
[Interface]
PrivateKey = ${PC_PRIV}
Address    = 10.0.0.2/24

[Peer]
PublicKey           = ${VPS_PUB}
PresharedKey        = ${PC_PSK}
Endpoint            = ${VPS_ENDPOINT}
AllowedIPs          = 10.0.0.0/24
PersistentKeepalive = 25
WG
    sudo chmod 600 /etc/wireguard/wg0.conf
    sudo systemctl enable --now wg-quick@wg0
    ok "WireGuard wg0 configured (PC: 10.0.0.2, VPS peer: ${VPS_ENDPOINT})"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  PAM setup complete${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
info "  Config:  ${CONFIG_DIR}/"
info "  CA:      ${CA_DIR}/ca.key.enc"
info "  Audit:   ${CONFIG_DIR}/audit_sign.key (private) + audit_sign.pub (public)"
info "  Mode:    ${MODE}, port ${PORT}, bind ${BIND_IP}"
echo ""
info "  Start daemon:  systemctl --user start rofi-bridge"
info "  Enable daemon: systemctl --user enable rofi-bridge"
info "  GUI:           pam-gui  (after: cd gui && make && make install)"
echo ""
if [ "$HARDENED" -eq 1 ]; then
    info "  Hardened: run relay-setup.sh on VPS first,"
    info "            then: wg show   (verify tunnel)"
fi
echo ""
