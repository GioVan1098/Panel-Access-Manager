#!/usr/bin/env bash
# relay-setup.sh — PAM-hardened: WireGuard relay setup for VPS
#
# Run this script on the VPS (Oracle Free Tier / Hetzner / any Linux VPS).
# It configures WireGuard, NAT forwarding, and UFW rules.
# After this script completes, take note of the VPS public key AND the
# PC pre-shared key, and pass both to setup.sh --hardened on your PC.
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── Prerequisites ─────────────────────────────────────────────────────────
info "Checking prerequisites..."
for cmd in wg wg-quick iptables ip; do
    command -v "$cmd" >/dev/null 2>&1 || {
        info "Installing wireguard-tools..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -qq && sudo apt-get install -y wireguard-tools
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y wireguard-tools
        else
            die "Install wireguard-tools manually, then re-run."
        fi
        break
    }
done
ok "WireGuard tools available"

# ── Detect external network interface ─────────────────────────────────────
ETH=$(ip route show default | awk '/default/{print $5; exit}')
[ -n "$ETH" ] || die "Could not detect default network interface."
info "External interface: ${ETH}"

# ── VPS WireGuard keypair ─────────────────────────────────────────────────
info "Generating VPS WireGuard keypair..."
VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "${VPS_PRIV}" | wg pubkey)

echo ""
echo -e "${BOLD}VPS public key (share this with your PC for setup.sh --hardened):${NC}"
echo -e "${BLUE}${VPS_PUB}${NC}"
echo ""

# ── Collect PC public key ─────────────────────────────────────────────────
read -rp "Enter PC WireGuard public key: " PC_PUB
[ -n "$PC_PUB" ] || die "PC public key is required."

# ── Optional Android peer ─────────────────────────────────────────────────
echo ""
echo "Generate WireGuard keypair for Android client? [Y/n]"
read -rp "  (leave blank for yes): " GEN_ANDROID
GEN_ANDROID="${GEN_ANDROID:-y}"

ANDROID_PRIV=""
ANDROID_PUB=""
if [[ "${GEN_ANDROID,,}" != "n" ]]; then
    ANDROID_PRIV=$(wg genkey)
    ANDROID_PUB=$(echo "${ANDROID_PRIV}" | wg pubkey)
    ok "Android keypair generated"
fi

# ── Pre-shared keys (L-D — quantum resistance, per-peer) ──────────────────
# Each PSK is a unique 32-byte symmetric key placed in the [Peer] block
# on BOTH sides of the peering. It adds a layer of symmetric encryption
# on top of the Curve25519 key exchange (Noise_IKpsk2 handshake),
# providing resistance against future quantum attacks on the ECDH step.
# The VPS and PC must have the SAME PC_PSK; VPS and Android the SAME ANDROID_PSK.
info "Generating WireGuard pre-shared keys..."
PC_PSK=$(wg genpsk)
ANDROID_PSK=$(wg genpsk)
ok "Pre-shared keys generated"

# ── Build wg0.conf ────────────────────────────────────────────────────────
info "Writing /etc/wireguard/wg0.conf..."
sudo tee /etc/wireguard/wg0.conf > /dev/null <<WG
[Interface]
PrivateKey = ${VPS_PRIV}
Address    = 10.0.0.1/24
ListenPort = 51820
PostUp     = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${ETH} -j MASQUERADE
PostDown   = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${ETH} -j MASQUERADE

[Peer]
# PC (PAM daemon — binds to 10.0.0.2:7443)
PublicKey    = ${PC_PUB}
PresharedKey = ${PC_PSK}
AllowedIPs   = 10.0.0.2/32
WG

if [ -n "$ANDROID_PUB" ]; then
    sudo tee -a /etc/wireguard/wg0.conf > /dev/null <<WG

[Peer]
# Android client
PublicKey    = ${ANDROID_PUB}
PresharedKey = ${ANDROID_PSK}
AllowedIPs   = 10.0.0.3/32
WG
fi

sudo chmod 600 /etc/wireguard/wg0.conf
ok "wg0.conf written"

# ── IP forwarding ─────────────────────────────────────────────────────────
info "Enabling IPv4 forwarding..."
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-pam-wg.conf > /dev/null
sudo sysctl -p /etc/sysctl.d/99-pam-wg.conf > /dev/null
ok "IPv4 forwarding enabled"

# ── Firewall rules (UFW) ──────────────────────────────────────────────────
if command -v ufw >/dev/null 2>&1; then
    info "Configuring UFW rules..."
    sudo ufw allow 51820/udp comment "WireGuard — PAM relay"
    ok "UFW rules added (UDP/51820)"
    info "Port 7443 is NOT opened: the PAM daemon runs on the PC (10.0.0.2:7443)"
    info "inside the WireGuard tunnel — it is never reachable from the public internet."
else
    warn "ufw not found. Add this rule manually:"
    warn "  iptables -A INPUT -p udp --dport 51820 -j ACCEPT"
fi

# ── Start and enable WireGuard ────────────────────────────────────────────
info "Enabling and starting wg-quick@wg0..."
sudo systemctl enable --now wg-quick@wg0
ok "WireGuard wg0 started (VPS: 10.0.0.1)"

# Verify tunnel is up
sleep 1
wg show wg0 | grep -q "interface:" && ok "wg0 interface is up" || warn "wg0 may not be running — check: sudo wg show"

# ── Android WireGuard client config ───────────────────────────────────────
VPS_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
         curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null || \
         echo "<VPS_PUBLIC_IP>")

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  VPS relay configured${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
info "  WireGuard VPS: 10.0.0.1  (this machine)"
info "  PC daemon:     10.0.0.2  (setup.sh --hardened)"
info "  Android:       10.0.0.3  (WireGuard client)"
echo ""

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  IMPORTANT — Pre-shared keys (save these securely)${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}PC_PSK (needed for setup.sh --hardened on the PC):${NC}"
echo -e "  ${BLUE}${PC_PSK}${NC}"
echo ""
if [ -n "$ANDROID_PUB" ]; then
    echo -e "  ${BOLD}ANDROID_PSK (for Android WireGuard config below):${NC}"
    echo -e "  ${BLUE}${ANDROID_PSK}${NC}"
    echo ""
fi
warn "These keys cannot be retrieved after this script exits."
echo ""

if [ -n "$ANDROID_PRIV" ]; then
    echo -e "${BOLD}Android WireGuard client config (import into WireGuard app):${NC}"
    echo ""
    cat <<ANDROID
[Interface]
PrivateKey = ${ANDROID_PRIV}
Address    = 10.0.0.3/24
DNS        = 1.1.1.1

[Peer]
PublicKey           = ${VPS_PUB}
PresharedKey        = ${ANDROID_PSK}
Endpoint            = ${VPS_IP}:51820
AllowedIPs          = 10.0.0.0/24
PersistentKeepalive = 25
ANDROID
    echo ""
    warn "Save the Android config above — the private key cannot be retrieved later."
fi

info "Next: run setup.sh --hardened on the PC."
info "You will need: VPS public key (${VPS_PUB}) and PC_PSK (shown above)."
echo ""
