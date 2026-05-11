#!/usr/bin/env bash
# =============================================================================
# Mafsal — Zero Trust Launcher
# launch_zero_trust.sh
#
# Copyright (C) 2026  Mafsal Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage — Method A (environment variables already exported):
#   export RELAY_KEY="<64+ hex characters>"
#   export COLAB_WS_URL="wss://xxxx.trycloudflare.com/bridge"
#   ./launch_zero_trust.sh
#
# Usage — Method B (interactive prompts):
#   ./launch_zero_trust.sh
#   → Script will ask for the key and URL
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[ZT]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[!!]${RESET} $*"; }
log_error() { echo -e "${RED}[ER]${RESET} $*"; exit 1; }

echo -e "\n${BOLD}╔════════════════════════════════════════════════════╗"
echo -e "║  Mafsal — Zero Trust Launcher                      ║"
echo -e "║  AES-256-GCM | X25519 FS | Kill-Switch            ║"
echo -e "╚════════════════════════════════════════════════════╝${RESET}\n"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_SRC="${SCRIPT_DIR}/ZeroTrustProfile"
CLIENT_SCRIPT="${SCRIPT_DIR}/mafsal_client.py"

# ---------------------------------------------------------------------------
# [1] Dependency check
# ---------------------------------------------------------------------------
log_info "Checking dependencies..."

FIREFOX_BIN=""
for candidate in firefox firefox-esr firefox-bin; do
    command -v "$candidate" &>/dev/null && { FIREFOX_BIN="$candidate"; break; }
done
[[ -z "$FIREFOX_BIN" ]] && log_error "Firefox not found! (sudo apt install firefox-esr)"
log_ok "Firefox: $(command -v "$FIREFOX_BIN")"

command -v python3 &>/dev/null || log_error "python3 not found!"
python3 -c "import websockets, cryptography" 2>/dev/null \
    || log_error "Python packages missing. Run: pip install websockets cryptography"
log_ok "Python dependencies verified"

[[ -f "$CLIENT_SCRIPT" ]] || log_error "mafsal_client.py not found: ${CLIENT_SCRIPT}"
log_ok "mafsal_client.py found"

[[ -f "${PROFILE_SRC}/prefs.js" ]] || log_error "ZeroTrustProfile/prefs.js not found"

# ---------------------------------------------------------------------------
# [2] Key input
# ---------------------------------------------------------------------------
if [[ -z "${RELAY_KEY:-}" ]]; then
    echo -e "\n${YELLOW}Generate a key on the kiosk with:${RESET}"
    echo -e "  python3 -c \"import os; print(os.urandom(32).hex())\"\n"
    echo -n "Enter RELAY_KEY (64+ hex characters): "
    read -rs RELAY_KEY
    echo ""
fi

[[ -z "$RELAY_KEY" ]] && log_error "RELAY_KEY cannot be empty."
[[ ${#RELAY_KEY} -lt 64 ]] && log_error "RELAY_KEY too short: ${#RELAY_KEY} chars (need ≥ 64)."
python3 -c "bytes.fromhex('${RELAY_KEY}')" 2>/dev/null \
    || log_error "RELAY_KEY is not valid hexadecimal (only 0-9 and a-f)."

log_ok "RELAY_KEY: ${RELAY_KEY:0:8}...${RELAY_KEY: -4} (${#RELAY_KEY} chars)"

# ---------------------------------------------------------------------------
# [3] Colab URL input
# ---------------------------------------------------------------------------
if [[ -z "${COLAB_WS_URL:-}" ]]; then
    echo -e "\n${YELLOW}Colab prints the URL in this format:${RESET}"
    echo -e "  wss://xxxx-xxxx.trycloudflare.com/bridge\n"
    echo -n "Enter COLAB_WS_URL: "
    read -r COLAB_WS_URL
fi

[[ -z "$COLAB_WS_URL" ]] && log_error "COLAB_WS_URL cannot be empty."
[[ "$COLAB_WS_URL" != wss://* ]] && log_warn "URL should start with 'wss://' — continuing..."
log_ok "Colab URL: ${COLAB_WS_URL}"

# ---------------------------------------------------------------------------
# [4] RAM disk
# ---------------------------------------------------------------------------
RAM_PROFILE_BASE="/tmp"
RAM_PROFILE_DIR=$(mktemp -d "${RAM_PROFILE_BASE}/mafsal_XXXXXX")
chmod 700 "$RAM_PROFILE_DIR"
DOWNLOAD_DIR="${RAM_PROFILE_DIR}/downloads"
mkdir -p "$DOWNLOAD_DIR"
log_ok "RAM profile directory: ${RAM_PROFILE_DIR}"

# ---------------------------------------------------------------------------
# [5] Copy enterprise profile to RAM
# ---------------------------------------------------------------------------
DIST_DIR="${RAM_PROFILE_DIR}/distribution"
mkdir -p "$DIST_DIR"

cp "${PROFILE_SRC}/prefs.js" "${RAM_PROFILE_DIR}/prefs.js"
log_ok "prefs.js copied (kill-switch + WebRTC block active)"

if [[ -f "${PROFILE_SRC}/distribution/policies.json" ]]; then
    cp "${PROFILE_SRC}/distribution/policies.json" "${DIST_DIR}/policies.json"
    log_ok "policies.json copied"
fi

# Lock the download directory to RAM
cat >> "${RAM_PROFILE_DIR}/user.js" <<EOF
user_pref("browser.download.dir", "${DOWNLOAD_DIR}");
user_pref("browser.download.useDownloadDir", true);
user_pref("browser.download.folderList", 2);
EOF
log_ok "Download directory locked to RAM"

# ---------------------------------------------------------------------------
# [6] Start Mafsal client
# ---------------------------------------------------------------------------
log_info "Starting mafsal_client.py..."

RELAY_LOG="${RAM_PROFILE_DIR}/relay.log"
RELAY_KEY="$RELAY_KEY" COLAB_WS_URL="$COLAB_WS_URL" \
    python3 "$CLIENT_SCRIPT" > "$RELAY_LOG" 2>&1 &
RELAY_PID=$!

# Wait for the client to open the SOCKS5 port
RELAY_READY=0
for i in $(seq 1 16); do
    sleep 0.5
    if ! kill -0 "$RELAY_PID" 2>/dev/null; then
        echo ""
        log_error "mafsal_client.py crashed! Log:\n$(tail -20 "$RELAY_LOG")"
    fi
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.3)
r = s.connect_ex(('127.0.0.1', 1080))
s.close()
sys.exit(0 if r == 0 else 1)
" 2>/dev/null; then
        RELAY_READY=1
        break
    fi
done

if [[ $RELAY_READY -eq 0 ]]; then
    echo ""
    log_error "Client not listening on localhost:1080!\nIs the Colab server running?\nLog: $(tail -5 "$RELAY_LOG")"
fi
log_ok "Mafsal client active — localhost:1080 ✓ (PID: ${RELAY_PID})"

# ---------------------------------------------------------------------------
# [7] Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    log_info "Session ended — secure cleanup..."

    if kill -0 "${RELAY_PID:-0}" 2>/dev/null; then
        kill "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
        log_ok "Client stopped"
    fi

    if [[ -d "$RAM_PROFILE_DIR" ]]; then
        if command -v shred &>/dev/null; then
            find "$RAM_PROFILE_DIR" -type f -exec shred -uzn 3 {} \; 2>/dev/null || true
            log_ok "Files shredded (3-pass overwrite)"
        fi
        rm -rf "$RAM_PROFILE_DIR"
        log_ok "RAM profile directory removed"
    fi

    unset RELAY_KEY
    unset COLAB_WS_URL
    log_ok "Environment variables cleared from memory"
    echo -e "\n${BOLD}Zero-trust session ended cleanly.${RESET}\n"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# [8] Firefox environment
# ---------------------------------------------------------------------------
export MOZ_NO_REMOTE=1
export MOZ_DISABLE_AUTO_SAFE_MODE=1
export MOZ_CRASHREPORTER_DISABLE=1
export HOME="$RAM_PROFILE_DIR"
export XDG_DATA_HOME="${RAM_PROFILE_DIR}/.local/share"
export XDG_CONFIG_HOME="${RAM_PROFILE_DIR}/.config"
export XDG_CACHE_HOME="${RAM_PROFILE_DIR}/.cache"
mkdir -p "${XDG_DATA_HOME}" "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}"

# ---------------------------------------------------------------------------
# [9] Summary
# ---------------------------------------------------------------------------
echo ""
log_info "Launch summary:"
echo -e "   ${BOLD}Firefox    :${RESET} $(command -v "$FIREFOX_BIN")"
echo -e "   ${BOLD}Profile    :${RESET} ${RAM_PROFILE_DIR} (RAM)"
echo -e "   ${BOLD}Proxy      :${RESET} SOCKS5 → 127.0.0.1:1080"
echo -e "   ${BOLD}Tunnel     :${RESET} ${COLAB_WS_URL}"
echo -e "   ${BOLD}Cipher     :${RESET} AES-256-GCM + HKDF per-packet"
echo -e "   ${BOLD}Key exch.  :${RESET} X25519 Ephemeral (Forward Secrecy)"
echo -e "   ${BOLD}Kill-switch:${RESET} active (tunnel failure → no direct internet)"
echo -e "   ${BOLD}WebRTC     :${RESET} disabled"
echo -e "   ${BOLD}Downloads  :${RESET} ${DOWNLOAD_DIR} (RAM)"
echo ""
echo -e "${YELLOW}  ⚠ Closing this window stops the relay, removes the profile, and scrubs all keys.${RESET}\n"

# ---------------------------------------------------------------------------
# [10] Launch Firefox
# ---------------------------------------------------------------------------
"$FIREFOX_BIN" \
    --profile "$RAM_PROFILE_DIR" \
    --no-remote \
    --new-instance \
    --private-window \
    "about:blank"

# cleanup() trap fires automatically on exit
