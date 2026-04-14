#!/bin/bash
#============================================================================
# COMMON.SH - Fonctions partagées par tous les modules
# [NON-REGRESSION] Inchangé depuis v4
#============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; GRAY='\033[0;90m'
NC='\033[0m'; BOLD='\033[1m'

log()     { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warning() { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }
phase()   { echo -e "\n${CYAN}━━━ ${BOLD}$*${NC}${CYAN} ━━━${NC}\n"; }

need() {
    if command -v "$1" &>/dev/null; then return 0
    else warning "$1 non disponible (apt install $1)"; return 1; fi
}

export -f log success warning error phase need 2>/dev/null || true
export RED GREEN YELLOW BLUE CYAN GRAY NC BOLD 2>/dev/null || true
