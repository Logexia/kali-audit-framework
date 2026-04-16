#!/bin/bash
#============================================================================
# PME IT AUDIT FRAMEWORK v4.5 - Orchestrateur
#
# Pipeline 6 phases:
#   1. Discovery       (réseau, hôtes, services, OS)
#   2. Enumeration     (SMB, SNMP, DNS, Email)
#   3. AD Deep Checks  (PingCastle-style)
#   4. Vuln Scan       (CVE + OpenVAS + Exploitability + SSL + WiFi)
#   5. Consolidation   (JSON unifié, scoring, historique)
#   6. HTML Report     (rapport + quality check)
#============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"

CLIENT_NAME="" ; NETWORK="" ; DOMAIN_CONTROLLER="" ; URLS_FILE=""
WIFI_INTERFACE="" ; OUTPUT_DIR="" ; MODULES="all"
SKIP_OPENVAS="false" ; CLIENT_DOMAIN="" ; EXCLUDE_MODULES=""
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ══════════════════════════════════════════════════════════════════════════
# HELP
# ══════════════════════════════════════════════════════════════════════════
usage() {
    cat <<EOF

${BOLD}╔═══════════════════════════════════════════════════════════╗
║         PME IT AUDIT FRAMEWORK v4.5                       ║
╚═══════════════════════════════════════════════════════════╝${NC}

${BOLD}USAGE:${NC}
  $0 --client NAME --network CIDR [options]

${BOLD}OBLIGATOIRE:${NC}
  --client NAME          Nom du client (ex: "ACME Corp")
  --network CIDR         Réseau cible (ex: 192.168.1.0/24)

${BOLD}OPTIONNEL:${NC}
  --domain FQDN          Domaine pour audit email SPF/DKIM/DMARC
  --dc IP                IP contrôleur de domaine
  --urls FILE            Fichier URLs pour scan SSL
  --wifi IFACE           Interface WiFi (ex: wlan0)
  --output DIR           Répertoire de sortie

${BOLD}CONTRÔLE DES MODULES:${NC}
  --modules LIST         Exécuter uniquement ces modules (virgules)
  --exclude-module NAME  Exclure un module (répétable)
  --skip-openvas         Forcer le mode dégradé OpenVAS

${BOLD}MODULES DISPONIBLES:${NC}

  ${BOLD}Phase 1 — Discovery${NC}
    discovery       Découverte réseau (Nmap, inventaire hôtes/services/OS)

  ${BOLD}Phase 2 — Enumeration${NC}
    smb             Audit SMB (partages, versions, signing, droits)
    snmp            Audit SNMP (community strings, topologie)
    dns             Audit DNS (zone transfer, subdomains, records)
    email           Sécurité email (SPF, DKIM, DMARC, MX, STARTTLS)
                    Requiert: --domain

  ${BOLD}Phase 3 — Active Directory${NC}
    ad              AD deep checks (PingCastle-style, scoring 0-100)
                    Recommandé: --dc

  ${BOLD}Phase 4 — Vulnerability Scan${NC}
    wifi            Audit WiFi (réseaux, chiffrement, WPS)
                    Requiert: --wifi
    cve             CVE baseline (Nmap vulners, WhatWeb, Nikto)
    openvas         OpenVAS / Greenbone (scan complet)
                    Requiert: GVM installé
    exploitability  Exploitabilité (searchsploit + MSF lookup, indicatif)
    ssl             Audit SSL/TLS (protocoles, certificats, faiblesses)
    web_owasp       Audit Web OWASP Top 10 (gobuster, sqlmap, wafw00f,
                    headers, cookies, CMS, WAF)

${BOLD}EXEMPLES:${NC}

  Audit complet:
    $0 --client "ACME" --network 192.168.1.0/24 \\
       --domain acme.ch --dc 192.168.1.10 --wifi wlan0

  Sans WiFi ni SNMP:
    $0 --client "ACME" --network 192.168.1.0/24 \\
       --exclude-module wifi --exclude-module snmp

  Seulement discovery + CVE + SSL:
    $0 --client "ACME" --network 192.168.1.0/24 \\
       --modules discovery,cve,ssl

  Variables OpenVAS:
    GVM_USER=admin GVM_PASS=secret $0 --client "ACME" --network 10.0.0.0/24

${BOLD}HISTORIQUE:${NC}
  Si des rapports précédents existent pour le même client dans /opt/audits/,
  le rapport HTML inclura automatiquement une section tendances avec
  l'évolution du score de risque et des vulnérabilités.

EOF
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════
# PARSE ARGS
# ══════════════════════════════════════════════════════════════════════════
while [[ $# -gt 0 ]]; do
    case $1 in
        --client)          CLIENT_NAME="$2";         shift 2 ;;
        --network)         NETWORK="$2";             shift 2 ;;
        --domain)          CLIENT_DOMAIN="$2";       shift 2 ;;
        --dc)              DOMAIN_CONTROLLER="$2";   shift 2 ;;
        --urls)            URLS_FILE="$2";           shift 2 ;;
        --wifi)            WIFI_INTERFACE="$2";      shift 2 ;;
        --output)          OUTPUT_DIR="$2";          shift 2 ;;
        --modules)         MODULES="$2";             shift 2 ;;
        --exclude-module)  EXCLUDE_MODULES="${EXCLUDE_MODULES:+$EXCLUDE_MODULES,}$2"; shift 2 ;;
        --skip-openvas)    SKIP_OPENVAS="true";      shift ;;
        --help|-h)         usage ;;
        --list-modules)
            echo "discovery smb snmp dns email ad wifi cve openvas exploitability ssl web_owasp"
            exit 0 ;;
        *) error "Option inconnue: $1"; echo "Utiliser --help"; exit 1 ;;
    esac
done

[[ -z "$CLIENT_NAME" || -z "$NETWORK" ]] && { error "--client et --network requis"; echo "Voir --help"; exit 1; }

if [[ -z "$OUTPUT_DIR" ]]; then
    SLUG=$(echo "$CLIENT_NAME" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')
    OUTPUT_DIR="/opt/audits/${SLUG}_${TIMESTAMP}"
fi
mkdir -p "$OUTPUT_DIR"/{discovery,smb,cve,openvas,exploitability,ssl,wifi,ad,snmp,dns,email_security,web_owasp,report}

export CLIENT_NAME NETWORK DOMAIN_CONTROLLER URLS_FILE WIFI_INTERFACE OUTPUT_DIR SCRIPT_DIR
export TIMESTAMP SKIP_OPENVAS CLIENT_DOMAIN EXCLUDE_MODULES

LOG_FILE="$OUTPUT_DIR/audit.log"
exec > >(tee -a "$LOG_FILE") 2>&1

cat > "$OUTPUT_DIR/audit_config.json" <<CONF
{
  "framework_version": "4.5",
  "client": "$CLIENT_NAME",
  "network": "$NETWORK",
  "domain": "${CLIENT_DOMAIN:-null}",
  "dc": "${DOMAIN_CONTROLLER:-null}",
  "wifi": "${WIFI_INTERFACE:-null}",
  "modules": "$MODULES",
  "exclude_modules": "${EXCLUDE_MODULES:-none}",
  "skip_openvas": $SKIP_OPENVAS,
  "timestamp": "$TIMESTAMP",
  "auditor": "$(whoami)@$(hostname)"
}
CONF

# ── Module helpers ────────────────────────────────────────────────────────
check_deps() {
    phase "Vérification des outils"
    for cmd in nmap smbclient sslscan python3 dig; do need "$cmd" || true; done
    for cmd in whatweb nikto enum4linux crackmapexec nxc testssl nbtscan \
               ldapsearch rpcclient snmpwalk snmp-check dnsrecon dnsenum \
               airmon-ng airodump-ng wash onesixtyone impacket-GetNPUsers \
               impacket-GetUserSPNs impacket-findDelegation gvm-cli searchsploit msfconsole \
               gobuster feroxbuster wafw00f wpscan sqlmap; do
        command -v "$cmd" &>/dev/null && success "$cmd" || true
    done
}

run_module() {
    local script="$SCRIPT_DIR/modules/$1.sh"
    [[ ! -f "$script" ]] && { error "Module introuvable: $script"; return 1; }
    phase "MODULE: $1"
    local t0=$(date +%s)
    bash "$script"
    local rc=$? dt=$(( $(date +%s) - t0 ))
    [[ $rc -eq 0 ]] && success "$1 terminé (${dt}s)" || warning "$1 code $rc (${dt}s)"
    return 0
}

is_excluded() {
    [[ -z "$EXCLUDE_MODULES" ]] && return 1
    echo ",$EXCLUDE_MODULES," | grep -qi ",$1,"
}

should_run() {
    is_excluded "$1" && return 1
    [[ "$MODULES" == "all" ]] || echo ",$MODULES," | grep -qi ",$1,"
}

# Tracker: quels modules ont tourné (pour cacher dans le rapport)
MODULES_RAN=""
track() { MODULES_RAN="${MODULES_RAN:+$MODULES_RAN,}$1"; }

# ══════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         PME IT AUDIT FRAMEWORK v4.5                       ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Client:     $CLIENT_NAME"
echo "  Réseau:     $NETWORK"
echo "  Domaine:    ${CLIENT_DOMAIN:-(non spécifié)}"
echo "  DC:         ${DOMAIN_CONTROLLER:-(auto)}"
echo "  WiFi:       ${WIFI_INTERFACE:-(désactivé)}"
echo "  Date:       $(date '+%d/%m/%Y %H:%M')"
echo "  Output:     $OUTPUT_DIR"
[[ -n "$EXCLUDE_MODULES" ]] && echo -e "  ${YELLOW}Exclus:     $EXCLUDE_MODULES${NC}"
echo ""

check_deps

# ── Phase 1 ───────────────────────────────────────────────────────────────
phase "PHASE 1 — DISCOVERY"
should_run "discovery" && { run_module "01_discovery"; track discovery; }

# ── Phase 2 ───────────────────────────────────────────────────────────────
phase "PHASE 2 — ENUMERATION"
should_run "smb"  && { run_module "02_smb"; track smb; }
should_run "snmp" && { run_module "03_snmp"; track snmp; }
should_run "dns"  && { run_module "04_dns"; track dns; }
if should_run "email"; then
    if [[ -n "$CLIENT_DOMAIN" ]]; then run_module "04b_email_security"; track email
    else warning "Pas de --domain → email sauté"; fi
fi

# ── Phase 3 ───────────────────────────────────────────────────────────────
phase "PHASE 3 — AD DEEP CHECKS"
should_run "ad" && { run_module "05_ad"; track ad; }

# ── Phase 4 ───────────────────────────────────────────────────────────────
phase "PHASE 4 — VULNERABILITY SCAN"
should_run "wifi"           && { run_module "06_wifi"; track wifi; }
should_run "cve"            && { run_module "07_cve"; track cve; }
should_run "openvas"        && { run_module "07b_openvas"; track openvas; }
should_run "exploitability" && { run_module "07c_exploitability"; track exploitability; }
should_run "web_owasp"      && { run_module "09_web_owasp"; track web_owasp; }
should_run "ssl"            && { run_module "08_ssl"; track ssl; }

# ── Sauver la liste des modules exécutés ──────────────────────────────────
echo "$MODULES_RAN" > "$OUTPUT_DIR/report/modules_ran.txt"
export MODULES_RAN

# ── Phase 5 ───────────────────────────────────────────────────────────────
phase "PHASE 5 — CONSOLIDATION"
bash "$SCRIPT_DIR/scripts/consolidate.sh"

# ── Phase 6 ───────────────────────────────────────────────────────────────
phase "PHASE 6 — RAPPORTS"
bash "$SCRIPT_DIR/scripts/generate_report.sh"
bash "$SCRIPT_DIR/scripts/generate_report_docx.sh"
bash "$SCRIPT_DIR/scripts/quality_check.sh"

echo ""
success "AUDIT TERMINÉ"
log "Rapport HTML:  $OUTPUT_DIR/report/rapport_audit.html"
log "Rapport DOCX:  $OUTPUT_DIR/report/rapport_audit.docx"
log "Log:           $LOG_FILE"
