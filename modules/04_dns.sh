#!/bin/bash
#============================================================================
# 04 - DNS: Zone transfer, enum sous-domaines, misconfig
# v4.5.1 — Ajouts: DNSSEC validation, wildcard DNS, DNS rebinding check
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/dns"
DNS_HOSTS="$OUTPUT_DIR/discovery/dns_hosts.txt"

if [[ ! -s "$DNS_HOSTS" ]]; then
    nmap -p 53 --open "$NETWORK" -oG - 2>/dev/null | grep "53/open" | awk '{print $2}' > "$DNS_HOSTS"
fi

DOMAIN=""
if [[ -n "${CLIENT_DOMAIN:-}" ]]; then
    DOMAIN="$CLIENT_DOMAIN"
elif [[ -n "${DOMAIN_CONTROLLER:-}" ]]; then
    DOMAIN=$(nmap -sC -p 389 "$DOMAIN_CONTROLLER" 2>/dev/null | grep -oP '(?<=Domain: )\S+' | head -1)
fi
if [[ -z "$DOMAIN" && -s "$DNS_HOSTS" ]]; then
    DOMAIN=$(nmap -sC -p 53 -iL "$DNS_HOSTS" 2>/dev/null | grep -oP '(?<=Domain: )\S+' | head -1)
fi

if [[ ! -s "$DNS_HOSTS" && -z "$DOMAIN" ]]; then
    warning "Aucun serveur DNS ni domaine"
    echo '{"issues":[],"counts":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}}' > "$OUT/summary.json"
    exit 0
fi
log "DNS: $(wc -l < "$DNS_HOSTS" 2>/dev/null || echo 0) serveurs | Domaine: ${DOMAIN:-inconnu}"

# ══════════════════════════════════════════════════════════════════════════
# ZONE TRANSFER (AXFR)
# ══════════════════════════════════════════════════════════════════════════
log "Test transferts de zone (AXFR)"
> "$OUT/zone_transfers.txt"
while IFS= read -r dns_ip; do
    [[ -z "$dns_ip" ]] && continue
    if [[ -n "$DOMAIN" ]]; then
        echo "=== AXFR $DOMAIN @$dns_ip ===" >> "$OUT/zone_transfers.txt"
        dig axfr "$DOMAIN" @"$dns_ip" >> "$OUT/zone_transfers.txt" 2>/dev/null
        echo "" >> "$OUT/zone_transfers.txt"
    fi
    NET_PREFIX=$(echo "$NETWORK" | cut -d. -f1-3)
    REV_ZONE=$(echo "$NET_PREFIX" | awk -F. '{print $3"."$2"."$1}').in-addr.arpa
    result_rev=$(dig axfr "$REV_ZONE" @"$dns_ip" 2>/dev/null)
    if echo "$result_rev" | grep -q "XFR size"; then
        echo "=== AXFR reverse $REV_ZONE @$dns_ip ===" >> "$OUT/zone_transfers.txt"
        echo "$result_rev" >> "$OUT/zone_transfers.txt"
    fi
done < "$DNS_HOSTS"

# ══════════════════════════════════════════════════════════════════════════
# DNSSEC VALIDATION
# ══════════════════════════════════════════════════════════════════════════
log "DNSSEC validation"
> "$OUT/dnssec.txt"
if [[ -n "$DOMAIN" ]]; then
    # DS record (existence dans le domaine parent)
    echo "=== DS record ===" >> "$OUT/dnssec.txt"
    dig +short DS "$DOMAIN" >> "$OUT/dnssec.txt" 2>/dev/null || echo "(pas de DS)" >> "$OUT/dnssec.txt"

    # DNSKEY record
    echo "=== DNSKEY ===" >> "$OUT/dnssec.txt"
    dig +short DNSKEY "$DOMAIN" >> "$OUT/dnssec.txt" 2>/dev/null || echo "(pas de DNSKEY)" >> "$OUT/dnssec.txt"

    # SOA avec validation DNSSEC
    echo "=== SOA + DNSSEC validation ===" >> "$OUT/dnssec.txt"
    dig +dnssec SOA "$DOMAIN" >> "$OUT/dnssec.txt" 2>/dev/null || true

    # Vérification avec un resolver public (si disponible)
    if [[ -s "$DNS_HOSTS" ]]; then
        DNS_IP=$(head -1 "$DNS_HOSTS")
        echo "=== DNSSEC check via $DNS_IP ===" >> "$OUT/dnssec.txt"
        dig +dnssec +sigchase "$DOMAIN" @"$DNS_IP" A >> "$OUT/dnssec.txt" 2>/dev/null || \
        dig +dnssec "$DOMAIN" @"$DNS_IP" A >> "$OUT/dnssec.txt" 2>/dev/null || true
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
# WILDCARD DNS
# ══════════════════════════════════════════════════════════════════════════
log "Wildcard DNS check"
> "$OUT/wildcard.txt"
if [[ -n "$DOMAIN" && -s "$DNS_HOSTS" ]]; then
    DNS_IP=$(head -1 "$DNS_HOSTS")
    RAND1="nonexistent-$(date +%s)-audit"
    RAND2="xrandom-$(openssl rand -hex 4 2>/dev/null || echo 'testxyz')"
    for rnd in "$RAND1" "$RAND2"; do
        result=$(dig +short A "${rnd}.${DOMAIN}" @"$DNS_IP" 2>/dev/null)
        echo "${rnd}.${DOMAIN} → ${result:-NXDOMAIN}" >> "$OUT/wildcard.txt"
    done
fi

# ══════════════════════════════════════════════════════════════════════════
# DNS REBINDING CHECK
# ══════════════════════════════════════════════════════════════════════════
log "DNS rebinding check"
> "$OUT/rebinding.txt"
if [[ -n "$DOMAIN" ]]; then
    # Vérifier si des sous-domaines public résolvent vers des IPs privées (RFC1918)
    # On utilise dnsrecon ou dig sur les enregistrements A connus
    PRIVATE_RANGES="^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[01]\.\|^192\.168\."
    {
        dig +short A "$DOMAIN" 2>/dev/null
        dig +short A "www.$DOMAIN" 2>/dev/null
        dig +short A "mail.$DOMAIN" 2>/dev/null
        dig +short A "ftp.$DOMAIN" 2>/dev/null
    } | grep -E "$PRIVATE_RANGES" >> "$OUT/rebinding.txt" 2>/dev/null || true

    if [[ -s "$OUT/rebinding.txt" ]]; then
        warning "DNS rebinding potentiel: IPs privées dans résolution publique"
    else
        echo "(aucun rebinding détecté)" >> "$OUT/rebinding.txt"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
# ENUM (dnsrecon + dnsenum)
# ══════════════════════════════════════════════════════════════════════════
if [[ -n "$DOMAIN" ]]; then
    command -v dnsrecon &>/dev/null && {
        log "dnsrecon"
        timeout 120 dnsrecon -d "$DOMAIN" -n "$(head -1 "$DNS_HOSTS")" \
            -t std,brt,axfr -j "$OUT/dnsrecon.json" > "$OUT/dnsrecon.txt" 2>/dev/null || true
    }
    command -v dnsenum &>/dev/null && {
        log "dnsenum"
        timeout 120 dnsenum --dnsserver "$(head -1 "$DNS_HOSTS")" \
            --noreverse "$DOMAIN" -o "$OUT/dnsenum.xml" > "$OUT/dnsenum.txt" 2>/dev/null || true
    }
fi

log "Nmap DNS scripts"
nmap -p 53 --script "dns-nsid,dns-recursion,dns-service-discovery,dns-cache-snoop" \
    -iL "$DNS_HOSTS" -oA "$OUT/nmap_dns" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════
# ANALYSE PYTHON
# ══════════════════════════════════════════════════════════════════════════
python3 << 'PY'
import json, os, re
from collections import Counter
out = os.environ['OUTPUT_DIR'] + '/dns'
issues = []
records = []
seen = set()

def add_issue(target, severity, issue, recommendation):
    k = f"{target}|{issue[:80]}"
    if k not in seen:
        seen.add(k)
        issues.append({'target': target, 'severity': severity,
                       'issue': issue, 'recommendation': recommendation,
                       'module': 'dns'})

# ── Zone transfer ─────────────────────────────────────────────────────
try:
    c = open(f'{out}/zone_transfers.txt').read()
    for block in c.split('=== AXFR'):
        if not block.strip():
            continue
        header = block.split('\n')[0].strip()
        if 'XFR size' in block or '\tIN\t' in block:
            m = re.search(r'@(\S+)', header)
            dns_ip = m.group(1) if m else 'inconnu'
            add_issue(dns_ip, 'HIGH',
                      f'Transfert de zone DNS autorisé ({header.split("===")[0].strip()})',
                      'Restreindre AXFR aux seuls IP des serveurs DNS secondaires autorisés')
            for line in block.split('\n'):
                if '\tIN\t' in line:
                    records.append(line.strip())
except Exception:
    pass

# ── Récursion DNS ouverte ─────────────────────────────────────────────
try:
    c = open(f'{out}/nmap_dns.nmap').read()
    host = ''
    for line in c.split('\n'):
        if 'Nmap scan report' in line:
            host = line.split()[-1].strip('()')
        if 'Recursion: Enabled' in line:
            add_issue(host, 'MEDIUM',
                      f'Récursion DNS ouverte sur {host} — amplification possible',
                      'Désactiver la récursion ouverte ou restreindre aux clients internes')
        if 'cache snooping' in line.lower() and 'vulnerable' in line.lower():
            add_issue(host, 'MEDIUM',
                      f'DNS cache snooping possible sur {host}',
                      'Désactiver le cache snooping (Response Policy Zones)')
except Exception:
    pass

# ── DNSSEC ────────────────────────────────────────────────────────────
dnssec_ok = False
domain = os.environ.get('CLIENT_DOMAIN', os.environ.get('DOMAIN', ''))
try:
    c = open(f'{out}/dnssec.txt').read()
    # DS et DNSKEY présents → DNSSEC actif
    has_ds    = bool(re.search(r'\d+ \d+ \d+ [A-Fa-f0-9]+', c))
    has_dnskey = 'DNSKEY' in c and '256 3' in c  # ZSK flag
    has_rrsig  = 'RRSIG' in c

    if has_ds or has_dnskey or has_rrsig:
        dnssec_ok = True
    else:
        if domain:
            add_issue(domain, 'MEDIUM',
                      f'DNSSEC non configuré sur {domain}',
                      'Configurer DNSSEC pour protéger contre le DNS spoofing et cache poisoning')

    # Vérifier si DNSSEC est cassé (présent mais signatures invalides)
    if re.search(r'SERVFAIL|BOGUS|validation failed', c, re.I):
        add_issue(domain or 'DNS', 'HIGH',
                  f'DNSSEC configuré mais validation échoue sur {domain}',
                  'Vérifier la chaîne de confiance DNSSEC (DS record + clés ZSK/KSK)')
except Exception:
    pass

# ── Wildcard DNS ──────────────────────────────────────────────────────
try:
    c = open(f'{out}/wildcard.txt').read()
    wildcard_ips = set()
    for line in c.split('\n'):
        if '→' in line:
            parts = line.split('→')
            resolved = parts[1].strip() if len(parts) > 1 else ''
            if resolved and resolved != 'NXDOMAIN' and not resolved.startswith('('):
                wildcard_ips.add(resolved)
    if wildcard_ips:
        add_issue(domain or 'DNS', 'MEDIUM',
                  f'Wildcard DNS détecté sur {domain}: résout vers {", ".join(wildcard_ips)}',
                  'Supprimer les enregistrements wildcard (*) DNS sauf si nécessaire (risque subdomain takeover)')
except Exception:
    pass

# ── DNS rebinding ─────────────────────────────────────────────────────
try:
    rebinding = open(f'{out}/rebinding.txt').read().strip()
    if rebinding and 'aucun' not in rebinding.lower():
        for ip in rebinding.split('\n'):
            ip = ip.strip()
            if ip:
                add_issue(domain or 'DNS', 'HIGH',
                          f'DNS rebinding potentiel: {domain} résout vers IP privée {ip}',
                          'Supprimer les enregistrements DNS pointant vers des IPs RFC1918 dans les zones publiques')
except Exception:
    pass

# ── dnsrecon records ──────────────────────────────────────────────────
try:
    data = json.load(open(f'{out}/dnsrecon.json'))
    for e in data:
        if e.get('type') in ('A','AAAA','CNAME','MX','NS','TXT','SRV'):
            records.append(f"{e.get('name','')} {e.get('type','')} {e.get('address', e.get('target',''))}")
except Exception:
    pass

# ── DNS servers list ──────────────────────────────────────────────────
dns_servers = []
dns_hosts_file = f"{os.environ['OUTPUT_DIR']}/discovery/dns_hosts.txt"
if os.path.exists(dns_hosts_file):
    dns_servers = [l.strip() for l in open(dns_hosts_file).read().strip().split('\n') if l.strip()]

counts = Counter(i['severity'] for i in issues)
json.dump({
    'domain':      domain,
    'dns_servers': dns_servers,
    'dnssec':      dnssec_ok,
    'records_found': len(records),
    'records':     records[:100],
    'issues':      issues,
    'counts': {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH':     counts.get('HIGH', 0),
        'MEDIUM':   counts.get('MEDIUM', 0),
        'LOW':      counts.get('LOW', 0),
    },
}, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)
print(f"DNS: {len(records)} records, {len(issues)} issues, DNSSEC: {'OK' if dnssec_ok else 'non configuré'}")
PY

RC=$?
if [[ $RC -ne 0 ]]; then error "Module DNS ÉCHOUÉ (Python $RC)"; exit 1; fi
if [[ ! -s "$OUT/summary.json" ]]; then error "dns/summary.json vide"; exit 1; fi
success "Module DNS terminé"
