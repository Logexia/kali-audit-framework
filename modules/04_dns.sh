#!/bin/bash
#============================================================================
# 04 - DNS: Zone transfer, enum sous-domaines, misconfig
# [NON-REGRESSION] Inchangé depuis v4
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/dns"
DNS_HOSTS="$OUTPUT_DIR/discovery/dns_hosts.txt"

if [[ ! -s "$DNS_HOSTS" ]]; then
    nmap -p 53 --open "$NETWORK" -oG - 2>/dev/null | grep "53/open" | awk '{print $2}' > "$DNS_HOSTS"
fi
DOMAIN=""
if [[ -n "${DOMAIN_CONTROLLER:-}" ]]; then
    DOMAIN=$(nmap -sC -p 389 "$DOMAIN_CONTROLLER" 2>/dev/null | grep -oP '(?<=Domain: )\S+' | head -1)
fi
if [[ -z "$DOMAIN" && -s "$DNS_HOSTS" ]]; then
    DOMAIN=$(nmap -sC -p 53 -iL "$DNS_HOSTS" 2>/dev/null | grep -oP '(?<=Domain: )\S+' | head -1)
fi
if [[ ! -s "$DNS_HOSTS" && -z "$DOMAIN" ]]; then
    warning "Aucun serveur DNS"; echo '{"issues":[]}' > "$OUT/summary.json"; exit 0
fi
log "DNS: $(wc -l < "$DNS_HOSTS" 2>/dev/null || echo 0) serveurs | Domaine: ${DOMAIN:-inconnu}"

log "Test transferts de zone"
> "$OUT/zone_transfers.txt"
while IFS= read -r dns_ip; do
    [[ -z "$dns_ip" ]] && continue
    [[ -n "$DOMAIN" ]] && { echo "=== AXFR $DOMAIN @$dns_ip ===" >> "$OUT/zone_transfers.txt"; dig axfr "$DOMAIN" @"$dns_ip" >> "$OUT/zone_transfers.txt" 2>/dev/null; echo "" >> "$OUT/zone_transfers.txt"; }
    NET_PREFIX=$(echo "$NETWORK" | cut -d. -f1-3); REV_ZONE=$(echo "$NET_PREFIX" | awk -F. '{print $3"."$2"."$1}').in-addr.arpa
    result_rev=$(dig axfr "$REV_ZONE" @"$dns_ip" 2>/dev/null)
    echo "$result_rev" | grep -q "XFR size" && { echo "=== AXFR reverse $REV_ZONE @$dns_ip ===" >> "$OUT/zone_transfers.txt"; echo "$result_rev" >> "$OUT/zone_transfers.txt"; }
done < "$DNS_HOSTS"

if [[ -n "$DOMAIN" ]]; then
    command -v dnsrecon &>/dev/null && { log "dnsrecon"; dnsrecon -d "$DOMAIN" -n "$(head -1 "$DNS_HOSTS")" -t std,brt,axfr -j "$OUT/dnsrecon.json" > "$OUT/dnsrecon.txt" 2>/dev/null || true; }
    command -v dnsenum &>/dev/null && { log "dnsenum"; dnsenum --dnsserver "$(head -1 "$DNS_HOSTS")" --noreverse "$DOMAIN" -o "$OUT/dnsenum.xml" > "$OUT/dnsenum.txt" 2>/dev/null || true; }
fi
nmap -p 53 --script "dns-nsid,dns-recursion,dns-service-discovery,dns-cache-snoop" -iL "$DNS_HOSTS" -oA "$OUT/nmap_dns" 2>/dev/null || true

python3 << 'PY'
import json, os, re
from collections import Counter
out = os.environ['OUTPUT_DIR'] + '/dns'
issues = []; records = []
try:
    c = open(f'{out}/zone_transfers.txt').read()
    for block in c.split('=== AXFR'):
        if not block.strip(): continue
        header = block.split('\n')[0].strip()
        if 'XFR size' in block or '\tIN\t' in block:
            m = re.search(r'@(\S+)', header); dns_ip = m.group(1) if m else 'unknown'
            issues.append({'target':dns_ip,'severity':'HIGH','issue':f'Transfert de zone DNS autorisé ({header.split("===")[0].strip()})','recommendation':'Restreindre AXFR'})
            for line in block.split('\n'):
                if '\tIN\t' in line: records.append(line.strip())
except: pass
try:
    c = open(f'{out}/nmap_dns.nmap').read(); host = ''
    for l in c.split('\n'):
        if 'Nmap scan report' in l: host = l.split()[-1].strip('()')
        if 'Recursion: Enabled' in l:
            issues.append({'target':host,'severity':'MEDIUM','issue':f'Récursion DNS activée sur {host}','recommendation':'Désactiver récursion ou restreindre'})
except: pass
try:
    data = json.load(open(f'{out}/dnsrecon.json'))
    for e in data:
        if e.get('type') in ('A','AAAA','CNAME','MX','NS','TXT','SRV'):
            records.append(f"{e.get('name','')} {e.get('type','')} {e.get('address', e.get('target',''))}")
except: pass
counts = Counter(i['severity'] for i in issues)
json.dump({
    'domain': os.environ.get('DOMAIN',''),
    'dns_servers': open(f'{os.environ["OUTPUT_DIR"]}/discovery/dns_hosts.txt').read().strip().split('\n') if os.path.exists(f'{os.environ["OUTPUT_DIR"]}/discovery/dns_hosts.txt') else [],
    'records_found':len(records),'records':records[:100],'issues':issues,'counts':dict(counts)
}, open(f'{out}/summary.json','w'), indent=2, ensure_ascii=False)
print(f"DNS: {len(records)} records, {len(issues)} issues")
PY
