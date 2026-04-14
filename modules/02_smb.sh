#!/bin/bash
#============================================================================
# 02 - SMB: Shares, versions, signing, permissions, vulnérabilités
# [NON-REGRESSION] Inchangé depuis v4
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/smb"
HOSTS="$OUTPUT_DIR/discovery/smb_hosts.txt"

if [[ ! -s "$HOSTS" ]]; then
    warning "Aucun hôte SMB détecté"; echo '{"total":0,"issues":[]}' > "$OUT/summary.json"; exit 0
fi
log "$(wc -l < "$HOSTS") hôtes SMB"

log "Versions SMB et signing"
nmap -p 139,445 --script smb-protocols,smb2-security-mode,smb-security-mode,smb-os-discovery \
    -iL "$HOSTS" -oA "$OUT/versions" -oX "$OUT/versions.xml" 2>/dev/null
success "Versions scannées"

CME=""; command -v nxc &>/dev/null && CME="nxc"; command -v crackmapexec &>/dev/null && CME="${CME:-crackmapexec}"
if [[ -n "$CME" ]]; then
    log "Enum shares ($CME)"
    $CME smb $(cat "$HOSTS" | tr '\n' ' ') --shares -u '' -p '' > "$OUT/shares_null.txt" 2>/dev/null || true
    $CME smb $(cat "$HOSTS" | tr '\n' ' ') --shares -u 'guest' -p '' > "$OUT/shares_guest.txt" 2>/dev/null || true
fi

log "Test accès shares (smbclient)"
> "$OUT/shares_access.txt"
while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    echo "═══ $ip ═══" >> "$OUT/shares_access.txt"
    shares=$(smbclient -L "//$ip" -N 2>/dev/null | grep -i "disk" | awk '{print $1}')
    [[ -z "$shares" ]] && { echo "  (aucun share listé)" >> "$OUT/shares_access.txt"; continue; }
    for s in $shares; do
        r="  \\\\$ip\\$s → "
        if smbclient "//$ip/$s" -N -c "ls" &>/dev/null; then
            r+="LECTURE"; tmp=$(mktemp); echo "x" > "$tmp"
            smbclient "//$ip/$s" -N -c "put $tmp .audit_rw_test; rm .audit_rw_test" &>/dev/null && r+=" + ECRITURE"
            rm -f "$tmp"
        else r+="PAS D'ACCES (anon)"; fi
        echo "$r" >> "$OUT/shares_access.txt"
    done
done < "$HOSTS"

if need enum4linux; then
    log "enum4linux"
    while IFS= read -r ip; do [[ -z "$ip" ]] && continue
        if command -v enum4linux-ng &>/dev/null; then enum4linux-ng -A "$ip" -oJ "$OUT/enum_${ip}" 2>/dev/null || true
        else enum4linux -a "$ip" > "$OUT/enum_${ip}.txt" 2>/dev/null || true; fi
    done < "$HOSTS"
fi

log "Scan vulns SMB (EternalBlue, MS08-067...)"
nmap -p 445 --script "smb-vuln-*" -iL "$HOSTS" -oA "$OUT/vulns" 2>/dev/null

python3 << 'PY'
import xml.etree.ElementTree as ET, json, os
from collections import Counter
out = os.environ['OUTPUT_DIR'] + '/smb'
issues = []
try:
    tree = ET.parse(f'{out}/versions.xml')
    for hel in tree.getroot().findall('host'):
        ip = next((a.get('addr') for a in hel.findall('address') if a.get('addrtype')=='ipv4'), '')
        for sc in hel.findall('.//script'):
            o = sc.get('output',''); sid = sc.get('id','')
            if 'smb-protocols' in sid and 'SMBv1' in o:
                issues.append({'target':ip,'severity':'CRITICAL','issue':f'SMBv1 activé sur {ip}','recommendation':'Désactiver SMBv1'})
            if 'security-mode' in sid and ('not required' in o.lower() or 'disabled' in o.lower()):
                issues.append({'target':ip,'severity':'HIGH','issue':f'SMB signing non requis sur {ip}','recommendation':'Activer SMB signing (GPO)'})
except: pass
try:
    c = open(f'{out}/vulns.nmap').read(); host=''
    for l in c.split('\n'):
        if 'Nmap scan report' in l: host = l.split()[-1].strip('()')
        if 'VULNERABLE' in l: issues.append({'target':host,'severity':'CRITICAL','issue':l.strip(),'recommendation':'Appliquer patchs Microsoft'})
except: pass
try:
    for l in open(f'{out}/shares_access.txt'):
        l = l.strip()
        if 'ECRITURE' in l: issues.append({'target':l.split('→')[0].strip(),'severity':'HIGH','issue':f'Share écriture anonyme: {l.split("→")[0].strip()}','recommendation':'Supprimer accès anonymous write'})
        elif 'LECTURE' in l and 'PAS D' not in l: issues.append({'target':l.split('→')[0].strip(),'severity':'MEDIUM','issue':f'Share lecture anonyme: {l.split("→")[0].strip()}','recommendation':'Restreindre accès anonyme'})
except: pass
counts = Counter(i['severity'] for i in issues)
json.dump({'total': int(os.popen(f"wc -l < {os.environ['OUTPUT_DIR']}/discovery/smb_hosts.txt").read().strip() or 0),
           'issues': issues, 'counts': dict(counts)}, open(f'{out}/summary.json','w'), indent=2, ensure_ascii=False)
print(f"SMB: {len(issues)} issues (C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)})")
PY
