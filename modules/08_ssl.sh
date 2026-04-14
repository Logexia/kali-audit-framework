#!/bin/bash
#============================================================================
# 08 - SSL/TLS: Protocoles, ciphers, certificats, vulnérabilités
# [NON-REGRESSION] Inchangé depuis v4
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/ssl"
WEB="$OUTPUT_DIR/discovery/web_hosts.txt"

> "$OUT/targets.txt"
[[ -n "${URLS_FILE:-}" && -f "$URLS_FILE" ]] && cat "$URLS_FILE" >> "$OUT/targets.txt"
[[ -s "$WEB" ]] && while IFS= read -r h; do [[ -n "$h" ]] && echo "$h:443" >> "$OUT/targets.txt"; done < "$WEB"
sort -u "$OUT/targets.txt" -o "$OUT/targets.txt"

COUNT=$(wc -l < "$OUT/targets.txt" 2>/dev/null || echo 0)
if [[ "$COUNT" -eq 0 ]]; then
    warning "Aucune cible SSL"; echo '{"targets":0,"issues":[]}' > "$OUT/summary.json"; exit 0
fi
log "$COUNT cibles SSL"

log "SSLScan"; mkdir -p "$OUT/sslscan"
while IFS= read -r target; do [[ -z "$target" ]] && continue
    clean=$(echo "$target" | sed 's|https\?://||; s|/.*||'); safe=$(echo "$clean" | tr ':/' '_')
    sslscan --no-colour "$clean" > "$OUT/sslscan/${safe}.txt" 2>/dev/null || true
done < "$OUT/targets.txt"

TESTSSL=""; for c in testssl testssl.sh /usr/bin/testssl; do command -v "$c" &>/dev/null && TESTSSL="$c" && break; done
if [[ -n "$TESTSSL" ]]; then
    log "testssl.sh"; mkdir -p "$OUT/testssl"
    while IFS= read -r target; do [[ -z "$target" ]] && continue
        clean=$(echo "$target" | sed 's|https\?://||; s|/.*||'); safe=$(echo "$clean" | tr ':/' '_')
        timeout 180 $TESTSSL --quiet --wide --jsonfile "$OUT/testssl/${safe}.json" --csvfile "$OUT/testssl/${safe}.csv" "$clean" > "$OUT/testssl/${safe}.txt" 2>/dev/null || true
    done < "$OUT/targets.txt"
fi

log "Nmap SSL scripts"
awk -F: '{print $1}' "$OUT/targets.txt" | sed 's|https\?://||' | sort -u > "$OUT/ssl_ips.txt"
nmap -p 443,8443,993,995,636,3389 --script "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params" \
    -iL "$OUT/ssl_ips.txt" -oA "$OUT/nmap_ssl" -oX "$OUT/nmap_ssl.xml" 2>/dev/null

python3 << 'SSLPY'
import json, os, re, csv, glob
from collections import Counter
out = os.environ['OUTPUT_DIR'] + '/ssl'
issues = []; targets_detail = {}

for f in glob.glob(f'{out}/sslscan/*.txt'):
    target = os.path.basename(f).replace('.txt','').replace('_',':',1)
    try:
        c = open(f).read()
        info = {'target':target,'protocols':[],'ciphers':[],'cert_cn':'','cert_expiry':'','cert_issuer':'','cert_selfsigned':False}
        for proto, flag in [('SSLv2','CRITICAL'),('SSLv3','CRITICAL'),('TLSv1.0','HIGH'),('TLSv1.1','HIGH'),('TLSv1.2','OK'),('TLSv1.3','OK')]:
            if re.search(rf'{re.escape(proto)}\s+enabled', c):
                info['protocols'].append(proto)
                if flag in ('CRITICAL','HIGH'):
                    issues.append({'target':target,'severity':flag,'issue':f'{proto} activé sur {target}','recommendation':f'Désactiver {proto}'})
        for pat, desc in [(r'NULL','NULL'),(r'EXPORT','EXPORT'),(r'RC4','RC4'),(r'DES-CBC(?!3)','DES')]:
            if re.search(pat, c): issues.append({'target':target,'severity':'HIGH','issue':f'{desc} cipher sur {target}','recommendation':f'Désactiver {desc}'})
        cn_m = re.search(r'Subject:\s*(.+)', c); info['cert_cn'] = cn_m.group(1).strip() if cn_m else ''
        exp_m = re.search(r'Not valid after:\s*(.+)', c); info['cert_expiry'] = exp_m.group(1).strip() if exp_m else ''
        iss_m = re.search(r'Issuer:\s*(.+)', c); info['cert_issuer'] = iss_m.group(1).strip() if iss_m else ''
        if re.search(r'self.signed', c, re.I): info['cert_selfsigned'] = True; issues.append({'target':target,'severity':'MEDIUM','issue':f'Certificat auto-signé sur {target}','recommendation':'Utiliser un certificat CA'})
        if 'expired' in c.lower(): issues.append({'target':target,'severity':'HIGH','issue':f'Certificat expiré sur {target}','recommendation':'Renouveler le certificat'})
        if re.search(r'heartbleed.*vulnerable', c, re.I): issues.append({'target':target,'severity':'CRITICAL','issue':f'Heartbleed sur {target}','recommendation':'Patcher OpenSSL'})
        if 'TLSv1.3' not in c and ('TLSv1.2' in c or 'TLSv1.1' in c): issues.append({'target':target,'severity':'LOW','issue':f'TLS 1.3 absent sur {target}','recommendation':'Activer TLS 1.3'})
        targets_detail[target] = info
    except: pass

seen = set(); unique = []
for i in issues:
    k = f"{i['target']}-{i['issue'][:50]}"
    if k not in seen: seen.add(k); unique.append(i)
issues = unique

counts = Counter(i['severity'] for i in issues)
json.dump({'targets':len(targets_detail),'targets_detail':targets_detail,'issues':issues,'counts':dict(counts)}, open(f'{out}/summary.json','w'), indent=2, ensure_ascii=False)
with open(f'{out}/ssl_results.csv','w',newline='') as f:
    w = csv.writer(f, delimiter=';'); w.writerow(['Cible','Protocoles','Cert CN','Cert Expiry','Auto-signé'])
    for t, info in targets_detail.items(): w.writerow([t,', '.join(info.get('protocols',[])),info.get('cert_cn',''),info.get('cert_expiry',''),'Oui' if info.get('cert_selfsigned') else 'Non'])
print(f"SSL: {len(targets_detail)} cibles, {len(issues)} issues")
SSLPY
