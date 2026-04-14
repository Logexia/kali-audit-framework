#!/bin/bash
#============================================================================
# 07 - CVE BASELINE: Nmap vulners, whatweb, nikto
#
# Ce module produit la détection CVE de base via Nmap vulners.
# OpenVAS est géré par le sous-module 07b_openvas.sh (indépendant).
# L'exploitabilité est gérée par 07c_exploitability.sh (indicatif).
#
# Artefacts produits:
#   cve/vulners.xml          Nmap vulners brut
#   cve/vuln_scripts.nmap    Nmap vuln scripts
#   cve/whatweb/*.json       Technologies web
#   cve/nikto/*.json         Résultats Nikto
#   cve/cve_list.csv         CVE consolidées
#   cve/web_technologies.csv Technologies détectées
#   cve/summary.json         Résumé structuré
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/cve"
LIVE="$OUTPUT_DIR/discovery/live_hosts.txt"
WEB="$OUTPUT_DIR/discovery/web_hosts.txt"

if [[ ! -s "$LIVE" ]]; then
    warning "Pas de live_hosts.txt"; echo '{"total_cves":0,"issues":[],"mode":"no_hosts"}' > "$OUT/summary.json"; exit 0
fi

log "Nmap vulners (CVE par version de service)"
nmap -sV --script vulners --script-args mincvss=4.0 \
    -iL "$LIVE" -oA "$OUT/vulners" -oX "$OUT/vulners.xml" 2>/dev/null
success "Nmap vulners terminé"

log "Nmap vuln scripts (safe)"
nmap -sV --script "vuln and safe" -iL "$LIVE" -oA "$OUT/vuln_scripts" 2>/dev/null

if command -v whatweb &>/dev/null && [[ -s "$WEB" ]]; then
    log "WhatWeb (technologies)"; mkdir -p "$OUT/whatweb"
    while IFS= read -r host; do [[ -z "$host" ]] && continue
        for s in http https; do
            whatweb -a 3 --log-json "$OUT/whatweb/${host}_${s}.json" "$s://$host" > /dev/null 2>&1 || true
        done
    done < "$WEB"
fi

if command -v nikto &>/dev/null && [[ -s "$WEB" ]]; then
    log "Nikto (vulns web)"; mkdir -p "$OUT/nikto"
    while IFS= read -r host; do [[ -z "$host" ]] && continue
        timeout 120 nikto -h "$host" -o "$OUT/nikto/${host}.json" -Format json \
            -Tuning 12346789ab -maxtime 120s 2>/dev/null || true
    done < "$WEB"
fi

python3 << 'CVESUM'
import xml.etree.ElementTree as ET
import json, os, re, csv, glob
from collections import Counter

out = os.environ['OUTPUT_DIR'] + '/cve'
issues = []; cve_list = []; web_tech = {}

# Parse Nmap vulners XML
try:
    tree = ET.parse(f'{out}/vulners.xml')
    for hel in tree.getroot().findall('host'):
        ip = next((a.get('addr') for a in hel.findall('address') if a.get('addrtype')=='ipv4'), '')
        for port_el in hel.findall('.//port'):
            pid = port_el.get('portid','')
            svc = port_el.find('service')
            svc_name = f"{svc.get('product','')} {svc.get('version','')}".strip() if svc is not None else ''
            for sc in port_el.findall('.//script'):
                if sc.get('id') != 'vulners': continue
                for line in sc.get('output','').split('\n'):
                    m = re.search(r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)', line)
                    if m:
                        score = float(m.group(2))
                        sev = 'CRITICAL' if score>=9 else 'HIGH' if score>=7 else 'MEDIUM' if score>=4 else 'LOW'
                        cve_list.append({
                            'cve': m.group(1), 'cvss': score, 'host': ip,
                            'port': pid, 'service': svc_name, 'severity': sev,
                            'source': 'nmap-vulners'
                        })
                        issues.append({
                            'target': f'{ip}:{pid}', 'severity': sev,
                            'issue': f'{m.group(1)} (CVSS {score}) - {svc_name}',
                            'recommendation': f'Mettre à jour {svc_name}'
                        })
except Exception as e:
    print(f"Parse vulners.xml: {e}")

# Parse vuln scripts
try:
    c = open(f'{out}/vuln_scripts.nmap').read(); host = ''
    for l in c.split('\n'):
        if 'Nmap scan report' in l: host = l.split()[-1].strip('()')
        if 'VULNERABLE' in l:
            issues.append({'target': host, 'severity': 'HIGH', 'issue': l.strip(), 'recommendation': 'Voir détails nmap'})
except: pass

# Parse WhatWeb
for f in glob.glob(f'{out}/whatweb/*.json'):
    try:
        data = json.load(open(f))
        if not isinstance(data, list): continue
        for entry in data:
            target = entry.get('target','')
            plugins = entry.get('plugins',{})
            tech = {}
            skip = {'IP','Country','UncommonHeaders','HTML5','Script','Meta-Refresh-Redirect',
                    'Strict-Transport-Security','X-Frame-Options','X-XSS-Protection',
                    'X-Content-Type-Options','HttpOnly'}
            for name, info in plugins.items():
                if name in skip: continue
                versions = info.get('version', [])
                tech[name] = versions[0] if len(versions)==1 else (versions if versions else True)
            if tech:
                bn = os.path.basename(f).replace('.json','')
                ip = bn.rsplit('_',1)[0]
                scheme = bn.rsplit('_',1)[1] if '_' in bn else 'http'
                web_tech[f'{scheme}://{ip}'] = tech
    except: pass

# Parse Nikto
for f in glob.glob(f'{out}/nikto/*.json'):
    try:
        data = json.load(open(f))
        if not isinstance(data, list): continue
        for entry in data:
            for v in entry.get('vulnerabilities', []):
                issues.append({
                    'target': entry.get('host',''), 'severity': 'MEDIUM',
                    'issue': f"Nikto: {v.get('msg','')}",
                    'recommendation': 'Corriger config serveur web'
                })
    except: pass

# Dedup CVE
seen = set(); unique_cve = []
for c in cve_list:
    k = f"{c['host']}:{c['cve']}"
    if k not in seen: seen.add(k); unique_cve.append(c)
cve_list = unique_cve

counts = Counter(i['severity'] for i in issues)
summary = {
    'mode': 'nmap-vulners',
    'total_cves': len(cve_list),
    'total_issues': len(issues),
    'counts': dict(counts),
    'web_technologies': web_tech,
    'cve_list': cve_list,
    'issues': issues
}
json.dump(summary, open(f'{out}/summary.json','w'), indent=2, ensure_ascii=False)

with open(f'{out}/cve_list.csv','w', newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['Host','Port','Service','CVE','CVSS','Sévérité','Source'])
    for c in sorted(cve_list, key=lambda x: -x['cvss']):
        w.writerow([c['host'], c['port'], c['service'], c['cve'], c['cvss'], c['severity'], c['source']])

with open(f'{out}/web_technologies.csv','w', newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['URL','Technologie','Version'])
    for url, techs in web_tech.items():
        for name, ver in techs.items():
            w.writerow([url, name, ver if isinstance(ver, str) else ''])

print(f"CVE baseline: {len(cve_list)} CVE uniques | C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)}")
CVESUM
