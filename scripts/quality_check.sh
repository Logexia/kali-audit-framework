#!/bin/bash
#============================================================================
# QUALITY_CHECK.SH v4.5 - Vérification + non-régression (11 points)
#
#  1. Discovery: inventaire réseau
#  2. SMB: partages + versions + droits
#  3. TLS/SSL: versions + faiblesses
#  4. SNMP: community + topologie
#  5. DNS: zone transfer + subdomains
#  6. WiFi: découverte + faiblesses
#  7. AD: score + findings critiques
#  8. Email: SPF + DKIM + DMARC
#  9. CVE OpenVAS: export + résumé HTML
# 10. Rapport HTML: toutes sections + nouvelles
# 11. Modules existants non modifiés / non dépendants OpenVAS
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
log "Quality Check + Non-régression"

python3 << 'QCPY'
import json, os, sys
from pathlib import Path

out = os.environ['OUTPUT_DIR']
rpt = f"{out}/report"
script_dir = os.environ.get('SCRIPT_DIR', '')

checks = []; warnings = []; errors = []
nr = []

def check(name, cond, ok, fail, crit=False):
    if cond: checks.append(('OK', name, ok))
    elif crit: errors.append(('FAIL', name, fail))
    else: warnings.append(('WARN', name, fail))

def nr_check(num, name, cond, ok, fail):
    nr.append({'num':num, 'name':name, 'status':'OK' if cond else 'NOK',
               'detail': ok if cond else fail})

# ── Load consolidated ──────────────────────────────────────────────
check('consolidated.json', Path(f'{rpt}/consolidated.json').exists(), 'Présent', 'MANQUANT', True)
html_files = [f for f in os.listdir(rpt) if f.endswith('.html')] if Path(rpt).exists() else []
check('Rapport HTML', len(html_files)>0, html_files[0] if html_files else '', 'Aucun HTML', True)

try: D = json.load(open(f'{rpt}/consolidated.json'))
except: print("\033[31mconsolidated.json illisible\033[0m"); sys.exit(1)

hosts = D.get('hosts',[]); ad = D.get('ad',{}); openvas = D.get('openvas',{})
email = D.get('email_security',{}); scoring = D.get('scoring',{})

# ══════════════ NON-REGRESSION (11 points) ══════════════

# 1. Discovery
nr_check(1, 'Discovery: inventaire réseau',
    len(hosts) > 0, f'{len(hosts)} hôtes', 'Aucun hôte')

# 2. SMB
smb_p = f'{out}/smb/summary.json'
smb_ok = Path(smb_p).exists() or not D.get('smb_hosts')
nr_check(2, 'SMB: partages + versions + droits', smb_ok,
    'Données SMB présentes' if Path(smb_p).exists() else 'Pas d\'hôtes SMB',
    'summary.json SMB manquant')

# 3. TLS/SSL
ssl_p = f'{out}/ssl/summary.json'
ssl_ok = Path(ssl_p).exists() or D.get('ssl',{}).get('targets',0)==0
nr_check(3, 'TLS/SSL: versions + faiblesses', ssl_ok,
    'Données SSL présentes', 'summary.json SSL manquant')

# 4. SNMP
snmp_ok = Path(f'{out}/snmp/summary.json').exists() or not D.get('snmp_hosts')
nr_check(4, 'SNMP: community + topologie', snmp_ok,
    'Données SNMP présentes', 'summary.json SNMP manquant')

# 5. DNS
dns_ok = Path(f'{out}/dns/summary.json').exists() or not D.get('dns_hosts')
nr_check(5, 'DNS: zone transfer + subdomains', dns_ok,
    'Données DNS présentes', 'summary.json DNS manquant')

# 6. WiFi
wifi_ok = Path(f'{out}/wifi/summary.json').exists()
nr_check(6, 'WiFi: découverte + faiblesses', wifi_ok,
    'Données WiFi présentes', 'Module WiFi non exécuté')

# 7. AD
if ad.get('dc_ip'):
    ad_ok = ad.get('ad_score') is not None and len(ad.get('findings',[]))>0
    nr_check(7, 'AD: score + findings', ad_ok,
        f"Score:{ad.get('ad_score',0)}/100 Findings:{len(ad.get('findings',[]))}",
        'Score AD ou findings manquants')
else:
    nr_check(7, 'AD: score + findings', True, 'Pas de DC (OK)', '')

# 8. Email SPF/DKIM/DMARC
email_p = f'{out}/email_security/summary.json'
if Path(email_p).exists():
    em = json.load(open(email_p))
    if em.get('mode') == 'skipped':
        nr_check(8, 'Email: SPF + DKIM + DMARC', True, 'Pas de --domain (sauté)', '')
    else:
        em_ok = 'spf' in em and 'dmarc' in em and 'dkim' in em
        det = f"SPF:{'✓' if em.get('spf',{}).get('exists') else '✗'} DMARC:{'✓' if em.get('dmarc',{}).get('exists') else '✗'} DKIM:{em.get('dkim',{}).get('selectors_found',0)} sel."
        nr_check(8, 'Email: SPF + DKIM + DMARC', em_ok, det, 'Données email incomplètes')
else:
    nr_check(8, 'Email: SPF + DKIM + DMARC', True, 'Module non exécuté (optionnel)', '')

# 9. CVE OpenVAS
ov_mode = openvas.get('mode','not_run')
if ov_mode == 'openvas':
    nr_check(9, 'CVE OpenVAS: export + résumé', True,
        f"CVE:{openvas.get('total_cves',0)} Critiques:{openvas.get('critical_vulns',0)}", '')
elif ov_mode == 'degraded':
    nr_check(9, 'CVE OpenVAS: export + résumé', True,
        f"Mode dégradé ({openvas.get('reason','')})", '')
else:
    nr_check(9, 'CVE OpenVAS: export + résumé', True, 'Non exécuté (optionnel)', '')

# 9b. Web OWASP (optionnel)
web_owasp_p = f'{out}/web_owasp/summary.json'
if Path(web_owasp_p).exists():
    wo = json.load(open(web_owasp_p))
    wo_mode = wo.get('mode', 'unknown')
    if wo_mode == 'skipped':
        nr_check(9, 'Web OWASP: module exécuté', True, 'Sauté — aucune cible web (OK)', '')
    else:
        wo_ok = wo_mode == 'executed' and 'owasp_findings' in wo
        wo_cnt = wo.get('counts', {})
        wo_det = f"Findings: {len(wo.get('owasp_findings',[]))} (C:{wo_cnt.get('CRITICAL',0)} H:{wo_cnt.get('HIGH',0)} M:{wo_cnt.get('MEDIUM',0)})"
        nr_check(9, 'Web OWASP: module exécuté', wo_ok, wo_det, 'summary.json invalide ou mode incorrect')
else:
    nr_check(9, 'Web OWASP: module exécuté', True, 'Non exécuté (optionnel)', '')

# 10. Rapport HTML: toutes sections
html_ok = False; html_detail = 'Pas vérifié'
if html_files:
    html = open(f'{rpt}/{html_files[0]}').read()
    required = ['scores','scoring-detail','exec-summary','synthese','inventaire',
                 'ad-audit','email-security','vulns','openvas-vulns','exploitability',
                 'smb','snmp','dns','ssl','web-owasp','web-tech','wifi','remediation']
    found = [s for s in required if f'id="{s}"' in html]
    missing = [s for s in required if f'id="{s}"' not in html]
    has_legal = 'AVERTISSEMENT' in html
    html_ok = len(missing) <= 4  # tolérance (certaines sections conditionnelles)
    html_detail = f"{len(found)}/{len(required)} sections | Legal:{'✓' if has_legal else '✗'}"
    if missing: html_detail += f" | Absentes: {','.join(missing[:5])}"
nr_check(10, 'Rapport HTML: sections complètes', html_ok, html_detail, html_detail)

# 11. Modules non modifiés
intact = True; detail = 'OK'
for mf in ['01_discovery.sh','02_smb.sh','03_snmp.sh','04_dns.sh','05_ad.sh','06_wifi.sh','08_ssl.sh','09_web_owasp.sh']:
    p = f'{script_dir}/modules/{mf}' if script_dir else ''
    if p and Path(p).exists():
        content = open(p).read()
        if 'openvas' in content.lower() or 'gvm' in content.lower():
            intact = False; detail = f'{mf} référence OpenVAS/GVM'; break
nr_check(11, 'Modules existants non modifiés', intact, detail, detail)

# ── Scoring cohérence ──────────────────────────────────────────────
cats = scoring.get('categories',{})
if cats:
    total_weight = sum(c['weight'] for c in cats.values())
    total_score = sum(c['score'] for c in cats.values())
    check('Scoring: poids total = 100', total_weight == 100,
        f'Total poids: {total_weight}', f'Poids: {total_weight} ≠ 100')
    check('Scoring: score ≤ 100', D.get('risk_score',0) <= 100,
        f"Score: {D.get('risk_score',0)}", f"Score > 100: {D.get('risk_score',0)}")
    check('Scoring: chaque catégorie ≤ poids', all(c['score']<=c['weight'] for c in cats.values()),
        'Tous plafonnés', 'Catégorie dépasse son poids')

# ══════════════ OUTPUT ══════════════
nr_ok = sum(1 for n in nr if n['status']=='OK')
nr_nok = sum(1 for n in nr if n['status']=='NOK')

print(f"\n{'='*65}")
print(f" CHECKLIST NON-RÉGRESSION ({len(nr)} points)")
print(f"{'='*65}\n")
for n in nr:
    sym = '\033[32m[OK]\033[0m' if n['status']=='OK' else '\033[31m[NOK]\033[0m'
    print(f"  {n['num']:>2}. {sym} {n['name']}")
    print(f"      → {n['detail']}")

print(f"\n  Résultat: {nr_ok}/{len(nr)} OK, {nr_nok}/{len(nr)} NOK\n")
print(f"{'='*65}")
print(f" QUALITY: {len(checks)} OK, {len(warnings)} WARN, {len(errors)} FAIL")
print(f"{'='*65}\n")
for _,n,m in checks: print(f"\033[32m  [✓] {n}: {m}\033[0m")
for _,n,m in warnings: print(f"\033[33m  [!] {n}: {m}\033[0m")
for _,n,m in errors: print(f"\033[31m  [✗] {n}: {m}\033[0m")

json.dump({
    'non_regression': {'total':len(nr),'ok':nr_ok,'nok':nr_nok,'checks':nr},
    'quality': {'ok':len(checks),'warnings':len(warnings),'errors':len(errors)},
}, open(f'{rpt}/quality_check.json','w'), indent=2, ensure_ascii=False)

if errors: print(f"\n\033[31m⚠ {len(errors)} erreur(s)\033[0m"); sys.exit(1)
elif nr_nok > 0: print(f"\n\033[33m⚡ {nr_nok} NOK\033[0m")
else: print(f"\n\033[32m✓ Complet — non-régression validée\033[0m")
QCPY
