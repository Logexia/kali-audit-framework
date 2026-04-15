#!/bin/bash
#============================================================================
# 08 - SSL/TLS: Protocoles, ciphers, certificats, vulnérabilités
# v4.5.1 — Ajouts: testssl.sh JSON complet, expiration <30/<90j,
#           Heartbleed/POODLE/ROBOT/BEAST/CRIME/BREACH depuis testssl,
#           certificats auto-signés + chaîne, HSTS preload check
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/ssl"
WEB="$OUTPUT_DIR/discovery/web_hosts.txt"

> "$OUT/targets.txt"
[[ -n "${URLS_FILE:-}" && -f "$URLS_FILE" ]] && cat "$URLS_FILE" >> "$OUT/targets.txt"
[[ -s "$WEB" ]] && while IFS= read -r h; do
    [[ -n "$h" ]] && echo "$h:443" >> "$OUT/targets.txt"
done < "$WEB"
sort -u "$OUT/targets.txt" -o "$OUT/targets.txt"

COUNT=$(wc -l < "$OUT/targets.txt" 2>/dev/null || echo 0)
if [[ "$COUNT" -eq 0 ]]; then
    warning "Aucune cible SSL"
    echo '{"targets":0,"issues":[],"counts":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}}' > "$OUT/summary.json"
    exit 0
fi
log "$COUNT cibles SSL/TLS"

# ══════════════════════════════════════════════════════════════════════════
# SSLSCAN
# ══════════════════════════════════════════════════════════════════════════
log "SSLScan"
mkdir -p "$OUT/sslscan"
while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    clean=$(echo "$target" | sed 's|https\?://||; s|/.*||')
    safe=$(echo "$clean"  | tr ':/' '_')
    timeout 60 sslscan --no-colour "$clean" > "$OUT/sslscan/${safe}.txt" 2>/dev/null || true
done < "$OUT/targets.txt"

# ══════════════════════════════════════════════════════════════════════════
# TESTSSL.SH (quand disponible — beaucoup plus complet)
# ══════════════════════════════════════════════════════════════════════════
TESTSSL=""
for c in testssl testssl.sh /usr/bin/testssl /usr/local/bin/testssl.sh; do
    command -v "$c" &>/dev/null && TESTSSL="$c" && break
done
if [[ -n "$TESTSSL" ]]; then
    log "testssl.sh (JSON + CSV + vulnérabilités)"
    mkdir -p "$OUT/testssl"
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        clean=$(echo "$target" | sed 's|https\?://||; s|/.*||')
        safe=$(echo "$clean" | tr ':/' '_')
        timeout 300 "$TESTSSL" \
            --quiet --wide \
            --jsonfile "$OUT/testssl/${safe}.json" \
            --csvfile  "$OUT/testssl/${safe}.csv" \
            "$clean" > "$OUT/testssl/${safe}.txt" 2>/dev/null || true
    done < "$OUT/targets.txt"
    success "testssl.sh terminé"
else
    warning "testssl.sh absent — analyse réduite (apt install testssl.sh)"
fi

# ══════════════════════════════════════════════════════════════════════════
# NMAP SSL SCRIPTS
# ══════════════════════════════════════════════════════════════════════════
log "Nmap SSL scripts (heartbleed, poodle, certs, ciphers)"
awk -F: '{print $1}' "$OUT/targets.txt" | sed 's|https\?://||' | sort -u > "$OUT/ssl_ips.txt"
nmap -p 443,8443,993,995,636,3389 \
    --script "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-known-key" \
    -iL "$OUT/ssl_ips.txt" -oA "$OUT/nmap_ssl" -oX "$OUT/nmap_ssl.xml" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════
# ANALYSE PYTHON
# ══════════════════════════════════════════════════════════════════════════
python3 << 'SSLPY'
import json, os, re, csv, glob
from datetime import datetime, timezone
from collections import Counter
from pathlib import Path

out = os.environ['OUTPUT_DIR'] + '/ssl'
issues = []
targets_detail = {}
seen = set()

def add_issue(target, severity, issue, recommendation):
    k = f"{target}|{issue[:80]}"
    if k not in seen:
        seen.add(k)
        issues.append({'target': target, 'severity': severity,
                       'issue': issue, 'recommendation': recommendation,
                       'module': 'ssl'})

# ══════════════════════════════════════════════════════════════════════════
# 1. PARSE SSLSCAN (baseline — toujours présent)
# ══════════════════════════════════════════════════════════════════════════
for f in glob.glob(f'{out}/sslscan/*.txt'):
    target = os.path.basename(f).replace('.txt', '').replace('_', ':', 1)
    try:
        c = open(f).read()
        info = {
            'target': target, 'protocols': [], 'ciphers': [],
            'cert_cn': '', 'cert_expiry': '', 'cert_issuer': '',
            'cert_selfsigned': False, 'cert_days_remaining': None,
        }
        # Protocoles
        for proto, sev in [('SSLv2','CRITICAL'),('SSLv3','CRITICAL'),
                           ('TLSv1.0','HIGH'),('TLSv1.1','HIGH')]:
            if re.search(rf'{re.escape(proto)}\s+enabled', c):
                info['protocols'].append(proto)
                add_issue(target, sev, f'{proto} activé sur {target}',
                          f'Désactiver {proto} — utiliser TLS 1.2/1.3 uniquement')
        for proto in ('TLSv1.2', 'TLSv1.3'):
            if re.search(rf'{re.escape(proto)}\s+enabled', c):
                info['protocols'].append(proto)

        # Ciphers faibles
        for pat, desc in [(r'\bNULL\b','NULL cipher'), (r'\bEXPORT\b','EXPORT cipher'),
                          (r'\bRC4\b','RC4'), (r'\bDES-CBC\b(?!3)','DES'),
                          (r'\bANON\b','ANON cipher')]:
            if re.search(pat, c):
                info['ciphers'].append(desc)
                add_issue(target, 'HIGH', f'{desc} sur {target}',
                          f'Désactiver {desc} — utiliser AES-GCM, ChaCha20 uniquement')

        # Certificat
        cn_m   = re.search(r'(?:Subject|Common Name):\s*(.+)', c)
        exp_m  = re.search(r'Not valid after:\s*(.+)', c)
        iss_m  = re.search(r'Issuer:\s*(.+)', c)
        info['cert_cn']      = cn_m.group(1).strip() if cn_m else ''
        info['cert_expiry']  = exp_m.group(1).strip() if exp_m else ''
        info['cert_issuer']  = iss_m.group(1).strip() if iss_m else ''

        # Auto-signé
        if re.search(r'self.sign', c, re.I):
            info['cert_selfsigned'] = True
            add_issue(target, 'MEDIUM', f'Certificat auto-signé sur {target}',
                      'Remplacer par un certificat émis par une CA de confiance (Let\'s Encrypt, etc.)')

        # Expiration
        if exp_m:
            try:
                exp_str = exp_m.group(1).strip()
                # Formats: "Apr 15 00:00:00 2025 GMT" ou "2025-04-15"
                for fmt in ('%b %d %H:%M:%S %Y %Z', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
                    try:
                        exp_dt = datetime.strptime(exp_str.replace('GMT','').strip(), fmt)
                        break
                    except ValueError:
                        exp_dt = None
                if exp_dt:
                    days_rem = (exp_dt - datetime.now()).days
                    info['cert_days_remaining'] = days_rem
                    if days_rem < 0:
                        add_issue(target, 'CRITICAL', f'Certificat EXPIRÉ depuis {-days_rem} jours sur {target}',
                                  'Renouveler immédiatement le certificat SSL/TLS')
                    elif days_rem < 30:
                        add_issue(target, 'HIGH', f'Certificat expire dans {days_rem} jours sur {target}',
                                  f'Renouveler le certificat SSL/TLS (expiration: {exp_str})')
                    elif days_rem < 90:
                        add_issue(target, 'MEDIUM', f'Certificat expire dans {days_rem} jours sur {target}',
                                  'Planifier le renouvellement du certificat')
            except Exception:
                pass

        # Heartbleed (sslscan)
        if re.search(r'heartbleed.*vulnerable', c, re.I):
            add_issue(target, 'CRITICAL', f'Heartbleed (CVE-2014-0160) sur {target}',
                      'Patcher OpenSSL vers 1.0.1g+ et révoquer/regénérer les certificats')

        # TLS 1.3 absent
        if 'TLSv1.3' not in info['protocols'] and any(p in info['protocols'] for p in ('TLSv1.2', 'TLSv1.1', 'TLSv1.0')):
            add_issue(target, 'LOW', f'TLS 1.3 non activé sur {target}',
                      'Activer TLS 1.3 pour les performances et la sécurité maximales')

        targets_detail[target] = info
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════
# 2. PARSE TESTSSL.SH JSON (analyse approfondie si disponible)
# ══════════════════════════════════════════════════════════════════════════
VULN_IDS = {
    # id_testssl: (display_name, cve, severity_if_vuln, recommendation)
    'heartbleed':    ('Heartbleed',         'CVE-2014-0160', 'CRITICAL', 'Patcher OpenSSL immédiatement'),
    'CCS':           ('OpenSSL CCS',        'CVE-2014-0224', 'CRITICAL', 'Patcher OpenSSL >= 1.0.1h'),
    'ticketbleed':   ('Ticketbleed',        'CVE-2016-9244', 'HIGH',     'Mettre à jour F5 BIG-IP'),
    'ROBOT':         ('ROBOT',              'CVE-2017-13099','HIGH',     'Désactiver RSA key exchange'),
    'crime_tls':     ('CRIME (TLS)',        'CVE-2012-4929', 'MEDIUM',   'Désactiver TLS compression'),
    'breach':        ('BREACH',             'CVE-2013-3587', 'MEDIUM',   'Désactiver HTTP compression ou utiliser CSRF tokens'),
    'poodle_ssl':    ('POODLE (SSLv3)',     'CVE-2014-3566', 'HIGH',     'Désactiver SSLv3'),
    'BEAST':         ('BEAST (TLS 1.0)',    'CVE-2011-3389', 'MEDIUM',   'Désactiver TLS 1.0 / RC4'),
    'lucky13':       ('Lucky 13',          'CVE-2013-0169', 'MEDIUM',   'Patcher OpenSSL/GnuTLS'),
    'RC4':           ('RC4 cipher',         '',              'HIGH',     'Désactiver RC4 sur le serveur'),
    'LOGJAM-common': ('LOGJAM (DH 1024)',  'CVE-2015-4000', 'HIGH',     'Utiliser DH >= 2048 bits'),
    'DROWN':         ('DROWN (SSLv2)',      'CVE-2016-0800', 'CRITICAL', 'Désactiver SSLv2 et les clés partagées'),
    'FREAK':         ('FREAK',             'CVE-2015-0204', 'HIGH',     'Désactiver EXPORT cipher suites'),
    'SWEET32':       ('SWEET32 (3DES)',    'CVE-2016-2183', 'MEDIUM',   'Désactiver 3DES cipher suites'),
}

for jfile in glob.glob(f'{out}/testssl/*.json'):
    # Déduire la cible depuis le nom de fichier
    safe_name = os.path.basename(jfile).replace('.json', '')
    # Reconvertir : premier _ → : (pour host:port)
    target_ts = safe_name.replace('_', ':', 1)

    try:
        raw = open(jfile).read().strip()
        if not raw:
            continue
        ts_data = json.loads(raw)
        # testssl JSON peut être un dict avec 'scanResult' ou une liste directe
        if isinstance(ts_data, dict):
            entries = ts_data.get('scanResult', [])
            if isinstance(entries, list) and entries:
                entries = entries[0].get('serverDefaults', []) + \
                          entries[0].get('protocols', []) + \
                          entries[0].get('ciphers', []) + \
                          entries[0].get('vulnerabilities', []) + \
                          entries[0].get('serverPreferences', [])
        elif isinstance(ts_data, list):
            entries = ts_data
        else:
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            eid    = entry.get('id', '')
            sev    = entry.get('severity', '').upper()
            finding = entry.get('finding', '')

            # Vulnérabilités connues
            for vuln_id, (name, cve, issue_sev, rec) in VULN_IDS.items():
                if vuln_id.lower() in eid.lower():
                    vuln_text = finding.lower()
                    # Pas vulnérable → skip
                    if any(x in vuln_text for x in ('not vulnerable', 'not affected', 'mitigated')):
                        continue
                    if sev in ('WARN', 'MEDIUM', 'HIGH', 'CRITICAL') or \
                       any(x in vuln_text for x in ('vulnerable', 'potentially', 'exploitable')):
                        cve_str = f' ({cve})' if cve else ''
                        add_issue(target_ts, issue_sev,
                                  f'{name}{cve_str} sur {target_ts}: {finding[:80]}',
                                  rec)

            # Certificat expiré / expiration bientôt (testssl)
            if 'cert_expirationStatus' in eid or 'cert_notAfter' in eid:
                if finding and re.search(r'expired|< 30 days|<= 30', finding, re.I):
                    days_m = re.search(r'(\d+)\s*days', finding)
                    days = int(days_m.group(1)) if days_m else 0
                    sev_cert = 'CRITICAL' if 'expired' in finding.lower() else 'HIGH'
                    add_issue(target_ts, sev_cert,
                              f'Certificat expire bientôt sur {target_ts}: {finding[:80]}',
                              'Renouveler le certificat SSL/TLS')

            # Certificat auto-signé (testssl)
            if 'cert_chain_of_trust' in eid and ('self signed' in finding.lower() or 'untrusted' in finding.lower()):
                add_issue(target_ts, 'MEDIUM',
                          f'Certificat non-fiable sur {target_ts}: {finding[:80]}',
                          'Utiliser un certificat émis par une CA de confiance')

            # HSTS
            if 'hsts' in eid.lower() and 'preload' not in eid.lower():
                if sev in ('WARN', 'NOT_OK') or 'not' in finding.lower() or 'absent' in finding.lower():
                    add_issue(target_ts, 'MEDIUM',
                              f'HSTS manquant ou mal configuré sur {target_ts}',
                              'Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload')

            if 'hsts_preload' in eid.lower():
                if sev in ('WARN', 'NOT_OK') or 'not' in finding.lower():
                    add_issue(target_ts, 'LOW',
                              f'HSTS preload absent sur {target_ts}',
                              'Soumettre le domaine à https://hstspreload.org/ pour protection maximale')

            # Chaîne de certification incomplète (testssl)
            if 'chain_of_trust' in eid.lower() and sev in ('WARN', 'NOT_OK', 'CRITICAL'):
                if 'incomplete' in finding.lower() or 'missing' in finding.lower():
                    add_issue(target_ts, 'MEDIUM',
                              f'Chaîne de certification incomplète sur {target_ts}',
                              'Configurer le serveur pour envoyer la chaîne intermédiaire complète')

    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════
# 3. PARSE NMAP XML (Heartbleed, ciphers supplémentaires)
# ══════════════════════════════════════════════════════════════════════════
try:
    import xml.etree.ElementTree as ET
    tree = ET.parse(f'{out}/nmap_ssl.xml')
    for hel in tree.getroot().findall('host'):
        ip = next((a.get('addr') for a in hel.findall('address') if a.get('addrtype') == 'ipv4'), '')
        for sc in hel.findall('.//script'):
            sid = sc.get('id', ''); o = sc.get('output', '')
            if 'ssl-heartbleed' in sid and 'VULNERABLE' in o:
                add_issue(ip, 'CRITICAL', f'Heartbleed (CVE-2014-0160) confirmé par Nmap sur {ip}',
                          'Patcher OpenSSL >= 1.0.1g et révoquer les certificats')
            if 'ssl-poodle' in sid and 'VULNERABLE' in o:
                add_issue(ip, 'HIGH', f'POODLE (CVE-2014-3566) confirmé par Nmap sur {ip}',
                          'Désactiver SSLv3')
except Exception:
    pass

# ══════════════════════════════════════════════════════════════════════════
# Dédup et build summary
# ══════════════════════════════════════════════════════════════════════════
counts = Counter(i['severity'] for i in issues)
json.dump({
    'targets': len(targets_detail),
    'targets_detail': targets_detail,
    'issues': issues,
    'counts': {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH':     counts.get('HIGH', 0),
        'MEDIUM':   counts.get('MEDIUM', 0),
        'LOW':      counts.get('LOW', 0),
    },
}, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)

with open(f'{out}/ssl_results.csv', 'w', newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['Cible','Protocoles','Cert CN','Cert Expiry','Jours restants','Auto-signé'])
    for t, info in targets_detail.items():
        w.writerow([t, ', '.join(info.get('protocols', [])),
                    info.get('cert_cn', ''), info.get('cert_expiry', ''),
                    info.get('cert_days_remaining', ''),
                    'Oui' if info.get('cert_selfsigned') else 'Non'])

print(f"SSL: {len(targets_detail)} cibles, {len(issues)} issues "
      f"(C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)})")
SSLPY

RC=$?
if [[ $RC -ne 0 ]]; then error "Module SSL ÉCHOUÉ (Python $RC)"; exit 1; fi
if [[ ! -s "$OUT/summary.json" ]]; then error "ssl/summary.json vide"; exit 1; fi
success "Module SSL/TLS terminé"
