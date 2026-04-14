#!/bin/bash
#============================================================================
# 04b - EMAIL SECURITY: Audit SPF / DKIM / DMARC
#
# Utilise le domaine passé via --domain (export CLIENT_DOMAIN)
#
# Vérifie:
#   SPF  — enregistrement TXT, syntaxe, mécanismes, +all dangereux
#   DKIM — selectors courants (default, google, selector1/2, dkim, k1, s1…)
#   DMARC — enregistrement _dmarc, policy, rua/ruf, pourcentage
#   MX   — serveurs mail, priorité, TLS STARTTLS
#   DANE / MTA-STS / BIMI (bonus)
#
# Artefacts:
#   email_security/spf_raw.txt
#   email_security/dkim_results.txt
#   email_security/dmarc_raw.txt
#   email_security/mx_records.txt
#   email_security/summary.json
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/email_security"
DOMAIN="${CLIENT_DOMAIN:-}"

if [[ -z "$DOMAIN" ]]; then
    warning "Pas de domaine client (--domain). Module email sauté."
    echo '{"mode":"skipped","reason":"no_domain","issues":[]}' > "$OUT/summary.json"
    exit 0
fi

log "Audit email security: $DOMAIN"

# ══════════════════════════════════════════════════════════════════════════
# COLLECTE DNS
# ══════════════════════════════════════════════════════════════════════════

# SPF
log "SPF — dig TXT $DOMAIN"
dig +short TXT "$DOMAIN" > "$OUT/spf_raw.txt" 2>/dev/null
# Aussi via nslookup en fallback
nslookup -type=TXT "$DOMAIN" >> "$OUT/spf_raw.txt" 2>/dev/null || true

# DMARC
log "DMARC — dig TXT _dmarc.$DOMAIN"
dig +short TXT "_dmarc.$DOMAIN" > "$OUT/dmarc_raw.txt" 2>/dev/null

# DKIM — tester les sélecteurs courants
log "DKIM — test sélecteurs courants"
> "$OUT/dkim_results.txt"
DKIM_SELECTORS="default google selector1 selector2 dkim k1 k2 s1 s2 s3 mail smtp dkim1 protonmail mandrill mxvault everlytickey1 cm sig1"
for sel in $DKIM_SELECTORS; do
    result=$(dig +short TXT "${sel}._domainkey.$DOMAIN" 2>/dev/null)
    if [[ -n "$result" && "$result" != *"NXDOMAIN"* ]]; then
        echo "SELECTOR: $sel" >> "$OUT/dkim_results.txt"
        echo "$result" >> "$OUT/dkim_results.txt"
        echo "" >> "$OUT/dkim_results.txt"
    fi
done

# MX
log "MX — dig MX $DOMAIN"
dig +short MX "$DOMAIN" > "$OUT/mx_records.txt" 2>/dev/null

# MTA-STS
log "MTA-STS — dig TXT _mta-sts.$DOMAIN"
dig +short TXT "_mta-sts.$DOMAIN" > "$OUT/mta_sts.txt" 2>/dev/null || true

# DANE / TLSA
log "DANE — dig TLSA _25._tcp.mx.*"
> "$OUT/dane_results.txt"
while IFS= read -r mxline; do
    mx=$(echo "$mxline" | awk '{print $NF}' | sed 's/\.$//')
    [[ -z "$mx" ]] && continue
    tlsa=$(dig +short TLSA "_25._tcp.$mx" 2>/dev/null)
    [[ -n "$tlsa" ]] && echo "MX: $mx → TLSA: $tlsa" >> "$OUT/dane_results.txt"
done < "$OUT/mx_records.txt"

# BIMI
log "BIMI — dig TXT default._bimi.$DOMAIN"
dig +short TXT "default._bimi.$DOMAIN" > "$OUT/bimi.txt" 2>/dev/null || true

# STARTTLS check sur MX primaire
MX_PRIMARY=$(head -1 "$OUT/mx_records.txt" | awk '{print $NF}' | sed 's/\.$//')
if [[ -n "$MX_PRIMARY" ]]; then
    log "STARTTLS — test $MX_PRIMARY:25"
    timeout 10 bash -c "echo 'EHLO test' | openssl s_client -connect $MX_PRIMARY:25 -starttls smtp -brief 2>&1" > "$OUT/starttls_check.txt" 2>/dev/null || true
fi

# ══════════════════════════════════════════════════════════════════════════
# ANALYSE PYTHON
# ══════════════════════════════════════════════════════════════════════════
python3 << 'EMAILPY'
import os, json, re
from pathlib import Path

out = os.environ['OUTPUT_DIR'] + '/email_security'
domain = os.environ.get('CLIENT_DOMAIN', '')
issues = []
findings = []

def add_finding(cat, title, severity, score, details='', recommendation=''):
    findings.append({
        'category': cat, 'title': title, 'severity': severity,
        'score_impact': score, 'details': details, 'recommendation': recommendation
    })
    issues.append({
        'target': domain, 'severity': severity,
        'issue': f"[Email] {title}", 'recommendation': recommendation,
        'module': 'email_security'
    })

# ── SPF ───────────────────────────────────────────────────────────────────
spf_raw = Path(f'{out}/spf_raw.txt').read_text().strip() if Path(f'{out}/spf_raw.txt').exists() else ''
spf_record = ''
for line in spf_raw.replace('"','').split('\n'):
    if 'v=spf1' in line.lower():
        spf_record = line.strip(); break

spf_data = {
    'record': spf_record, 'exists': bool(spf_record),
    'mechanisms': [], 'policy': '', 'issues': []
}

if not spf_record:
    add_finding('SPF', 'Pas d\'enregistrement SPF', 'HIGH', 8,
        f'{domain} n\'a pas d\'enregistrement SPF publié.',
        'Créer un enregistrement TXT SPF: v=spf1 include:... -all')
    spf_data['issues'].append('absent')
else:
    # Parser les mécanismes
    parts = spf_record.split()
    for p in parts:
        if p.startswith('v='): continue
        spf_data['mechanisms'].append(p)

    # Qualifier final
    if '+all' in spf_record:
        add_finding('SPF', 'SPF avec +all (permissif)', 'CRITICAL', 12,
            'Le mécanisme +all autorise TOUT expéditeur à envoyer au nom du domaine.',
            'Remplacer +all par ~all ou -all')
        spf_data['policy'] = '+all'
        spf_data['issues'].append('+all')
    elif '~all' in spf_record:
        add_finding('SPF', 'SPF avec ~all (softfail)', 'MEDIUM', 3,
            'Le mécanisme ~all signale les échecs mais ne rejette pas.',
            'Passer de ~all à -all après validation de la couverture SPF')
        spf_data['policy'] = '~all'
    elif '-all' in spf_record:
        spf_data['policy'] = '-all'  # OK
    elif '?all' in spf_record:
        add_finding('SPF', 'SPF avec ?all (neutre)', 'HIGH', 6,
            'Le mécanisme ?all ne fournit aucune protection.',
            'Remplacer ?all par ~all ou -all')
        spf_data['policy'] = '?all'
        spf_data['issues'].append('?all')
    else:
        add_finding('SPF', 'SPF sans qualifier all', 'MEDIUM', 4,
            'Pas de mécanisme all explicite. Par défaut: ?all (neutre).',
            'Ajouter -all en fin d\'enregistrement SPF')
        spf_data['policy'] = 'implicit ?all'

    # Trop d'includes (max 10 lookups DNS)
    includes = [p for p in parts if p.startswith('include:')]
    redirects = [p for p in parts if p.startswith('redirect=')]
    lookup_count = len(includes) + len(redirects) + len([p for p in parts if p.startswith(('a:','mx:','ptr:','exists:'))])
    if lookup_count > 10:
        add_finding('SPF', f'SPF: trop de lookups DNS ({lookup_count}/10)', 'HIGH', 6,
            'SPF est limité à 10 lookups DNS. Au-delà, le SPF échoue (permerror).',
            'Réduire le nombre d\'includes ou utiliser des mécanismes ip4:/ip6:')

# ── DMARC ─────────────────────────────────────────────────────────────────
dmarc_raw = Path(f'{out}/dmarc_raw.txt').read_text().strip() if Path(f'{out}/dmarc_raw.txt').exists() else ''
dmarc_record = ''
for line in dmarc_raw.replace('"','').split('\n'):
    if 'v=dmarc1' in line.lower():
        dmarc_record = line.strip(); break

dmarc_data = {
    'record': dmarc_record, 'exists': bool(dmarc_record),
    'policy': '', 'sub_policy': '', 'rua': '', 'ruf': '', 'pct': 100
}

if not dmarc_record:
    add_finding('DMARC', 'Pas d\'enregistrement DMARC', 'HIGH', 8,
        f'_dmarc.{domain} n\'a pas d\'enregistrement DMARC.',
        'Créer: _dmarc.{domain} TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"')
else:
    # Parser les tags
    tags = {}
    for part in dmarc_record.replace(' ','').split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()

    dmarc_data['policy'] = tags.get('p', '')
    dmarc_data['sub_policy'] = tags.get('sp', '')
    dmarc_data['rua'] = tags.get('rua', '')
    dmarc_data['ruf'] = tags.get('ruf', '')
    try: dmarc_data['pct'] = int(tags.get('pct', '100'))
    except: dmarc_data['pct'] = 100

    policy = tags.get('p', 'none').lower()
    if policy == 'none':
        add_finding('DMARC', 'DMARC policy = none (monitoring only)', 'MEDIUM', 5,
            'La policy DMARC est en mode monitoring. Les emails frauduleux ne sont pas bloqués.',
            'Passer progressivement de p=none à p=quarantine puis p=reject')
    elif policy == 'quarantine':
        pass  # Acceptable
    elif policy == 'reject':
        pass  # Best practice

    if not dmarc_data['rua']:
        add_finding('DMARC', 'DMARC sans adresse de rapport (rua)', 'LOW', 2,
            'Pas de tag rua= dans DMARC. Les rapports agrégés ne sont pas collectés.',
            'Ajouter rua=mailto:dmarc-reports@{domain}')

    if dmarc_data['pct'] < 100:
        add_finding('DMARC', f'DMARC pct={dmarc_data["pct"]}% (pas 100%)', 'LOW', 2,
            f'Seuls {dmarc_data["pct"]}% des emails sont soumis à la policy DMARC.',
            'Augmenter pct= progressivement vers 100')

# ── DKIM ──────────────────────────────────────────────────────────────────
dkim_raw = Path(f'{out}/dkim_results.txt').read_text().strip() if Path(f'{out}/dkim_results.txt').exists() else ''
dkim_selectors = []
current_sel = ''
for line in dkim_raw.split('\n'):
    if line.startswith('SELECTOR:'):
        current_sel = line.split(':',1)[1].strip()
    elif current_sel and line.strip():
        key_data = line.strip().replace('"','')
        dkim_selectors.append({
            'selector': current_sel,
            'record': key_data[:200],
            'has_key': 'p=' in key_data,
            'key_type': 'rsa' if 'k=rsa' in key_data.lower() or ('p=' in key_data and 'k=' not in key_data) else
                        'ed25519' if 'k=ed25519' in key_data.lower() else 'other'
        })
        current_sel = ''

dkim_data = {
    'selectors_found': len(dkim_selectors),
    'selectors': dkim_selectors
}

if not dkim_selectors:
    add_finding('DKIM', 'Aucun sélecteur DKIM trouvé', 'MEDIUM', 5,
        'Aucun sélecteur DKIM standard détecté. Les emails ne sont peut-être pas signés.',
        'Configurer DKIM avec le fournisseur email et publier la clé publique dans le DNS')
else:
    # Vérifier taille de clé (si visible)
    for sel in dkim_selectors:
        rec = sel['record']
        if 'p=' in rec:
            key_b64 = re.search(r'p=([A-Za-z0-9+/=]+)', rec)
            if key_b64:
                key_len = len(key_b64.group(1)) * 6 // 8  # approximation
                if key_len < 128:  # < 1024 bits
                    add_finding('DKIM', f'DKIM clé courte ({sel["selector"]})', 'MEDIUM', 4,
                        f'La clé DKIM du sélecteur {sel["selector"]} semble courte (< 1024 bits).',
                        'Utiliser une clé RSA 2048 bits minimum')

# ── MX ────────────────────────────────────────────────────────────────────
mx_raw = Path(f'{out}/mx_records.txt').read_text().strip() if Path(f'{out}/mx_records.txt').exists() else ''
mx_records = []
for line in mx_raw.split('\n'):
    parts = line.strip().split()
    if len(parts) >= 2:
        try:
            prio = int(parts[0])
            host = parts[1].rstrip('.')
            mx_records.append({'priority': prio, 'host': host})
        except: pass

mx_data = {'records': mx_records, 'count': len(mx_records)}

if not mx_records:
    add_finding('MX', 'Pas d\'enregistrement MX', 'HIGH', 6,
        f'{domain} n\'a pas d\'enregistrement MX.',
        'Configurer les enregistrements MX pour la réception des emails')

# STARTTLS
starttls_ok = False
starttls_raw = ''
if Path(f'{out}/starttls_check.txt').exists():
    starttls_raw = Path(f'{out}/starttls_check.txt').read_text()
    starttls_ok = 'SSL-Session' in starttls_raw or 'Protocol' in starttls_raw

# MTA-STS
mta_sts_raw = Path(f'{out}/mta_sts.txt').read_text().strip() if Path(f'{out}/mta_sts.txt').exists() else ''
has_mta_sts = 'v=STSv1' in mta_sts_raw

# BIMI
bimi_raw = Path(f'{out}/bimi.txt').read_text().strip() if Path(f'{out}/bimi.txt').exists() else ''
has_bimi = 'v=bimi1' in bimi_raw.lower()

# DANE
dane_raw = Path(f'{out}/dane_results.txt').read_text().strip() if Path(f'{out}/dane_results.txt').exists() else ''
has_dane = bool(dane_raw)

# ── SCORING ───────────────────────────────────────────────────────────────
email_score = sum(f['score_impact'] for f in findings)
email_score = min(100, email_score)

if email_score <= 10: risk = 'Faible'
elif email_score <= 25: risk = 'Moyen'
elif email_score <= 50: risk = 'Élevé'
else: risk = 'Critique'

# ── SUMMARY ───────────────────────────────────────────────────────────────
summary = {
    'domain': domain,
    'email_score': email_score,
    'risk_level': risk,
    'spf': spf_data,
    'dmarc': dmarc_data,
    'dkim': dkim_data,
    'mx': mx_data,
    'starttls': {'tested': bool(starttls_raw), 'ok': starttls_ok, 'mx_primary': mx_records[0]['host'] if mx_records else ''},
    'extras': {
        'mta_sts': has_mta_sts,
        'dane': has_dane,
        'bimi': has_bimi
    },
    'findings': findings,
    'issues': issues,
    'total_findings': len(findings)
}

json.dump(summary, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)

print(f"Email Security: {domain}")
print(f"  SPF:   {'✓ ' + spf_data['policy'] if spf_data['exists'] else '✗ Absent'}")
print(f"  DMARC: {'✓ p=' + dmarc_data['policy'] if dmarc_data['exists'] else '✗ Absent'}")
print(f"  DKIM:  {'✓ ' + str(len(dkim_selectors)) + ' sélecteur(s)' if dkim_selectors else '✗ Aucun sélecteur'}")
print(f"  MX:    {'✓ ' + str(len(mx_records)) + ' serveur(s)' if mx_records else '✗ Absent'}")
print(f"  Score: {email_score}/100 ({risk})")
EMAILPY

success "Module email security terminé"
