#!/bin/bash
#============================================================================
# 02 - SMB: Shares, versions, signing, permissions, vulnérabilités
# v4.5.1 — Ajouts: enum4linux-ng prioritaire, null sessions, recherche
#           fichiers sensibles dans shares accessibles (.kdbx, passwords…)
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/smb"
HOSTS="$OUTPUT_DIR/discovery/smb_hosts.txt"

if [[ ! -s "$HOSTS" ]]; then
    warning "Aucun hôte SMB détecté"
    echo '{"total":0,"issues":[],"counts":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}}' > "$OUT/summary.json"
    exit 0
fi
log "$(wc -l < "$HOSTS") hôtes SMB"

# ══════════════════════════════════════════════════════════════════════════
# VERSIONS SMB ET SIGNING
# ══════════════════════════════════════════════════════════════════════════
log "Versions SMB et signing"
nmap -p 139,445 --script smb-protocols,smb2-security-mode,smb-security-mode,smb-os-discovery \
    -iL "$HOSTS" -oA "$OUT/versions" -oX "$OUT/versions.xml" 2>/dev/null
success "Versions scannées"

# ══════════════════════════════════════════════════════════════════════════
# ENUM SHARES (CrackMapExec / NXC)
# ══════════════════════════════════════════════════════════════════════════
CME=""; command -v nxc &>/dev/null && CME="nxc"; command -v crackmapexec &>/dev/null && CME="${CME:-crackmapexec}"
if [[ -n "$CME" ]]; then
    log "Enum shares ($CME) — null + guest"
    $CME smb $(cat "$HOSTS" | tr '\n' ' ') --shares -u '' -p ''       > "$OUT/shares_null.txt"  2>/dev/null || true
    $CME smb $(cat "$HOSTS" | tr '\n' ' ') --shares -u 'guest' -p ''  > "$OUT/shares_guest.txt" 2>/dev/null || true
    # Null session: test authentification
    $CME smb $(cat "$HOSTS" | tr '\n' ' ') -u '' -p '' 2>/dev/null | tee "$OUT/null_session.txt" >/dev/null || true
fi

# ══════════════════════════════════════════════════════════════════════════
# ACCÈS SHARES + RECHERCHE FICHIERS SENSIBLES
# ══════════════════════════════════════════════════════════════════════════
log "Test accès shares (smbclient)"
> "$OUT/shares_access.txt"
> "$OUT/sensitive_files.txt"

# Patterns de fichiers sensibles à rechercher dans les shares
SENSITIVE_KEYWORDS="kdbx\|\.kdb\|password\|passwords\|credential\|secret\|id_rsa\|id_dsa\|\.pfx\|\.p12\|\.ppk\|web\.config\|appsettings\.json\|\.env\b\|\.sql\b\|dump\.sql\|backup\.sql\|wp-config\|\.pem\|private\.key\|config\.php\|passw"

while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    echo "═══ $ip ═══" >> "$OUT/shares_access.txt"
    shares=$(timeout 15 smbclient -L "//$ip" -N 2>/dev/null | grep -iE "^\s+\S+\s+Disk" | awk '{print $1}')
    [[ -z "$shares" ]] && { echo "  (aucun share listé ou accès refusé)" >> "$OUT/shares_access.txt"; continue; }

    for s in $shares; do
        r="  \\\\$ip\\$s → "
        if timeout 15 smbclient "//$ip/$s" -N -c "ls" &>/dev/null 2>/dev/null; then
            r+="LECTURE"
            # Test écriture
            tmp=$(mktemp); echo "audit_test" > "$tmp"
            if timeout 10 smbclient "//$ip/$s" -N -c "put $tmp .audit_rw_test; rm .audit_rw_test" &>/dev/null 2>/dev/null; then
                r+=" + ECRITURE"
            fi
            rm -f "$tmp"

            # Recherche fichiers sensibles (listing récursif limité)
            log "    [sensible] $ip\\$s"
            sensitive_hits=$(timeout 30 smbclient "//$ip/$s" -N \
                -c "recurse on; ls" 2>/dev/null | \
                grep -iE "$SENSITIVE_KEYWORDS" | head -20 || true)
            if [[ -n "$sensitive_hits" ]]; then
                echo "=== $ip\\$s ===" >> "$OUT/sensitive_files.txt"
                echo "$sensitive_hits"  >> "$OUT/sensitive_files.txt"
                warning "    Fichiers sensibles trouvés dans $ip\\$s"
            fi
        else
            r+="PAS D'ACCÈS (anonyme)"
        fi
        echo "$r" >> "$OUT/shares_access.txt"
    done
done < "$HOSTS"

# ══════════════════════════════════════════════════════════════════════════
# ENUM4LINUX-NG (prioritaire) ou ENUM4LINUX
# ══════════════════════════════════════════════════════════════════════════
if command -v enum4linux-ng &>/dev/null; then
    log "enum4linux-ng (mode complet)"
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        timeout 120 enum4linux-ng -A "$ip" -oJ "$OUT/enum_${ip}" 2>/dev/null || true
    done < "$HOSTS"
elif command -v enum4linux &>/dev/null; then
    log "enum4linux"
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        timeout 120 enum4linux -a "$ip" > "$OUT/enum_${ip}.txt" 2>/dev/null || true
    done < "$HOSTS"
else
    warning "enum4linux / enum4linux-ng absent"
fi

# ══════════════════════════════════════════════════════════════════════════
# SCAN VULNS SMB (EternalBlue, MS08-067, etc.)
# ══════════════════════════════════════════════════════════════════════════
log "Scan vulns SMB (EternalBlue, MS08-067…)"
nmap -p 445 --script "smb-vuln-*" -iL "$HOSTS" -oA "$OUT/vulns" 2>/dev/null

# ══════════════════════════════════════════════════════════════════════════
# ANALYSE PYTHON
# ══════════════════════════════════════════════════════════════════════════
python3 << 'PY'
import xml.etree.ElementTree as ET, json, os, re
from collections import Counter
out = os.environ['OUTPUT_DIR'] + '/smb'
issues = []
seen = set()

def add_issue(target, severity, issue, recommendation):
    k = f"{target}|{issue[:80]}"
    if k not in seen:
        seen.add(k)
        issues.append({'target': target, 'severity': severity,
                       'issue': issue, 'recommendation': recommendation,
                       'module': 'smb'})

# ── Versions SMB et signing ────────────────────────────────────────────
try:
    tree = ET.parse(f'{out}/versions.xml')
    for hel in tree.getroot().findall('host'):
        ip = next((a.get('addr') for a in hel.findall('address') if a.get('addrtype') == 'ipv4'), '')
        for sc in hel.findall('.//script'):
            o = sc.get('output', ''); sid = sc.get('id', '')
            if 'smb-protocols' in sid:
                if 'SMBv1' in o:
                    add_issue(ip, 'CRITICAL', f'SMBv1 activé sur {ip} — vulnérable EternalBlue/WannaCry',
                              'Désactiver SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false')
                if 'SMB2' not in o and 'SMB3' not in o and 'SMBv1' in o:
                    add_issue(ip, 'CRITICAL', f'SMBv1 uniquement sur {ip}',
                              'Mettre à jour Windows et désactiver SMBv1')
            if 'security-mode' in sid:
                if 'not required' in o.lower() or 'disabled' in o.lower():
                    add_issue(ip, 'HIGH', f'SMB signing non requis sur {ip} — risque NTLM relay',
                              'GPO: Microsoft network server: Digitally sign = Always require')
                if 'message signing enabled but not required' in o.lower():
                    add_issue(ip, 'MEDIUM', f'SMB signing activé mais non requis sur {ip}',
                              'Renforcer: passer de "enabled" à "required"')
except Exception as e:
    pass

# ── Vulnérabilités Nmap (VULNERABLE) ───────────────────────────────────
try:
    c = open(f'{out}/vulns.nmap').read(); host = ''
    for line in c.split('\n'):
        if 'Nmap scan report' in line:
            host = line.split()[-1].strip('()')
        if 'VULNERABLE' in line:
            add_issue(host, 'CRITICAL', line.strip()[:150],
                      'Appliquer les patchs Microsoft de sécurité correspondants')
except Exception:
    pass

# ── Inventaire shares (CME/NXC + smbclient) ────────────────────────────
# Construit shares_inventory = {ip: [{name, permissions, comment}]}
# en parsant les fichiers CME (permissions explicites) puis shares_access.txt
CME_PAT = re.compile(r'^\s*SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\S+\s+(.*)')
shares_inventory = {}

def _parse_cme(fpath):
    if not os.path.exists(fpath): return
    in_shares = set()
    for raw in open(fpath, errors='replace'):
        m = CME_PAT.match(raw)
        if not m: continue
        ip, rest = m.group(1), m.group(2).strip()
        shares_inventory.setdefault(ip, [])
        if 'Enumerated shares' in rest:
            in_shares.add(ip); continue
        if ip not in in_shares: continue
        if re.search(r'Share\s+Permission', rest) or re.match(r'^-{3}', rest) or not rest:
            continue
        parts = [p for p in re.split(r'\s{2,}', rest) if p.strip()]
        if not parts: continue
        sname = parts[0].strip()
        if not re.match(r'^[A-Za-z0-9_$@!#.\-]+$', sname): continue
        perms   = parts[1].strip() if len(parts) > 1 else ''
        comment = parts[2].strip() if len(parts) > 2 else ''
        # Si le 2e champ n'est pas READ/WRITE, c'est le commentaire
        if not re.match(r'^(READ|WRITE|NO ACCESS|,|\s)*$', perms, re.I):
            comment = (perms + ' ' + comment).strip(); perms = ''
        perms = perms.upper()
        existing = next((s for s in shares_inventory[ip]
                         if s['name'].upper() == sname.upper()), None)
        if existing:
            if perms and not existing['permissions']: existing['permissions'] = perms
        else:
            shares_inventory[ip].append({'name': sname, 'permissions': perms, 'comment': comment})

_parse_cme(f'{out}/shares_null.txt')
_parse_cme(f'{out}/shares_guest.txt')

# Enrichir / compléter avec les résultats smbclient (shares_access.txt)
try:
    cur_ip = ''
    for raw in open(f'{out}/shares_access.txt'):
        line = raw.strip()
        if '═══' in line:
            m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            cur_ip = m.group(1) if m else ''; continue
        if '→' not in line or not cur_ip: continue
        left, right = line.split('→', 1)
        m = re.search(r'\\\\(?:[\d.]+)\\(\S+)', left)
        sname = m.group(1) if m else ''
        if not sname: continue
        access = right.strip()
        perms = 'READ,WRITE' if 'ECRITURE' in access else ('READ' if 'LECTURE' in access else '')
        shares_inventory.setdefault(cur_ip, [])
        existing = next((s for s in shares_inventory[cur_ip]
                         if s['name'].upper() == sname.upper()), None)
        if existing:
            if perms and not existing['permissions']: existing['permissions'] = perms
        else:
            shares_inventory[cur_ip].append({'name': sname, 'permissions': perms, 'comment': ''})
except Exception:
    pass

# Générer issues à partir de l'inventaire
for ip, sh_list in shares_inventory.items():
    for sh in sh_list:
        p = sh.get('permissions', '').upper()
        n = sh.get('name', '')
        if 'WRITE' in p:
            add_issue(ip, 'HIGH',
                      f'Share {n} accessible en écriture anonyme sur {ip}',
                      "Supprimer les droits d'accès anonyme en écriture")
        elif 'READ' in p and n.upper() not in ('IPC$',):
            add_issue(ip, 'MEDIUM',
                      f'Share {n} accessible en lecture anonyme sur {ip}',
                      "Restreindre l'accès anonyme (GPO: RestrictNullSessAccess=1)")

# ── Null session (nxc/cme) ─────────────────────────────────────────────
try:
    for line in open(f'{out}/null_session.txt'):
        if '(+)' in line or '[+]' in line:
            ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            ip = ip_m.group(1) if ip_m else 'inconnu'
            add_issue(ip, 'HIGH',
                      f'Null session SMB acceptée sur {ip}',
                      'Configurer RestrictAnonymous=2 et désactiver les null sessions')
except Exception:
    pass

# ── Fichiers sensibles dans shares ─────────────────────────────────────
try:
    current_share = ''
    for line in open(f'{out}/sensitive_files.txt'):
        line = line.strip()
        if line.startswith('==='):
            current_share = line.strip('= ')
        elif line:
            # Déterminer sévérité par type de fichier
            line_l = line.lower()
            if any(p in line_l for p in ['id_rsa', 'id_dsa', '.ppk', '.pem', 'private.key', '.pfx', '.p12']):
                sev = 'CRITICAL'
                rec = 'Supprimer immédiatement les clés privées des partages réseau'
            elif any(p in line_l for p in ['password', 'credential', 'secret', '.kdbx', '.kdb']):
                sev = 'CRITICAL'
                rec = 'Supprimer ou chiffrer les fichiers de mots de passe des partages'
            elif any(p in line_l for p in ['dump.sql', 'backup.sql', '.sql', 'web.config', 'appsettings', 'wp-config']):
                sev = 'HIGH'
                rec = 'Déplacer les fichiers sensibles hors des partages accessibles'
            elif any(p in line_l for p in ['.env', 'config.php']):
                sev = 'HIGH'
                rec = 'Retirer les fichiers de configuration des partages réseau'
            else:
                sev = 'MEDIUM'
                rec = 'Auditer ce fichier et restreindre l\'accès si nécessaire'

            fname = re.search(r'\S+\.\w+', line)
            fname = fname.group(0) if fname else line[:60]
            add_issue(current_share or 'SMB share', sev,
                      f'Fichier sensible accessible dans share: {fname}', rec)
except Exception:
    pass

# ── enum4linux-ng : null session user enum ─────────────────────────────
import glob
for jfile in glob.glob(f'{out}/enum_*.json'):
    try:
        data = json.load(open(jfile))
        if data.get('users'):
            ip = os.path.basename(jfile).replace('enum_', '').replace('.json', '')
            n = len(data['users'])
            if n > 0:
                add_issue(ip, 'MEDIUM',
                          f'Énumération utilisateurs via null session ({n} comptes)',
                          'Activer RestrictAnonymous et désactiver la null session')
        if data.get('groups'):
            ip = os.path.basename(jfile).replace('enum_', '').replace('.json', '')
            add_issue(ip, 'LOW',
                      f'Énumération groupes via null session',
                      'Restreindre l\'accès RPC anonyme')
    except Exception:
        pass

# ── Build summary ──────────────────────────────────────────────────────
try:
    total = int(open(f"{os.environ['OUTPUT_DIR']}/discovery/smb_hosts.txt").read().strip().count('\n')) + 1
except Exception:
    total = 0
counts = Counter(i['severity'] for i in issues)
json.dump({
    'total': total,
    'shares_inventory': shares_inventory,
    'issues': issues,
    'counts': {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH':     counts.get('HIGH', 0),
        'MEDIUM':   counts.get('MEDIUM', 0),
        'LOW':      counts.get('LOW', 0),
    },
}, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)
print(f"SMB: {len(issues)} issues (C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)})")
PY

RC=$?
if [[ $RC -ne 0 ]]; then error "Module SMB ÉCHOUÉ (Python $RC)"; exit 1; fi
if [[ ! -s "$OUT/summary.json" ]]; then error "smb/summary.json vide"; exit 1; fi
success "Module SMB terminé"
