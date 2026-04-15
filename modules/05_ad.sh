#!/bin/bash
#============================================================================
# 05 - ACTIVE DIRECTORY: Audit PingCastle-style
# v4.5.1 — Ajouts: BloodHound collection, admins inactifs, LDAP channel
#           binding, pwdLastSet admins, Protected Users, fix os.environ
#
# Catégories: Configuration domaine, Comptes à risque, Kerberos,
# Délégations, Objets sensibles, Vulnérabilités critiques, Exposition
# Score: 0-30 faible, 31-60 moyen, 61-80 élevé, 81-100 critique
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/ad"
DC_IP="${DOMAIN_CONTROLLER:-}"

# ── Trouver le DC ─────────────────────────────────────────────────────
if [[ -z "$DC_IP" ]]; then
    log "Auto-détection DC"
    DC_FILE="$OUTPUT_DIR/discovery/dc_candidates.txt"
    if [[ -s "$DC_FILE" ]]; then DC_IP=$(head -1 "$DC_FILE")
    else DC_IP=$(nmap -p 88,389 --open "$NETWORK" -oG - 2>/dev/null | grep -E "88/open.*389/open|389/open.*88/open" | awk '{print $2}' | head -1); fi
fi
if [[ -z "$DC_IP" ]]; then
    warning "Aucun DC détecté"
    echo '{"status":"no_dc","ad_score":0,"issues":[],"findings":[],"counts":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}}' > "$OUT/summary.json"
    exit 0
fi
export DC_IP
log "DC: $DC_IP"

# ── 1. Fingerprint DC ────────────────────────────────────────────────
log "Fingerprint DC"
nmap -sS -sV -sC -O -p 53,88,135,139,389,445,464,636,3268,3269,5985,5986,9389 \
    "$DC_IP" -oA "$OUT/dc_fingerprint" -oX "$OUT/dc_fingerprint.xml" 2>/dev/null

DOMAIN_NAME=$(grep -oP '(?<=Domain: )[^,\s]+' "$OUT/dc_fingerprint.nmap" 2>/dev/null | head -1 || true)
DOMAIN_FQDN=$(grep -oP '(?<=DNS.*name: )\S+' "$OUT/dc_fingerprint.nmap" 2>/dev/null | head -1 || true)
NETBIOS=$(grep -oP '(?<=NetBIOS.*name: )\S+' "$OUT/dc_fingerprint.nmap" 2>/dev/null | head -1 || true)
DC_OS=$(grep -oP '(?<=OS details: ).+' "$OUT/dc_fingerprint.nmap" 2>/dev/null | head -1 || true)
[[ -z "$DOMAIN_NAME" ]] && DOMAIN_NAME="${NETBIOS:-}"

BASE_DN=""
if [[ -n "${DOMAIN_FQDN:-}" ]]; then
    BASE_DN=$(echo "${DOMAIN_FQDN%.}" | sed 's/\./,DC=/g; s/^/DC=/')
elif [[ -n "${DOMAIN_NAME:-}" ]]; then
    BASE_DN=$(echo "$DOMAIN_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/\./,DC=/g; s/^/DC=/')
fi
log "Domaine: ${DOMAIN_NAME:-?} | FQDN: ${DOMAIN_FQDN:-?} | BaseDN: ${BASE_DN:-?}"

# ── 2. SMB signing DC ────────────────────────────────────────────────
log "SMB signing et protocoles sur DC"
nmap -p 445 --script smb-protocols,smb2-security-mode,smb-security-mode "$DC_IP" -oA "$OUT/dc_smb" 2>/dev/null

# ── 3. LDAP enumeration ──────────────────────────────────────────────
LDAP_ANON="false"
if command -v ldapsearch &>/dev/null && [[ -n "${BASE_DN:-}" ]]; then
    log "Test LDAP anonymous bind"
    LDAP_TEST=$(ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" -s base "(objectClass=*)" 2>/dev/null || true)
    if echo "$LDAP_TEST" | grep -q "dn:"; then
        LDAP_ANON="true"; warning "LDAP anonymous bind AUTORISÉ"
        log "  Info domaine"
        ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" -s base "(objectClass=*)" msDS-Behavior-Version \
            > "$OUT/ldap_domain_info.txt" 2>/dev/null || true
        log "  Enum DCs"
        ldapsearch -x -H "ldap://$DC_IP" -b "OU=Domain Controllers,$BASE_DN" "(objectClass=computer)" \
            cn dNSHostName operatingSystem operatingSystemVersion whenCreated whenChanged \
            > "$OUT/ldap_dcs.txt" 2>/dev/null || true
        log "  Enum utilisateurs"
        ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" \
            "(&(objectClass=user)(objectCategory=person))" \
            sAMAccountName displayName description memberOf userAccountControl \
            pwdLastSet lastLogonTimestamp whenCreated servicePrincipalName \
            msDS-AllowedToDelegateTo adminCount mail \
            -E pr=1000/noprompt > "$OUT/ldap_users.txt" 2>/dev/null || true
        log "  Groupes privilégiés"
        for grp in "Domain Admins" "Administrateurs du domaine" "Enterprise Admins" \
                   "Schema Admins" "Account Operators" "Server Operators" \
                   "Backup Operators" "Print Operators" "DnsAdmins"; do
            ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" \
                "(&(objectClass=group)(|(cn=$grp)(sAMAccountName=$grp)))" \
                member cn >> "$OUT/ldap_privileged_groups.txt" 2>/dev/null || true
        done
        log "  Protected Users"
        ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" \
            "(&(objectClass=group)(cn=Protected Users))" \
            member cn > "$OUT/ldap_protected_users.txt" 2>/dev/null || true
        log "  Politique mots de passe"
        ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" -s base "(objectClass=domain)" \
            minPwdLength maxPwdAge minPwdAge lockoutThreshold lockoutDuration \
            pwdHistoryLength pwdProperties > "$OUT/ldap_pwpolicy.txt" 2>/dev/null || true
        ldapsearch -x -H "ldap://$DC_IP" -b "CN=Password Settings Container,CN=System,$BASE_DN" \
            "(objectClass=msDS-PasswordSettings)" \
            cn msDS-MinimumPasswordLength msDS-PasswordComplexityEnabled msDS-LockoutThreshold \
            > "$OUT/ldap_fgpp.txt" 2>/dev/null || true
        log "  Enum ordinateurs"
        ldapsearch -x -H "ldap://$DC_IP" -b "$BASE_DN" "(objectClass=computer)" \
            cn operatingSystem operatingSystemVersion dNSHostName \
            userAccountControl msDS-AllowedToDelegateTo whenCreated lastLogonTimestamp \
            > "$OUT/ldap_computers.txt" 2>/dev/null || true
        log "  Enum GPOs"
        ldapsearch -x -H "ldap://$DC_IP" -b "CN=Policies,CN=System,$BASE_DN" \
            "(objectClass=groupPolicyContainer)" \
            displayName cn gPCFileSysPath whenCreated whenChanged \
            > "$OUT/ldap_gpos.txt" 2>/dev/null || true
        log "  Enum trusts"
        ldapsearch -x -H "ldap://$DC_IP" -b "CN=System,$BASE_DN" "(objectClass=trustedDomain)" \
            cn trustType trustDirection trustAttributes > "$OUT/ldap_trusts.txt" 2>/dev/null || true
        log "  LDAP signing + channel binding settings"
        ldapsearch -x -H "ldap://$DC_IP" \
            -b "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$BASE_DN" \
            "(objectClass=nTDSService)" msDS-Other-Settings \
            > "$OUT/ldap_signing.txt" 2>/dev/null || true
    else
        success "LDAP anonymous bind refusé (OK)"
    fi
fi

# ── 3b. LDAP channel binding (LDAPS) ───────────────────────────────────
LDAP_CHANNEL_BINDING="unknown"
if command -v ldapsearch &>/dev/null; then
    log "LDAP channel binding check (LDAPS port 636)"
    cb_out=$(ldapsearch -x -H "ldaps://$DC_IP" -b "" -s base "(objectClass=*)" 2>&1 || true)
    if echo "$cb_out" | grep -q "dn:"; then
        LDAP_CHANNEL_BINDING="not_required"
        warning "LDAP channel binding non requis (CVE-2017-8563 — relay possible)"
    elif echo "$cb_out" | grep -qi "channel.bind\|80090346\|strong.*auth\|WSACONNRESET"; then
        LDAP_CHANNEL_BINDING="required"
        success "LDAP channel binding requis (OK)"
    fi
fi

# ── 4. RPC null session ──────────────────────────────────────────────
RPC_NULL="false"
if command -v rpcclient &>/dev/null; then
    log "Test RPC null session"
    {   echo "=== querydominfo ==="
        rpcclient -U "" -N "$DC_IP" -c "querydominfo" 2>/dev/null || echo "(refusé)"
        echo -e "\n=== enumdomusers ==="
        rpcclient -U "" -N "$DC_IP" -c "enumdomusers" 2>/dev/null | head -100 || echo "(refusé)"
        echo -e "\n=== enumdomgroups ==="
        rpcclient -U "" -N "$DC_IP" -c "enumdomgroups" 2>/dev/null || echo "(refusé)"
        echo -e "\n=== getdompwinfo ==="
        rpcclient -U "" -N "$DC_IP" -c "getdompwinfo" 2>/dev/null || echo "(refusé)"
    } > "$OUT/rpc_enum.txt"
    grep -q "user:" "$OUT/rpc_enum.txt" && RPC_NULL="true" || true
fi

# ── 5. Kerberos ──────────────────────────────────────────────────────
if command -v impacket-GetNPUsers &>/dev/null && [[ -s "$OUT/ldap_users.txt" ]]; then
    log "AS-REP Roasting"
    grep "sAMAccountName:" "$OUT/ldap_users.txt" | awk '{print $2}' > "$OUT/usernames.txt" 2>/dev/null || true
    [[ -s "$OUT/usernames.txt" ]] && \
        impacket-GetNPUsers "${DOMAIN_FQDN%.}/" -usersfile "$OUT/usernames.txt" \
            -dc-ip "$DC_IP" -format hashcat -outputfile "$OUT/asrep_hashes.txt" \
            2>/dev/null || true
fi
if command -v impacket-GetUserSPNs &>/dev/null && [[ -n "${DOMAIN_FQDN:-}" ]]; then
    log "Kerberoasting (anonymous)"
    impacket-GetUserSPNs "${DOMAIN_FQDN%.}/" -dc-ip "$DC_IP" -no-pass \
        -outputfile "$OUT/kerberoast_hashes.txt" > "$OUT/kerberoast.txt" 2>/dev/null || true
fi

# ── 6. Delegations ───────────────────────────────────────────────────
if command -v impacket-findDelegation &>/dev/null && [[ -n "${DOMAIN_FQDN:-}" ]]; then
    log "Delegation check"
    impacket-findDelegation "${DOMAIN_FQDN%.}/" -dc-ip "$DC_IP" -no-pass \
        > "$OUT/delegations.txt" 2>/dev/null || true
fi

# ── 7. Zerologon ─────────────────────────────────────────────────────
log "Zerologon + EternalBlue check"
nmap -p 135,139,445 --script "smb-vuln-ms17-010" "$DC_IP" -oA "$OUT/dc_vulns" 2>/dev/null || true
nmap -p 135 --script "ms-nrpc-zerologon" "$DC_IP" > "$OUT/zerologon.txt" 2>/dev/null || true

# ── 8. SYSVOL / NETLOGON ─────────────────────────────────────────────
log "Test SYSVOL/NETLOGON"
{   echo "=== SYSVOL ==="
    smbclient "//$DC_IP/SYSVOL" -N -c "ls" 2>/dev/null || echo "(refusé)"
    echo -e "\n=== NETLOGON ==="
    smbclient "//$DC_IP/NETLOGON" -N -c "ls" 2>/dev/null || echo "(refusé)"
} > "$OUT/sysvol_netlogon.txt"

# ── 9. DNS zone transfer via DC ──────────────────────────────────────
ZONE_TRANSFER="false"
if [[ -n "${DOMAIN_FQDN:-}" ]]; then
    dig axfr "${DOMAIN_FQDN%.}" @"$DC_IP" > "$OUT/zone_transfer.txt" 2>/dev/null || true
    grep -q "XFR size" "$OUT/zone_transfer.txt" 2>/dev/null && ZONE_TRANSFER="true" || true
fi

# ── 9b. BloodHound collection ─────────────────────────────────────────
if command -v bloodhound-python &>/dev/null && [[ -n "${DOMAIN_FQDN:-}" ]]; then
    log "BloodHound collection (best-effort, null auth)"
    mkdir -p "$OUT/bloodhound"
    timeout 180 bloodhound-python \
        -d "${DOMAIN_FQDN%.}" \
        --dc "$DC_IP" \
        --no-pass \
        -c DCOnly,Trusts \
        --zip \
        -o "$OUT/bloodhound" 2>/dev/null || true
    if ls "$OUT/bloodhound/"*.zip &>/dev/null 2>&1; then
        success "BloodHound: données collectées ($(ls "$OUT/bloodhound/"*.zip | wc -l) archive(s))"
    else
        warning "BloodHound: collecte échouée (auth requise?)"
    fi
fi

# ── 10. Export variables pour Python ─────────────────────────────────
# IMPORTANT: le bloc Python utilise un heredoc single-quoted ('ADPY') donc
# aucune expansion shell n'a lieu — toutes les variables bash doivent être
# exportées et lues via os.environ.get() dans Python.
export DOMAIN_NAME DOMAIN_FQDN NETBIOS BASE_DN DC_OS
export LDAP_ANON RPC_NULL ZONE_TRANSFER LDAP_CHANNEL_BINDING

# ── 11. Analyse Python PingCastle-style ──────────────────────────────
log "Analyse PingCastle-style et scoring"

python3 << 'ADPY'
import json, os, re, glob
from datetime import datetime
from collections import Counter

out       = os.environ['OUTPUT_DIR'] + '/ad'
dc_ip     = os.environ.get('DC_IP', '')
domain    = os.environ.get('DOMAIN_NAME', '')
fqdn      = os.environ.get('DOMAIN_FQDN', '')
netbios   = os.environ.get('NETBIOS', '')
base_dn   = os.environ.get('BASE_DN', '')
dc_os_env = os.environ.get('DC_OS', '')
ldap_anon = os.environ.get('LDAP_ANON', 'false') == 'true'
rpc_null  = os.environ.get('RPC_NULL', 'false') == 'true'
zone_xfer = os.environ.get('ZONE_TRANSFER', 'false') == 'true'
ldap_cb   = os.environ.get('LDAP_CHANNEL_BINDING', 'unknown')

findings = []

def add_finding(category, title, severity, score_impact, details, impact, recommendation):
    findings.append({
        'category': category, 'title': title, 'severity': severity,
        'score_impact': score_impact, 'details': details,
        'impact': impact, 'recommendation': recommendation,
    })

# ── Config domaine ─────────────────────────────────────────────────
func_level = -1; func_level_name = 'Inconnu'
func_level_map = {0:'2000',1:'2003 interim',2:'2003',3:'2008',4:'2008 R2',5:'2012',6:'2012 R2',7:'2016'}
try:
    c = open(f'{out}/ldap_domain_info.txt').read()
    m = re.search(r'msDS-Behavior-Version:\s*(\d+)', c)
    if m:
        func_level = int(m.group(1))
        func_level_name = func_level_map.get(func_level, f'Unknown ({func_level})')
except: pass
if func_level >= 0 and func_level < 5:
    add_finding('Configuration', f'Niveau fonctionnel bas: {func_level_name}', 'HIGH', 10,
                f'Domaine au niveau {func_level_name}',
                'Pas de protections modernes (AES Kerberos, gMSA)', 'Élever à 2012 R2+')
elif func_level >= 5:
    add_finding('Configuration', f'Niveau fonctionnel: {func_level_name}', 'INFO', 0,
                f'Niveau {func_level_name}', '', '')

dc_count = 0; dc_list = []
try:
    c = open(f'{out}/ldap_dcs.txt').read()
    for block in c.split('dn: '):
        if not block.strip(): continue
        dc_info = {}
        for line in block.split('\n'):
            if ':' in line:
                k, v = line.split(':', 1); dc_info[k.strip()] = v.strip()
        if dc_info.get('cn'):
            dc_count += 1
            dc_list.append({'name': dc_info.get('cn',''), 'dns': dc_info.get('dNSHostName',''),
                            'os': dc_info.get('operatingSystem',''), 'os_version': dc_info.get('operatingSystemVersion','')})
except: pass
if dc_count == 1:
    add_finding('Configuration', 'Un seul DC', 'HIGH', 8, f'{dc_count} DC',
                'Aucune redondance AD', 'Déployer 2 DCs minimum')
for dc in dc_list:
    if any(old in dc.get('os','').lower() for old in ['2008','2003','2000','vista','xp']):
        add_finding('Configuration', f'DC OS obsolète: {dc["name"]}', 'CRITICAL', 15,
                    f'{dc["name"]}: {dc.get("os","")}', 'OS non supporté', 'Migrer vers 2019+')

if dc_os_env and any(old in dc_os_env.lower() for old in ['2008','2003','2000']):
    add_finding('Configuration', 'Version Windows Server DC obsolète', 'CRITICAL', 15,
                f'OS: {dc_os_env}', 'Plus supporté par Microsoft', 'Migrer vers 2019+')

# ── Comptes ────────────────────────────────────────────────────────
users = []; now = datetime.now()
try:
    c = open(f'{out}/ldap_users.txt').read()
    current_user = {}
    for line in c.split('\n'):
        line = line.strip()
        if line.startswith('dn: '):
            if current_user.get('sAMAccountName'): users.append(current_user)
            current_user = {'memberOf': [], 'servicePrincipalName': []}
        elif ':' in line:
            k, v = line.split(':', 1); k = k.strip(); v = v.strip()
            if k in ('memberOf', 'servicePrincipalName'):
                current_user.setdefault(k, []).append(v)
            else:
                current_user[k] = v
    if current_user.get('sAMAccountName'): users.append(current_user)
except: pass

pwd_never_expires = []; pwd_not_required = []; no_preauth = []
unconstrained_deleg = []; constrained_deleg = []; inactive_90d = []; admin_users = []
admin_pwd_old = []  # admins avec pwdLastSet > 365 jours

for u in users:
    try: uac = int(u.get('userAccountControl', 0))
    except: uac = 0
    name = u.get('sAMAccountName', '')
    if uac & 0x10000:  pwd_never_expires.append(name)
    if uac & 0x20:     pwd_not_required.append(name)
    if uac & 0x400000: no_preauth.append(name)
    if uac & 0x80000:  unconstrained_deleg.append(name)
    if uac & 0x1000000: constrained_deleg.append(name)
    try:
        llt = u.get('lastLogonTimestamp', '')
        if llt:
            ts = (int(llt) - 116444736000000000) / 10000000
            last_logon = datetime.fromtimestamp(ts)
            if (now - last_logon).days > 90:
                inactive_90d.append(name)
    except: pass
    for grp in u.get('memberOf', []):
        if any(g in grp.lower() for g in ['domain admins','administrateurs du domaine',
                                           'enterprise admins','schema admins',
                                           'account operators','server operators']):
            admin_users.append(name); break

admin_users = list(set(admin_users)); da_count = len(admin_users)

# Vérifier pwdLastSet pour les comptes admin (flag > 365 jours)
for u in users:
    name = u.get('sAMAccountName', '')
    if name not in admin_users: continue
    try:
        pwd_set = u.get('pwdLastSet', '')
        if pwd_set and pwd_set != '0':
            ts = (int(pwd_set) - 116444736000000000) / 10000000
            pwd_date = datetime.fromtimestamp(ts)
            days_old = (now - pwd_date).days
            if days_old > 365:
                admin_pwd_old.append({'name': name, 'days': days_old})
    except: pass

# Admins inactifs (intersection admin_users ∩ inactive_90d)
admin_set = set(admin_users)
inactive_admins = [u for u in inactive_90d if u in admin_set]

if da_count > 5:
    add_finding('Comptes', f'Trop d\'admins: {da_count}', 'HIGH', 10,
                f'{da_count} admins: {", ".join(admin_users[:10])}',
                'Surface d\'attaque élargie', 'Réduire à 2-3 max')
elif da_count > 0:
    add_finding('Comptes', f'{da_count} admins', 'INFO', 0,
                f'Admins: {", ".join(admin_users)}', '', '')

if inactive_admins:
    add_finding('Comptes', f'{len(inactive_admins)} admin(s) inactif(s) > 90j', 'HIGH', 12,
                f'Comptes: {", ".join(inactive_admins[:10])}',
                'Comptes admin actifs mais inactifs — risque de compromission silencieuse',
                'Désactiver les comptes admin inactifs (tiered model ou PAM)')

if inactive_90d:
    pct = int(len(inactive_90d) / max(len(users), 1) * 100)
    sev = 'HIGH' if len(inactive_90d) > 20 or pct > 30 else 'MEDIUM'
    add_finding('Comptes', f'{len(inactive_90d)} inactifs > 90j ({pct}%)', sev,
                8 if sev == 'HIGH' else 4, f'{len(inactive_90d)} comptes',
                'Cibles faciles pour attaquants', 'Désactiver/supprimer')

if pwd_never_expires:
    sev = 'HIGH' if len(pwd_never_expires) > 10 else 'MEDIUM'
    add_finding('Comptes', f'{len(pwd_never_expires)} MDP sans expiration', sev,
                8 if sev == 'HIGH' else 4,
                f'Comptes: {", ".join(pwd_never_expires[:15])}',
                'Risque brute-force', 'Activer expiration ou MFA')

if pwd_not_required:
    add_finding('Comptes', f'{len(pwd_not_required)} MDP non requis', 'CRITICAL', 15,
                f'Comptes: {", ".join(pwd_not_required[:10])}',
                'Accès trivial possible', 'Supprimer flag PASSWD_NOTREQD')

if admin_pwd_old:
    names_str = ', '.join(f"{a['name']} ({a['days']}j)" for a in admin_pwd_old[:8])
    add_finding('Comptes', f'{len(admin_pwd_old)} admin(s) MDP > 365j', 'HIGH', 10,
                f'Comptes: {names_str}',
                'Mots de passe admin anciens — risque craquage / réutilisation',
                'Forcer changement MDP + activer LAPS ou PAM')

spn_users = [u.get('sAMAccountName','') for u in users
             if u.get('servicePrincipalName') and not u.get('sAMAccountName','').endswith('$')]
if spn_users:
    sev = 'HIGH' if len(spn_users) > 3 else 'MEDIUM'
    add_finding('Comptes', f'{len(spn_users)} Kerberoastables (SPN)', sev,
                10 if sev == 'HIGH' else 5,
                f'Comptes: {", ".join(spn_users[:10])}',
                'Hash crackable offline', 'Migrer vers gMSA')

# ── Protected Users ───────────────────────────────────────────────
protected_users = []
try:
    pu_content = open(f'{out}/ldap_protected_users.txt').read()
    for line in pu_content.split('\n'):
        if line.strip().startswith('member:'):
            m = re.search(r'CN=([^,]+)', line)
            if m: protected_users.append(m.group(1))
except: pass

if admin_users:
    if len(protected_users) == 0:
        add_finding('Comptes', 'Groupe "Protected Users" vide ou absent', 'MEDIUM', 4,
                    f'{da_count} admin(s) non protégés',
                    'Comptes admin vulnérables NTLM/délégation/Kerberos degradation',
                    'Ajouter tous les comptes admin dans "Protected Users" (KB2871997)')
    else:
        unprotected_admins = [a for a in admin_users if a not in protected_users]
        if unprotected_admins:
            add_finding('Comptes', f'{len(unprotected_admins)} admin(s) hors Protected Users', 'MEDIUM', 4,
                        f'Non protégés: {", ".join(unprotected_admins[:10])}',
                        'Protection Kerberos/NTLM/délégation non appliquée',
                        'Ajouter dans "Protected Users" (KB2871997)')

# ── Kerberos ──────────────────────────────────────────────────────
if no_preauth:
    add_finding('Kerberos', f'{len(no_preauth)} sans pré-auth', 'HIGH', 10,
                f'AS-REP Roastable: {", ".join(no_preauth[:10])}',
                'Brute-force offline possible', 'Activer pré-auth')
asrep_count = 0
try:
    f = f'{out}/asrep_hashes.txt'
    if os.path.exists(f) and os.path.getsize(f) > 0:
        asrep_count = sum(1 for l in open(f) if l.strip() and '$krb5asrep$' in l)
except: pass
if asrep_count:
    add_finding('Kerberos', f'{asrep_count} hash(es) AS-REP', 'CRITICAL', 15,
                f'{asrep_count} hashes récupérés', 'Compromission possible',
                'Changer MDP + activer pré-auth + MFA')
kerberoast_count = 0
try:
    f = f'{out}/kerberoast_hashes.txt'
    if os.path.exists(f) and os.path.getsize(f) > 0:
        kerberoast_count = sum(1 for l in open(f) if l.strip())
except: pass
if kerberoast_count:
    add_finding('Kerberos', f'{kerberoast_count} hash(es) Kerberoast', 'CRITICAL', 15,
                f'{kerberoast_count} tickets crackables', 'Mots de passe de service exposés',
                'gMSA + MDP 25+ chars')
if func_level >= 0 and func_level < 4:
    add_finding('Kerberos', 'RC4 probable (ancien level)', 'MEDIUM', 5,
                f'Level {func_level_name}', 'RC4 faible', 'Forcer AES')

# ── Délégations ───────────────────────────────────────────────────
if unconstrained_deleg:
    add_finding('Délégation', f'{len(unconstrained_deleg)} délég. non contraintes', 'CRITICAL', 15,
                f'Comptes: {", ".join(unconstrained_deleg[:10])}',
                'Contrôle total domaine possible', 'Migrer vers constrained delegation')
if constrained_deleg:
    add_finding('Délégation', f'{len(constrained_deleg)} délég. contraintes + protocol transition', 'MEDIUM', 5,
                f'Comptes: {", ".join(constrained_deleg[:10])}',
                'Impersonification ciblée', 'Vérifier services cibles')
try:
    c = open(f'{out}/delegations.txt').read()
    if 'Unconstrained' in c and 'AccountName' in c:
        lines = [l for l in c.split('\n') if l.strip() and 'Unconstrained' in l]
        if lines:
            add_finding('Délégation', 'Délég. non contraintes confirmées (impacket)', 'CRITICAL', 12,
                        f'{len(lines)} entrées', 'Confirmé par impacket', 'Supprimer')
except: pass

# ── GPOs, trusts ──────────────────────────────────────────────────
gpo_count = 0
try: gpo_count = open(f'{out}/ldap_gpos.txt').read().count('displayName:')
except: pass
if gpo_count:
    add_finding('Objets', f'{gpo_count} GPOs', 'INFO', 0, f'{gpo_count} GPOs', '', '')
try:
    trust_count = open(f'{out}/ldap_trusts.txt').read().count('cn:')
    if trust_count:
        add_finding('Objets', f'{trust_count} trust(s)', 'MEDIUM', 3,
                    f'{trust_count} trusts AD', 'Surface d\'attaque élargie',
                    'Auditer et supprimer si inutiles')
except: pass

# ── Vulnérabilités critiques ──────────────────────────────────────
smb_signing_ok = True; smbv1_dc = False
try:
    c = open(f'{out}/dc_smb.nmap').read()
    if 'SMBv1' in c:
        smbv1_dc = True
        add_finding('Vulnérabilités', 'SMBv1 sur DC', 'CRITICAL', 15, f'SMBv1 sur {dc_ip}',
                    'EternalBlue/WannaCry', 'Désactiver SMBv1')
    if 'not required' in c.lower() or 'disabled' in c.lower():
        smb_signing_ok = False
        add_finding('Vulnérabilités', 'SMB signing non requis sur DC', 'CRITICAL', 15,
                    f'SMB signing absent sur {dc_ip}', 'NTLM relay → compromission domaine',
                    'GPO: Digitally sign = Enabled')
except: pass
try:
    if 'VULNERABLE' in open(f'{out}/zerologon.txt').read().upper():
        add_finding('Vulnérabilités', 'ZEROLOGON (CVE-2020-1472)', 'CRITICAL', 20,
                    f'DC {dc_ip} vulnérable', 'Contrôle total domaine en secondes',
                    'Patch KB4571702 + enforcement')
except: pass
try:
    c = open(f'{out}/dc_vulns.nmap').read()
    if 'VULNERABLE' in c and 'ms17-010' in c.lower():
        add_finding('Vulnérabilités', 'EternalBlue (MS17-010) sur DC', 'CRITICAL', 20,
                    f'DC {dc_ip} vulnérable', 'RCE sans auth', 'Patch MS17-010')
except: pass
try:
    c = open(f'{out}/ldap_signing.txt').read()
    if 'RequireLDAPSigning' not in c or 'RequireLDAPSigning=1' not in c:
        add_finding('Vulnérabilités', 'LDAP signing non requis', 'HIGH', 8,
                    'LDAP signing absent', 'MITM sur LDAP',
                    'Configurer LDAP signing = Require')
    # Channel binding via msDS-Other-Settings
    if 'LdapEnforceChannelBinding=0' in c or \
       ('msDS-Other-Settings' in c and 'LdapEnforceChannelBinding' not in c):
        add_finding('Vulnérabilités', 'LDAP channel binding non requis (config)', 'HIGH', 8,
                    'LdapEnforceChannelBinding absent ou 0',
                    'CVE-2017-8563 — LDAP relay via LDAPS sans binding token',
                    'Configurer LdapEnforceChannelBinding=2 (KB4520412)')
except: pass

# Channel binding confirmé par test direct
if ldap_cb == 'not_required':
    add_finding('Vulnérabilités', 'LDAP channel binding non requis (confirmé)', 'HIGH', 8,
                f'Connexion LDAPS acceptée sans CBT sur {dc_ip}',
                'CVE-2017-8563 — NTLM relay via LDAPS',
                'Activer LdapEnforceChannelBinding=2 (KB4520412)')

# ── Exposition ────────────────────────────────────────────────────
if ldap_anon:
    add_finding('Exposition', 'LDAP anonymous bind', 'HIGH', 10,
                f'DC {dc_ip} accepte LDAP anonyme', 'Enum complète sans auth',
                'Désactiver bind anonyme')
if rpc_null:
    add_finding('Exposition', 'RPC null session', 'MEDIUM', 5,
                f'Null session sur {dc_ip}', 'Enum users/groupes sans auth',
                'RestrictAnonymous = 2')
if zone_xfer:
    add_finding('Exposition', 'Zone transfer DNS', 'HIGH', 8,
                f'DC {dc_ip} autorise AXFR', 'Cartographie réseau complète',
                'Restreindre AXFR')
try:
    c = open(f'{out}/dc_fingerprint.nmap').read()
    ldaps_absent = '636' not in c or (
        '636' in c and 'closed' in c.split('636')[0].split('\n')[-1])
    if ldaps_absent:
        add_finding('Exposition', 'LDAPS absent', 'MEDIUM', 5, 'Port 636 fermé',
                    'LDAP en clair', 'Configurer LDAPS')
except: pass

# ── Password policy ───────────────────────────────────────────────
pw_info = {}
try:
    c = open(f'{out}/ldap_pwpolicy.txt').read()
    for key in ['minPwdLength', 'lockoutThreshold', 'pwdHistoryLength']:
        m = re.search(rf'{key}:\s*(\d+)', c)
        if m: pw_info[key] = int(m.group(1))
    m = re.search(r'pwdProperties:\s*(\d+)', c)
    if m: pw_info['complexity'] = bool(int(m.group(1)) & 1)
except: pass
if pw_info.get('minPwdLength', 0) < 8:
    add_finding('Comptes', f'MDP min trop court: {pw_info.get("minPwdLength","?")}', 'CRITICAL', 12,
                f'Min: {pw_info.get("minPwdLength","?")}', 'Mots de passe crackables', 'Augmenter à 12+')
elif pw_info.get('minPwdLength', 0) < 12:
    add_finding('Comptes', f'MDP min: {pw_info.get("minPwdLength","?")} (reco: 12+)', 'MEDIUM', 4,
                f'Min actuel: {pw_info.get("minPwdLength","")}', 'Recommandation ANSSI: 12+', 'Augmenter à 12+')
if pw_info.get('lockoutThreshold', 1) == 0:
    add_finding('Comptes', 'Pas de verrouillage', 'HIGH', 10, 'lockoutThreshold = 0',
                'Brute-force illimité', 'Configurer 5-10')
if pw_info.get('pwdHistoryLength', 1) < 12:
    add_finding('Comptes', f'Historique MDP faible: {pw_info.get("pwdHistoryLength","?")}', 'LOW', 2,
                f'Historique: {pw_info.get("pwdHistoryLength","?")}',
                'Réutilisation anciens MDP', 'Configurer 12+')

# ── BloodHound ────────────────────────────────────────────────────
bh_files = glob.glob(f'{out}/bloodhound/*.zip')
if bh_files:
    add_finding('Objets', 'BloodHound collecté', 'INFO', 0,
                f'{len(bh_files)} archive(s)',
                'Données pour analyse de chemins d\'attaque',
                'Analyser avec BloodHound UI (neo4j)')

# ── Scoring ───────────────────────────────────────────────────────
raw_score = sum(f['score_impact'] for f in findings)
ad_score  = min(100, raw_score)
if   ad_score <= 30: risk_level = 'Faible'
elif ad_score <= 60: risk_level = 'Moyen'
elif ad_score <= 80: risk_level = 'Élevé'
else:                risk_level = 'Critique'

issues = [
    {'target': dc_ip, 'severity': f['severity'], 'issue': f['title'],
     'recommendation': f['recommendation'], 'category': f['category'],
     'impact': f['impact'], 'details': f['details'], 'module': 'ad'}
    for f in findings if f['severity'] in ('CRITICAL','HIGH','MEDIUM','LOW')
]
counts = Counter(i['severity'] for i in issues)

summary = {
    'dc_ip':    dc_ip,
    'domain':   domain,
    'fqdn':     fqdn,
    'netbios':  netbios,
    'dc_os':    dc_os_env,
    'base_dn':  base_dn,
    'functional_level': func_level_name,
    'ad_score':   ad_score,
    'risk_level': risk_level,
    'findings':   findings,
    'stats': {
        'total_users':             len(users),
        'domain_admins':           da_count,
        'admin_accounts':          admin_users,
        'inactive_90d':            len(inactive_90d),
        'inactive_admins':         inactive_admins,
        'admin_pwd_old':           len(admin_pwd_old),
        'protected_users':         len(protected_users),
        'pwd_never_expires':       len(pwd_never_expires),
        'pwd_not_required':        len(pwd_not_required),
        'no_preauth':              len(no_preauth),
        'spn_users':               len(spn_users),
        'unconstrained_delegation': len(unconstrained_deleg),
        'constrained_delegation':   len(constrained_deleg),
        'dc_count':                dc_count,
        'dc_list':                 dc_list,
        'gpo_count':               gpo_count,
        'bloodhound_collected':    len(bh_files) > 0,
    },
    'security': {
        'ldap_anonymous':     ldap_anon,
        'rpc_null_session':   rpc_null,
        'zone_transfer':      zone_xfer,
        'ldap_channel_binding': ldap_cb,
        'smb_signing_dc':     smb_signing_ok,
        'smbv1_dc':           smbv1_dc,
    },
    'password_policy': pw_info,
    'issues':  issues,
    'counts': {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH':     counts.get('HIGH', 0),
        'MEDIUM':   counts.get('MEDIUM', 0),
        'LOW':      counts.get('LOW', 0),
    },
}
json.dump(summary, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)
print(f"\n{'='*60}\n SCORE AD: {ad_score}/100 — Risque {risk_level}\n{'='*60}")
print(f" C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)}")
for f in findings:
    if f['severity'] != 'INFO':
        sym = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(f['severity'],'⚪')
        print(f"  {sym} [{f['severity']}] {f['title']}")
ADPY

RC=$?
if [[ $RC -ne 0 ]]; then error "Module AD ÉCHOUÉ (Python $RC)"; exit 1; fi
if [[ ! -s "$OUT/summary.json" ]]; then error "ad/summary.json vide"; exit 1; fi
success "Module AD PingCastle-style terminé"
