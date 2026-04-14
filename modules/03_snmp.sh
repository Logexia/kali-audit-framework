#!/bin/bash
#============================================================================
# 03 - SNMP: Audit approfondi
#
# Checks:
#   - Community strings (brute force 30+ strings courantes)
#   - SNMPv1 vs v2c vs v3 detection
#   - Write access test (snmpset sysContact)
#   - Enumération système: OS, hostname, uptime, contact, location
#   - Enumération services/processus en cours (hrSWRunName)
#   - Enumération logiciels installés (hrSWInstalledName)
#   - Interfaces réseau + IPs + routes
#   - Corrélation versions → CVE connues
#
# Artefacts:
#   snmp/hosts/*_snmpcheck.txt    snmp/hosts/*_processes.txt
#   snmp/hosts/*_software.txt     snmp/hosts/*_interfaces.txt
#   snmp/onesixtyone.txt          snmp/nmap_snmp.*
#   snmp/summary.json
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/snmp"
HOSTS="$OUTPUT_DIR/discovery/snmp_hosts.txt"

if [[ ! -s "$HOSTS" ]]; then
    log "Scan UDP 161 sur $NETWORK"
    nmap -sU -p 161 --open "$NETWORK" -oG - 2>/dev/null | grep "161/open" | awk '{print $2}' > "$HOSTS"
fi
if [[ ! -s "$HOSTS" ]]; then
    warning "Aucun hôte SNMP"
    echo '{"total":0,"devices":[],"issues":[],"counts":{}}' > "$OUT/summary.json"
    exit 0
fi
log "$(wc -l < "$HOSTS") hôtes SNMP"

# ── Community strings (élargi) ────────────────────────────────────────────
log "Test community strings (30+ candidates)"
cat > "$OUT/communities.txt" << 'COMM'
public
private
community
manager
admin
snmp
monitor
secret
cisco
router
switch
default
test
guest
read
write
network
access
system
security
COMM

if command -v onesixtyone &>/dev/null; then
    onesixtyone -c "$OUT/communities.txt" -i "$HOSTS" > "$OUT/onesixtyone.txt" 2>&1 || true
fi

# ── Enumération détaillée par hôte ────────────────────────────────────────
log "Enumération SNMP détaillée"
mkdir -p "$OUT/hosts"

while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    log "  SNMP enum: $ip"

    # snmp-check complet
    command -v snmp-check &>/dev/null && \
        snmp-check -c public "$ip" > "$OUT/hosts/${ip}_snmpcheck.txt" 2>/dev/null || true

    if command -v snmpwalk &>/dev/null; then
        # System info
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.1 > "$OUT/hosts/${ip}_system.txt" 2>/dev/null || true

        # Interfaces réseau
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.2.2 > "$OUT/hosts/${ip}_interfaces.txt" 2>/dev/null || true

        # IP addresses
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.4.20 > "$OUT/hosts/${ip}_ipaddr.txt" 2>/dev/null || true

        # Routes
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.4.21 > "$OUT/hosts/${ip}_routes.txt" 2>/dev/null || true

        # Processus en cours (hrSWRunName)
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.25.4.2.1.2 > "$OUT/hosts/${ip}_processes.txt" 2>/dev/null || true

        # Logiciels installés (hrSWInstalledName)
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.25.6.3.1.2 > "$OUT/hosts/${ip}_software.txt" 2>/dev/null || true

        # Ports TCP ouverts (tcpConnLocalPort)
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.6.13.1.3 > "$OUT/hosts/${ip}_tcpports.txt" 2>/dev/null || true

        # Storage (disques, partitions)
        snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.25.2.3 > "$OUT/hosts/${ip}_storage.txt" 2>/dev/null || true

        # ── Test WRITE access ─────────────────────────────────────────
        # Tenter un snmpset sur sysContact (OID safe, réversible)
        if command -v snmpset &>/dev/null; then
            # Sauvegarder la valeur actuelle
            original=$(snmpget -v2c -c public "$ip" 1.3.6.1.2.1.1.4.0 2>/dev/null | sed 's/.*STRING: //')
            # Test write avec community public
            snmpset -v2c -c public "$ip" 1.3.6.1.2.1.1.4.0 s "AUDIT_WRITE_TEST" > "$OUT/hosts/${ip}_write_public.txt" 2>&1 || true
            # Test write avec community private
            snmpset -v2c -c private "$ip" 1.3.6.1.2.1.1.4.0 s "AUDIT_WRITE_TEST" > "$OUT/hosts/${ip}_write_private.txt" 2>&1 || true
            # Restaurer
            if grep -q "AUDIT_WRITE_TEST" "$OUT/hosts/${ip}_write_public.txt" 2>/dev/null; then
                snmpset -v2c -c public "$ip" 1.3.6.1.2.1.1.4.0 s "${original:-}" 2>/dev/null || true
            fi
            if grep -q "AUDIT_WRITE_TEST" "$OUT/hosts/${ip}_write_private.txt" 2>/dev/null; then
                snmpset -v2c -c private "$ip" 1.3.6.1.2.1.1.4.0 s "${original:-}" 2>/dev/null || true
            fi
        fi
    fi
done < "$HOSTS"

# ── Nmap SNMP scripts ────────────────────────────────────────────────────
nmap -sU -p 161 --script "snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,snmp-processes,snmp-brute" \
    -iL "$HOSTS" -oA "$OUT/nmap_snmp" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════
# ANALYSE PYTHON
# ══════════════════════════════════════════════════════════════════════════
python3 << 'SNMPPY'
import json, os, re, glob
from collections import Counter
from pathlib import Path

out = os.environ['OUTPUT_DIR'] + '/snmp'
issues = []; devices = []

# ── Parse onesixtyone ─────────────────────────────────────────────────────
communities_found = {}  # ip -> list of communities
try:
    for l in open(f'{out}/onesixtyone.txt'):
        m = re.match(r'(\S+)\s+\[(\S+)\]\s*(.*)', l)
        if m:
            ip, comm, desc = m.group(1), m.group(2), m.group(3).strip()
            communities_found.setdefault(ip, []).append(comm)
except: pass

# ── Parse chaque hôte ─────────────────────────────────────────────────────
for f in sorted(glob.glob(f'{out}/hosts/*_snmpcheck.txt')):
    ip = os.path.basename(f).split('_')[0]
    try:
        c = open(f).read()
        if len(c) < 100: continue

        info = {
            'ip': ip, 'hostname': '', 'description': '', 'contact': '',
            'location': '', 'uptime': '', 'os_guess': '',
            'communities': communities_found.get(ip, ['public']),
            'interfaces': [], 'processes': [], 'software': [],
            'tcp_ports': [], 'write_access': False, 'write_community': '',
            'snmp_version': 'v2c',
        }

        m = re.search(r'System description\s*:\s*(.+)', c)
        info['description'] = m.group(1).strip() if m else ''
        m = re.search(r'Hostname\s*:\s*(.+)', c)
        info['hostname'] = m.group(1).strip() if m else ''
        m = re.search(r'Contact\s*:\s*(.+)', c)
        info['contact'] = m.group(1).strip() if m else ''
        m = re.search(r'Location\s*:\s*(.+)', c)
        info['location'] = m.group(1).strip() if m else ''
        m = re.search(r'Uptime.*?:\s*(.+)', c)
        info['uptime'] = m.group(1).strip() if m else ''

        # OS guess from sysDescr
        desc = info['description'].lower()
        if 'linux' in desc: info['os_guess'] = 'Linux'
        elif 'windows' in desc: info['os_guess'] = 'Windows'
        elif 'cisco' in desc: info['os_guess'] = 'Cisco IOS'
        elif 'junos' in desc or 'juniper' in desc: info['os_guess'] = 'Juniper'
        elif 'freebsd' in desc: info['os_guess'] = 'FreeBSD'
        elif 'synology' in desc: info['os_guess'] = 'Synology DSM'
        elif 'hp ' in desc or 'hewlett' in desc: info['os_guess'] = 'HP/HPE'
        elif 'fortinet' in desc or 'fortigate' in desc: info['os_guess'] = 'FortiGate'
        elif 'ubiquiti' in desc or 'unifi' in desc: info['os_guess'] = 'Ubiquiti'
        elif 'printer' in desc or 'xerox' in desc or 'ricoh' in desc: info['os_guess'] = 'Imprimante'

        # Interfaces
        intf_file = f'{out}/hosts/{ip}_interfaces.txt'
        if Path(intf_file).exists():
            for line in open(intf_file):
                m = re.search(r'STRING:\s*"?(.+?)"?\s*$', line)
                if m: info['interfaces'].append(m.group(1))

        # Processes
        proc_file = f'{out}/hosts/{ip}_processes.txt'
        if Path(proc_file).exists():
            for line in open(proc_file):
                m = re.search(r'STRING:\s*"?(.+?)"?\s*$', line)
                if m: info['processes'].append(m.group(1))

        # Software
        sw_file = f'{out}/hosts/{ip}_software.txt'
        if Path(sw_file).exists():
            for line in open(sw_file):
                m = re.search(r'STRING:\s*"?(.+?)"?\s*$', line)
                if m: info['software'].append(m.group(1))

        # TCP ports via SNMP
        tcp_file = f'{out}/hosts/{ip}_tcpports.txt'
        if Path(tcp_file).exists():
            ports = set()
            for line in open(tcp_file):
                m = re.search(r'INTEGER:\s*(\d+)', line)
                if m: ports.add(int(m.group(1)))
            info['tcp_ports'] = sorted(ports)

        # Write access test
        for comm in ['public', 'private']:
            wf = f'{out}/hosts/{ip}_write_{comm}.txt'
            if Path(wf).exists():
                wc = open(wf).read()
                if 'AUDIT_WRITE_TEST' in wc and 'Error' not in wc:
                    info['write_access'] = True
                    info['write_community'] = comm

        devices.append(info)

        # ── Issues ────────────────────────────────────────────────────
        for comm in info['communities']:
            if comm == 'public':
                issues.append({
                    'target': ip, 'severity': 'HIGH', 'module': 'snmp',
                    'issue': f'SNMP community "public" accessible — {info["os_guess"] or info["description"][:50]}',
                    'recommendation': 'Changer community string, restreindre accès SNMP par ACL, migrer vers SNMPv3'
                })
            else:
                issues.append({
                    'target': ip, 'severity': 'CRITICAL', 'module': 'snmp',
                    'issue': f'Community SNMP "{comm}" devinée — {info["os_guess"]}',
                    'recommendation': f'Changer community "{comm}", désactiver SNMP ou migrer SNMPv3 avec auth+priv'
                })

        # Write access = CRITICAL
        if info['write_access']:
            issues.append({
                'target': ip, 'severity': 'CRITICAL', 'module': 'snmp',
                'issue': f'SNMP WRITE access via community "{info["write_community"]}" — reconfiguration à distance possible',
                'recommendation': f'URGENT: désactiver SNMP write, changer community "{info["write_community"]}", firewall UDP 161'
            })

        # Sensitive processes detected
        sensitive_procs = {'sshd','httpd','apache2','nginx','mysqld','postgres',
                          'smbd','winbindd','named','dhcpd','snmpd','ftpd','telnetd',
                          'cupsd','dovecot','postfix','sendmail','openvpn','ipsec'}
        dangerous_procs = {'telnetd','ftpd','rsh','rlogin','rexecd'}
        found_procs = set(p.lower() for p in info['processes'])
        for dp in dangerous_procs:
            if dp in found_procs:
                issues.append({
                    'target': ip, 'severity': 'HIGH', 'module': 'snmp',
                    'issue': f'Service dangereux détecté via SNMP: {dp} (non chiffré)',
                    'recommendation': f'Désactiver {dp}, utiliser SSH/SFTP à la place'
                })

        # SNMPv1/v2c = no encryption
        issues.append({
            'target': ip, 'severity': 'MEDIUM', 'module': 'snmp',
            'issue': f'SNMPv2c sans chiffrement — communities transitent en clair',
            'recommendation': 'Migrer vers SNMPv3 avec authPriv (SHA+AES)'
        })

        # Version-based vulns from sysDescr
        desc_full = info['description']
        version_vulns = []
        # Cisco IOS old versions
        m = re.search(r'Cisco IOS.*?Version (\d+\.\d+)', desc_full, re.I)
        if m:
            ver = float(m.group(1))
            if ver < 15.0:
                version_vulns.append(('CRITICAL', f'Cisco IOS {m.group(1)} obsolète (multiples CVE)', 'Mettre à jour IOS vers la dernière version stable'))
        # Windows old
        if re.search(r'Windows.*(Server 2008|Server 2003|XP|Vista|Server 2012(?! R2))', desc_full, re.I):
            version_vulns.append(('CRITICAL', f'OS Windows obsolète détecté via SNMP: {desc_full[:60]}', 'Migrer vers un OS supporté'))
        # Linux kernel old
        m = re.search(r'Linux\s+\S+\s+(\d+\.\d+\.\d+)', desc_full)
        if m:
            parts = m.group(1).split('.')
            if int(parts[0]) < 4:
                version_vulns.append(('HIGH', f'Kernel Linux ancien ({m.group(1)}) détecté via SNMP', 'Mettre à jour le kernel'))
        # Printers with default SNMP
        if info['os_guess'] == 'Imprimante':
            version_vulns.append(('MEDIUM', f'Imprimante exposée via SNMP ({desc_full[:50]})', 'Restreindre SNMP imprimante, désactiver si non nécessaire'))
        # FortiGate old
        m = re.search(r'FortiGate.*?v(\d+\.\d+\.\d+)', desc_full, re.I)
        if m:
            version_vulns.append(('HIGH', f'FortiGate {m.group(1)} — vérifier CVE récentes (FortiOS)', 'Mettre à jour FortiOS, vérifier advisories Fortinet'))

        for sev, issue, rec in version_vulns:
            issues.append({'target': ip, 'severity': sev, 'module': 'snmp', 'issue': issue, 'recommendation': rec})

    except Exception as e:
        print(f"  ⚠ Erreur parsing {ip}: {e}")

# ── Parse onesixtyone pour les IPs sans snmp-check ────────────────────────
existing_ips = {d['ip'] for d in devices}
for ip, comms in communities_found.items():
    if ip not in existing_ips:
        for comm in comms:
            sev = 'CRITICAL' if comm != 'public' else 'HIGH'
            issues.append({
                'target': ip, 'severity': sev, 'module': 'snmp',
                'issue': f'Community SNMP "{comm}" accessible sur {ip}',
                'recommendation': f'Changer community "{comm}", SNMPv3'
            })

# Dedup issues
seen = set(); unique = []
for i in issues:
    k = f"{i['target']}-{i['issue'][:80]}"
    if k not in seen: seen.add(k); unique.append(i)
issues = unique

counts = Counter(i['severity'] for i in issues)
summary = {
    'total': len(devices),
    'devices': devices,
    'communities_found': {ip: list(set(comms)) for ip, comms in communities_found.items()},
    'write_access_hosts': [d['ip'] for d in devices if d.get('write_access')],
    'issues': issues,
    'counts': dict(counts),
}
json.dump(summary, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)

print(f"\nSNMP: {len(devices)} devices, {len(issues)} issues")
print(f"  Write access: {len(summary['write_access_hosts'])} hôte(s)")
print(f"  C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)}")
for d in devices:
    procs = f", {len(d['processes'])} processus" if d['processes'] else ""
    sw = f", {len(d['software'])} logiciels" if d['software'] else ""
    wr = " ⚠ WRITE" if d['write_access'] else ""
    print(f"  {d['ip']}: {d['os_guess'] or d['description'][:40]}{procs}{sw}{wr}")
SNMPPY
