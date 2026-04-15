#!/bin/bash
#============================================================================
# 01 - DISCOVERY: Réseau, hôtes, OS, services, topologie
# v4.5.1 — Ajouts: détection protocoles dangereux (Telnet/FTP/RDP/VNC/NFS),
#           score de surface d'attaque, issues enrichies
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/discovery"

log "Ping sweep $NETWORK"
nmap -sn -PE -PP -PA21,22,80,443,445,3389 "$NETWORK" -oA "$OUT/ping_sweep" 2>/dev/null
grep "Nmap scan report" "$OUT/ping_sweep.nmap" | awk '{print $NF}' | tr -d '()' > "$OUT/live_hosts.txt"
success "$(wc -l < "$OUT/live_hosts.txt") hôtes actifs"

log "Scan complet (TCP top 1000 + versions + OS)"
nmap -sS -sV -O -A --top-ports 1000 \
    --script "banner,http-title,http-server-header" \
    -iL "$OUT/live_hosts.txt" \
    -oA "$OUT/full_scan" -oX "$OUT/full_scan.xml" --open 2>/dev/null
success "Scan TCP terminé"

log "Scan UDP (ports clés)"
nmap -sU --top-ports 20 -iL "$OUT/live_hosts.txt" \
    -oA "$OUT/udp_scan" -oX "$OUT/udp_scan.xml" --open 2>/dev/null
success "Scan UDP terminé"

log "Génération inventaire"

python3 << 'PYINV'
import xml.etree.ElementTree as ET
import json, csv, os, sys
from collections import Counter

out = os.environ['OUTPUT_DIR'] + '/discovery'

def parse_nmap_xml(xml_path, existing_hosts=None):
    by_ip = {h['ip']: h for h in (existing_hosts or [])}
    try:
        tree = ET.parse(xml_path)
        for hel in tree.getroot().findall('host'):
            ip = mac = vendor = hostname = os_guess = os_acc = ''
            for a in hel.findall('address'):
                if a.get('addrtype') == 'ipv4': ip = a.get('addr','')
                elif a.get('addrtype') == 'mac': mac = a.get('addr',''); vendor = a.get('vendor','')
            for hn in hel.findall('.//hostname'): hostname = hn.get('name','')
            for om in hel.findall('.//osmatch'): os_guess = om.get('name',''); os_acc = om.get('accuracy','')+'%'; break
            h = by_ip.get(ip, {
                'ip': ip, 'mac': mac, 'vendor': vendor, 'hostname': hostname,
                'os': os_guess, 'os_accuracy': os_acc,
                'tcp_ports': [], 'udp_ports': [], 'services': [],
            })
            if mac     and not h.get('mac'):          h['mac'] = mac
            if vendor  and not h.get('vendor'):       h['vendor'] = vendor
            if hostname and not h.get('hostname'):    h['hostname'] = hostname
            if os_guess and not h.get('os'):          h['os'] = os_guess; h['os_accuracy'] = os_acc
            ports_el = hel.find('ports')
            if ports_el:
                for p in ports_el.findall('port'):
                    st = p.find('state')
                    if st is None or st.get('state') != 'open': continue
                    svc = p.find('service'); proto = p.get('protocol', 'tcp')
                    pinfo = {
                        'port': int(p.get('portid', 0)), 'protocol': proto,
                        'service':  svc.get('name', '')    if svc is not None else '',
                        'product':  svc.get('product', '') if svc is not None else '',
                        'version':  svc.get('version', '') if svc is not None else '',
                        'extra':    svc.get('extrainfo','')if svc is not None else '',
                    }
                    key = f"{pinfo['port']}/{proto}"
                    lst = h['tcp_ports'] if proto == 'tcp' else h['udp_ports']
                    if not any(f"{x['port']}/{x['protocol']}" == key for x in lst):
                        lst.append(pinfo)
                    svc_str = f"{pinfo['port']}/{proto} {pinfo['product']} {pinfo['version']}".strip()
                    if svc_str not in h['services']:
                        h['services'].append(svc_str)
            by_ip[ip] = h
    except Exception as e:
        print(f"Parse error {xml_path}: {e}", file=sys.stderr)
    return list(by_ip.values())

hosts = parse_nmap_xml(f'{out}/full_scan.xml')
hosts = parse_nmap_xml(f'{out}/udp_scan.xml', hosts)
hosts.sort(key=lambda x: [int(p) for p in x['ip'].split('.') if p.isdigit()])

def ips_with_port(port, proto='tcp'):
    key = 'tcp_ports' if proto == 'tcp' else 'udp_ports'
    return [h['ip'] for h in hosts if any(p['port'] == port for p in h.get(key, []))]

lists = {
    'smb_hosts': ips_with_port(445),
    'web_hosts': list(set(
        ips_with_port(80) + ips_with_port(443) + ips_with_port(8080) +
        ips_with_port(8443) + ips_with_port(8000) + ips_with_port(8888)
    )),
    'dc_candidates': list(set(ips_with_port(88) + ips_with_port(389))),
    'ssh_hosts':  ips_with_port(22),
    'rdp_hosts':  ips_with_port(3389),
    'snmp_hosts': ips_with_port(161, 'udp'),
    'dns_hosts':  ips_with_port(53),
    'db_hosts':   list(set(
        ips_with_port(3306) + ips_with_port(5432) +
        ips_with_port(1433) + ips_with_port(27017)
    )),
}
for name, lst in lists.items():
    with open(f'{out}/{name}.txt', 'w') as f:
        f.write('\n'.join(lst) + ('\n' if lst else ''))

# ══════════════════════════════════════════════════════════════════════════
# DÉTECTION PROTOCOLES DANGEREUX — génération d'issues
# ══════════════════════════════════════════════════════════════════════════
DANGEROUS_PORTS = {
    # port: (service_name, severity, description, recommendation)
    21:   ('FTP',     'HIGH',     'FTP (port 21) exposé — transfert en clair',
           'Remplacer FTP par SFTP (SSH) ou FTPS avec TLS obligatoire'),
    23:   ('Telnet',  'CRITICAL', 'Telnet (port 23) exposé — protocole non chiffré',
           'Désactiver Telnet immédiatement, utiliser SSH à la place'),
    69:   ('TFTP',    'HIGH',     'TFTP (port 69/UDP) exposé — pas d\'authentification',
           'Restreindre TFTP aux équipements réseau internes uniquement'),
    111:  ('RPC',     'MEDIUM',   'RPC Portmapper (port 111) exposé — énumération services',
           'Restreindre le portmapper ou désactiver si inutile'),
    512:  ('rexec',   'CRITICAL', 'rexec (port 512) exposé — protocole legacy non chiffré',
           'Désactiver rexec, utiliser SSH'),
    513:  ('rlogin',  'CRITICAL', 'rlogin (port 513) exposé — protocole legacy non chiffré',
           'Désactiver rlogin, utiliser SSH'),
    514:  ('rsh',     'CRITICAL', 'rsh (port 514) exposé — protocole legacy non chiffré',
           'Désactiver rsh, utiliser SSH'),
    873:  ('rsync',   'HIGH',     'rsync (port 873) exposé sans authentification potentielle',
           'Restreindre rsync aux IP autorisées avec authentification'),
    2049: ('NFS',     'HIGH',     'NFS (port 2049) exposé — risque montage non autorisé',
           'Restreindre NFS aux hôtes de confiance, utiliser Kerberos auth'),
    3389: ('RDP',     'MEDIUM',   'RDP (port 3389) exposé — surface d\'attaque brute-force',
           'Restreindre RDP par VPN ou IP whitelist, activer NLA, limiter les tentatives'),
    5800: ('VNC-HTTP','HIGH',     'VNC HTTP (port 5800) exposé',
           'Désactiver VNC ou le restreindre via VPN/tunnel SSH'),
    5900: ('VNC',     'HIGH',     'VNC (port 5900) exposé — souvent sans mot de passe fort',
           'Désactiver VNC ou le restreindre via VPN/tunnel SSH + mot de passe fort'),
    5901: ('VNC-2',   'HIGH',     'VNC session 2 (port 5901) exposé',
           'Désactiver VNC ou le restreindre via VPN'),
    6379: ('Redis',   'CRITICAL', 'Redis (port 6379) exposé sans auth potentielle',
           'Configurer requirepass, bind loopback, désactiver en externe'),
    27017:('MongoDB', 'CRITICAL', 'MongoDB (port 27017) exposé sans auth potentielle',
           'Activer l\'authentification MongoDB, restreindre bindIp au loopback'),
    9200: ('Elasticsearch','CRITICAL','Elasticsearch (port 9200) exposé sans auth potentielle',
           'Activer X-Pack security ou restreindre aux IP internes'),
    1521: ('Oracle',  'HIGH',     'Oracle DB (port 1521) exposé',
           'Restreindre Oracle DB aux serveurs applicatifs via firewall'),
    1433: ('MSSQL',   'HIGH',     'SQL Server (port 1433) exposé',
           'Restreindre MSSQL aux serveurs applicatifs, désactiver SA si inutile'),
    3306: ('MySQL',   'MEDIUM',   'MySQL (port 3306) exposé',
           'Restreindre MySQL aux connexions locales ou aux serveurs applicatifs'),
    5432: ('PostgreSQL','MEDIUM', 'PostgreSQL (port 5432) exposé',
           'Restreindre PostgreSQL via pg_hba.conf aux hôtes autorisés'),
    11211:('Memcached','HIGH',    'Memcached (port 11211) exposé — pas d\'auth par défaut',
           'Restreindre Memcached au loopback, pas d\'exposition Internet'),
    8080: ('HTTP-alt','LOW',      'Port HTTP alternatif (8080) exposé',
           'Vérifier si nécessaire, rediriger vers HTTPS si application web'),
    2375: ('Docker',  'CRITICAL', 'Docker API non sécurisée (port 2375)',
           'Désactiver Docker API TCP non chiffrée immédiatement (risque RCE)'),
    2376: ('Docker-TLS','MEDIUM', 'Docker API TLS (port 2376) exposé',
           'Vérifier les certificats client Docker et restreindre l\'accès'),
}

issues = []
seen_issues = set()
surface_score = 0

# Pondérations pour le score de surface d'attaque
SURFACE_WEIGHTS = {
    'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1,
}

for h in hosts:
    tcp_ports = {p['port']: p for p in h.get('tcp_ports', [])}
    udp_ports = {p['port']: p for p in h.get('udp_ports', [])}
    ip = h['ip']

    for port, (svc, sev, desc, rec) in DANGEROUS_PORTS.items():
        pinfo = tcp_ports.get(port) or udp_ports.get(port)
        if pinfo:
            product = pinfo.get('product', '')
            version = pinfo.get('version', '')
            ver_str = f' ({product} {version})'.strip() if product else ''
            issue_text = f'{desc}{ver_str} sur {ip}'
            k = f"{ip}|{port}|{sev}"
            if k not in seen_issues:
                seen_issues.add(k)
                issues.append({
                    'target': ip, 'severity': sev,
                    'issue':  issue_text, 'recommendation': rec,
                    'module': 'discovery',
                })
                surface_score += SURFACE_WEIGHTS.get(sev, 0)

    # Signaler les anciens OS Windows
    os_str = h.get('os', '').lower()
    if any(old in os_str for old in ('windows xp', 'windows 2003', 'windows vista',
                                      'windows 7', 'windows 2008')):
        k = f"{ip}|old_os"
        if k not in seen_issues:
            seen_issues.add(k)
            issues.append({
                'target': ip, 'severity': 'HIGH',
                'issue':  f"OS obsolète non supporté: {h.get('os', '')} sur {ip}",
                'recommendation': 'Migrer vers Windows Server 2019/2022 ou Windows 10/11',
                'module': 'discovery',
            })
            surface_score += SURFACE_WEIGHTS['HIGH']

counts = Counter(i['severity'] for i in issues)

# Score de surface normalisé (0-100)
attack_surface_pct = min(100, surface_score)

json.dump({
    **lists,
    'total_hosts': len(hosts),
    'hosts': hosts,
    'issues': issues,
    'counts': {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH':     counts.get('HIGH', 0),
        'MEDIUM':   counts.get('MEDIUM', 0),
        'LOW':      counts.get('LOW', 0),
    },
    'attack_surface_score': attack_surface_pct,
    'attack_surface_raw':   surface_score,
}, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)

with open(f'{out}/inventory.csv', 'w', newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['IP','Hostname','MAC','Vendor','OS','OS %','Ports TCP','Ports UDP','Services'])
    for h in hosts:
        w.writerow([
            h['ip'], h.get('hostname',''), h.get('mac',''), h.get('vendor',''),
            h.get('os',''), h.get('os_accuracy',''),
            ', '.join(str(p['port']) for p in h.get('tcp_ports',[])),
            ', '.join(str(p['port']) for p in h.get('udp_ports',[])),
            ' | '.join(h.get('services',[])),
        ])

print(f"\n{'IP':<18} {'Hostname':<22} {'OS':<38} {'TCP Ports'}")
print('─' * 110)
for h in hosts:
    tcp = ','.join(str(p['port']) for p in h.get('tcp_ports', []))
    os_s = (h.get('os','')[:36]+'..') if len(h.get('os','')) > 38 else h.get('os','')
    print(f"{h['ip']:<18} {h.get('hostname',''):<22} {os_s:<38} {tcp}")

if issues:
    print(f"\n⚠  {len(issues)} protocoles dangereux (score surface: {attack_surface_pct}/100)")
    for i in [x for x in issues if x['severity'] == 'CRITICAL']:
        print(f"  🔴 [CRITICAL] {i['issue']}")
    for i in [x for x in issues if x['severity'] == 'HIGH']:
        print(f"  🟠 [HIGH] {i['issue']}")
else:
    print("\n✓ Aucun protocole dangereux détecté")
PYINV

success "Inventaire: $OUT/inventory.csv"
