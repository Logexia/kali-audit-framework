#!/bin/bash
#============================================================================
# 01 - DISCOVERY: Réseau, hôtes, OS, services, topologie
# [NON-REGRESSION] Inchangé depuis v4
#============================================================================
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
            h = by_ip.get(ip, {'ip':ip,'mac':mac,'vendor':vendor,'hostname':hostname,'os':os_guess,'os_accuracy':os_acc,'tcp_ports':[],'udp_ports':[],'services':[]})
            if mac and not h.get('mac'): h['mac']=mac
            if vendor and not h.get('vendor'): h['vendor']=vendor
            if hostname and not h.get('hostname'): h['hostname']=hostname
            if os_guess and not h.get('os'): h['os']=os_guess; h['os_accuracy']=os_acc
            ports_el = hel.find('ports')
            if ports_el:
                for p in ports_el.findall('port'):
                    st = p.find('state')
                    if st is None or st.get('state')!='open': continue
                    svc = p.find('service'); proto = p.get('protocol','tcp')
                    pinfo = {'port':int(p.get('portid',0)),'protocol':proto,'service':svc.get('name','') if svc is not None else '','product':svc.get('product','') if svc is not None else '','version':svc.get('version','') if svc is not None else '','extra':svc.get('extrainfo','') if svc is not None else ''}
                    key = f"{pinfo['port']}/{proto}"; lst = h['tcp_ports'] if proto=='tcp' else h['udp_ports']
                    if not any(f"{x['port']}/{x['protocol']}"==key for x in lst): lst.append(pinfo)
                    svc_str = f"{pinfo['port']}/{proto} {pinfo['product']} {pinfo['version']}".strip()
                    if svc_str not in h['services']: h['services'].append(svc_str)
            by_ip[ip] = h
    except Exception as e: print(f"Parse error {xml_path}: {e}", file=sys.stderr)
    return list(by_ip.values())

hosts = parse_nmap_xml(f'{out}/full_scan.xml')
hosts = parse_nmap_xml(f'{out}/udp_scan.xml', hosts)
hosts.sort(key=lambda x: [int(p) for p in x['ip'].split('.') if p.isdigit()])

def ips_with_port(port, proto='tcp'):
    key = 'tcp_ports' if proto=='tcp' else 'udp_ports'
    return [h['ip'] for h in hosts if any(p['port']==port for p in h.get(key,[]))]

lists = {
    'smb_hosts':ips_with_port(445),'web_hosts':list(set(ips_with_port(80)+ips_with_port(443)+ips_with_port(8080)+ips_with_port(8443))),
    'dc_candidates':list(set(ips_with_port(88)+ips_with_port(389))),'ssh_hosts':ips_with_port(22),'rdp_hosts':ips_with_port(3389),
    'snmp_hosts':ips_with_port(161,'udp'),'dns_hosts':ips_with_port(53),
    'db_hosts':list(set(ips_with_port(3306)+ips_with_port(5432)+ips_with_port(1433)+ips_with_port(27017))),
}
for name, lst in lists.items():
    with open(f'{out}/{name}.txt','w') as f: f.write('\n'.join(lst)+('\n' if lst else ''))

json.dump({**lists,'total_hosts':len(hosts),'hosts':hosts}, open(f'{out}/summary.json','w'), indent=2, ensure_ascii=False)
with open(f'{out}/inventory.csv','w',newline='') as f:
    w = csv.writer(f,delimiter=';'); w.writerow(['IP','Hostname','MAC','Vendor','OS','OS %','Ports TCP','Ports UDP','Services'])
    for h in hosts:
        w.writerow([h['ip'],h.get('hostname',''),h.get('mac',''),h.get('vendor',''),h.get('os',''),h.get('os_accuracy',''),
                     ', '.join(str(p['port']) for p in h.get('tcp_ports',[])),', '.join(str(p['port']) for p in h.get('udp_ports',[])),
                     ' | '.join(h.get('services',[]))])

print(f"\n{'IP':<18} {'Hostname':<22} {'OS':<38} {'TCP Ports'}")
print('─'*110)
for h in hosts:
    tcp = ','.join(str(p['port']) for p in h.get('tcp_ports',[])); os_s = (h.get('os','')[:36]+'..') if len(h.get('os',''))>38 else h.get('os','')
    print(f"{h['ip']:<18} {h.get('hostname',''):<22} {os_s:<38} {tcp}")
PYINV
success "Inventaire: $OUT/inventory.csv"
