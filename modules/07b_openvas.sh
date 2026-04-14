#!/bin/bash
#============================================================================
# 07b - OPENVAS / GREENBONE: Source prioritaire CVE
#
# Méthode unique: python-gvm + UnixSocketConnection
#   ✅ Testé sur Kali Rolling, GVM 22.7, python-gvm 26.x
#   ✅ Socket /run/gvmd/gvmd.sock, user root
#
# Configurable:
#   GVM_USER (default: admin)  GVM_PASS (default: admin)
#   GVM_SOCKET (auto-détecté)  GVM_SCAN_TIMEOUT (default: 7200)
#
# Artefacts:
#   openvas/gvm_report.xml    openvas/gvm_hosts.json
#   openvas/openvas_vulns.csv openvas/gvm_status.txt
#   openvas/summary.json
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/openvas"
LIVE="$OUTPUT_DIR/discovery/live_hosts.txt"

GVM_USER="${GVM_USER:-admin}"
GVM_PASS="${GVM_PASS:-admin}"
GVM_SOCKET="${GVM_SOCKET:-}"
GVM_SCAN_TIMEOUT="${GVM_SCAN_TIMEOUT:-7200}"

# ── Pré-vérifications ─────────────────────────────────────────────────────
DEGRADED="false"; DEGRADED_REASON=""
[[ "${SKIP_OPENVAS:-false}" == "true" ]] && DEGRADED="true" && DEGRADED_REASON="--skip-openvas"
[[ "$DEGRADED" == "false" && ! -s "$LIVE" ]] && DEGRADED="true" && DEGRADED_REASON="Pas de live_hosts.txt"

if [[ "$DEGRADED" == "true" ]]; then
    warning "OpenVAS DÉGRADÉ: $DEGRADED_REASON"
    echo "DÉGRADÉ: $DEGRADED_REASON" > "$OUT/gvm_status.txt"
    cat > "$OUT/summary.json" <<-EOF
	{"mode":"degraded","reason":"$DEGRADED_REASON","timestamp":"$(date -Iseconds)",
	 "total_vulns":0,"total_cves":0,"critical_vulns":0,"hosts_scanned":0,
	 "vulns_by_host":{},"cve_list":[],"critical_cves":[],"issues":[],
	 "message":"Résultats basés sur Nmap vulners uniquement."}
	EOF
    exit 0
fi

log "Connexion GVM via python-gvm + socket..."

python3 << 'GVMPY'
import os, sys, json, time, re, csv
from collections import Counter, defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET

OUT       = os.environ['OUTPUT_DIR'] + '/openvas'
LIVE_FILE = os.environ['OUTPUT_DIR'] + '/discovery/live_hosts.txt'
GVM_USER  = os.environ.get('GVM_USER', 'admin')
GVM_PASS  = os.environ.get('GVM_PASS', 'admin')
GVM_SOCK  = os.environ.get('GVM_SOCKET', '')
TIMEOUT   = int(os.environ.get('GVM_SCAN_TIMEOUT', '7200'))
CLIENT    = os.environ.get('CLIENT_NAME', 'audit')
TS        = os.environ.get('TIMESTAMP', '')

with open(LIVE_FILE) as f:
    hosts = [l.strip() for l in f if l.strip()]
host_list = ','.join(hosts)
target_name = f"audit_{CLIENT.replace(' ','_')}_{TS}"

def degraded(reason):
    print(f"\n✗ DÉGRADÉ: {reason}")
    json.dump({'mode':'degraded','reason':reason,
        'timestamp':time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_vulns':0,'total_cves':0,'critical_vulns':0,'hosts_scanned':0,
        'vulns_by_host':{},'cve_list':[],'critical_cves':[],'issues':[],
        'message':reason}, open(f'{OUT}/summary.json','w'), indent=2)
    sys.exit(0)

# ── Socket ────────────────────────────────────────────────────────────────
def find_socket():
    if GVM_SOCK and Path(GVM_SOCK).exists(): return GVM_SOCK
    import subprocess
    cands = ['/run/gvmd/gvmd.sock','/var/run/gvmd/gvmd.sock',
             '/run/gvm/gvmd.sock','/var/run/gvm/gvmd.sock']
    try:
        r = subprocess.run(['find','/run','/var/run','-name','gvmd.sock','-type','s'],
                          capture_output=True, text=True, timeout=5)
        for p in r.stdout.strip().split('\n'):
            if p and p not in cands: cands.insert(0, p)
    except: pass
    for s in cands:
        if Path(s).exists(): return s
    return None

sock = find_socket()
if not sock: degraded("Socket gvmd.sock introuvable")
print(f"  Socket: {sock}")

try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
except ImportError:
    degraded("python-gvm non installé (pip install python-gvm)")

# ── Connexion fraîche par appel ───────────────────────────────────────────
def gmp_call(func):
    conn = UnixSocketConnection(path=sock, timeout=120)
    with Gmp(connection=conn, transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(GVM_USER, GVM_PASS)
        return func(gmp)

# ── Test connexion ────────────────────────────────────────────────────────
try:
    ver = gmp_call(lambda g: g.get_version().findtext('.//version','?'))
    print(f"  ✓ GVM {ver} connecté")
    with open(f'{OUT}/gvm_status.txt','w') as f:
        f.write(f"OK: python-gvm socket ({sock}), GVM {ver}\n")
except Exception as e:
    degraded(f"Connexion échouée: {e}")

# ── Config + Scanner ──────────────────────────────────────────────────────
def find_config(g):
    for c in g.get_scan_configs().findall('.//config'):
        n = c.findtext('name','')
        if 'full and fast' in n.lower() and 'ultimate' not in n.lower():
            return c.get('id'), n
    first = g.get_scan_configs().find('.//config')
    return (first.get('id'), first.findtext('name','?')) if first is not None else (None,None)

def find_scanner(g):
    for s in g.get_scanners().findall('.//scanner'):
        if 'openvas' in s.findtext('name','').lower():
            return s.get('id'), s.findtext('name','')
    first = g.get_scanners().find('.//scanner')
    return (first.get('id'), first.findtext('name','?')) if first is not None else (None,None)

config_id, config_name = gmp_call(find_config)
scanner_id, scanner_name = gmp_call(find_scanner)
if not config_id: degraded("Aucune config de scan")
if not scanner_id: degraded("Aucun scanner")
print(f"  Config:  {config_name}")
print(f"  Scanner: {scanner_name}")

# ── Créer cible + tâche + lancer ──────────────────────────────────────────
try:
    target_id = gmp_call(lambda g: g.create_target(
        name=target_name, hosts=[host_list],
        port_range='T:1-65535,U:53,137,161,445,500').get('id'))
    print(f"  Cible:   {target_id}")
except Exception as e: degraded(f"Création cible: {e}")

try:
    task_id = gmp_call(lambda g: g.create_task(
        name=target_name, config_id=config_id,
        target_id=target_id, scanner_id=scanner_id).get('id'))
    print(f"  Tâche:   {task_id}")
except Exception as e: degraded(f"Création tâche: {e}")

try:
    gmp_call(lambda g: g.start_task(task_id))
    print(f"\n  Scan lancé — {len(hosts)} hôtes, timeout {TIMEOUT}s\n")
except Exception as e:
    print(f"  ⚠ Erreur lancement: {e}")

# ── Polling avec progression ──────────────────────────────────────────────
elapsed = 0; poll = 30
bar_width = 40

while elapsed < TIMEOUT:
    try:
        def get_st(g):
            t = g.get_task(task_id)
            return t.findtext('.//status',''), t.findtext('.//progress','0')
        status, progress_str = gmp_call(get_st)
        try: pct = max(0, min(100, int(progress_str)))
        except: pct = 0

        filled = int(bar_width * pct / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        minutes = elapsed // 60
        eta_min = round((TIMEOUT - elapsed) / 60) if pct < 100 else 0

        line = f"\r  [{bar}] {pct:>3}%  {status:<12} {minutes}min  (ETA ~{eta_min}min)  "
        sys.stdout.write(line)
        sys.stdout.flush()

        if status in ('Done','Stopped','Container'):
            print()
            break
    except Exception as e:
        sys.stdout.write(f"\r  ⚠ Polling: {str(e)[:50]}")
        sys.stdout.flush()
    time.sleep(poll)
    elapsed += poll

if elapsed >= TIMEOUT:
    print(f"\n  ⚠ Timeout {TIMEOUT}s atteint")
    try: gmp_call(lambda g: g.stop_task(task_id))
    except: pass

# ── Export XML ────────────────────────────────────────────────────────────
print("\n  Export rapport...")
xml_report = None
try:
    def get_report(g):
        t = g.get_task(task_id)
        rids = [r.get('id') for r in t.findall('.//report') if r.get('id')]
        if not rids: return None
        try: return ET.tostring(g.get_report(rids[-1], details=True, ignore_pagination=True), encoding='unicode')
        except TypeError: return ET.tostring(g.get_report(report_id=rids[-1]), encoding='unicode')
    xml_report = gmp_call(get_report)
    if xml_report:
        with open(f'{OUT}/gvm_report.xml','w') as f: f.write(xml_report)
        print(f"  ✓ {len(xml_report):,} bytes")
except Exception as e:
    print(f"  ⚠ Export: {e}")

# ══════════════════════════════════════════════════════════════════════════
# PARSING
# ══════════════════════════════════════════════════════════════════════════
issues = []; cve_list = []; vulns_by_host = defaultdict(list); all_vulns = []
xml_path = f'{OUT}/gvm_report.xml'

if os.path.exists(xml_path) and os.path.getsize(xml_path) > 100:
    try:
        root = ET.parse(xml_path).getroot()
        results = []
        for path in ['.//results/result', './/result']:
            found = root.findall(path)
            if len(found) > len(results): results = found
        for rpt in root.findall('.//report'):
            for path in ['.//results/result', './/result']:
                found = rpt.findall(path)
                if len(found) > len(results): results = found

        for r in results:
            ip = (r.findtext('host','') or '').strip()
            if not ip: continue
            port = (r.findtext('port','') or '').strip()
            name = (r.findtext('name','') or '').strip()
            desc = (r.findtext('description','') or '').strip()
            threat = (r.findtext('threat','') or '').strip()
            try: cvss = float(r.findtext('severity','') or 0)
            except: cvss = 0.0

            sol = ''
            for tag in r.findall('.//tag'):
                if tag.get('name') == 'solution' and tag.text: sol = tag.text.strip(); break
            if not sol: sol = (r.findtext('solution','') or '').strip()

            cves = []
            nvt = r.find('nvt')
            if nvt is not None:
                for ref in nvt.findall('.//ref'):
                    if ref.get('type') == 'cve': cves.append(ref.get('id',''))
                ct = nvt.findtext('cve','')
                if ct and 'NOCVE' not in ct:
                    for c in re.findall(r'CVE-\d{4}-\d+', ct):
                        if c not in cves: cves.append(c)
            for c in re.findall(r'CVE-\d{4}-\d+', desc):
                if c not in cves: cves.append(c)

            if cvss >= 9: sev = 'CRITICAL'
            elif cvss >= 7: sev = 'HIGH'
            elif cvss >= 4: sev = 'MEDIUM'
            elif cvss > 0: sev = 'LOW'
            else: sev = 'INFO'

            if threat.lower() in ('log','debug','false positive') and cvss < 1: continue

            entry = {'host':ip,'port':port,'name':name,'description':desc[:500],
                     'cvss':cvss,'severity':sev,'solution':sol[:500],'cves':cves,'source':'openvas'}
            vulns_by_host[ip].append(entry)
            all_vulns.append(entry)

            if sev in ('CRITICAL','HIGH','MEDIUM'):
                itxt = name
                if cves: itxt += f" ({', '.join(cves[:3])})"
                itxt += f" [CVSS {cvss}]"
                issues.append({'target':f'{ip}:{port}' if port else ip,'severity':sev,
                               'issue':itxt,'recommendation':sol[:200] or f'Corriger: {name}','source':'openvas'})
            for cid in cves:
                cve_list.append({'cve':cid,'cvss':cvss,'host':ip,'port':port,
                    'service':name[:80],'severity':sev,'description':desc[:200],
                    'solution':sol[:200],'source':'openvas'})
        print(f"  {len(results)} résultats, {len(all_vulns)} vulnérabilités")
    except Exception as e:
        print(f"  Erreur parsing: {e}")
        import traceback; traceback.print_exc()

# Dedup
seen = set(); cve_list = [c for c in cve_list if not (f"{c['host']}:{c['cve']}" in seen or seen.add(f"{c['host']}:{c['cve']}"))]
seen_i = set(); issues = [i for i in issues if not (f"{i['target']}-{i['issue'][:60]}" in seen_i or seen_i.add(f"{i['target']}-{i['issue'][:60]}"))]

counts = Counter(i['severity'] for i in issues)
critical_cves = [c for c in cve_list if c['cvss'] >= 8.0]

hosts_detail = {}
for ip, vulns in vulns_by_host.items():
    sc = Counter(v['severity'] for v in vulns)
    hosts_detail[ip] = {'total_vulns':len(vulns),'critical':sc.get('CRITICAL',0),
        'high':sc.get('HIGH',0),'medium':sc.get('MEDIUM',0),'low':sc.get('LOW',0),
        'top_vulns':sorted(vulns, key=lambda x: -x['cvss'])[:5]}

# Summary
mode = 'openvas' if (all_vulns or cve_list) else 'openvas_empty'
summary = {
    'mode':mode,'connection':'python-gvm-socket',
    'timestamp':time.strftime('%Y-%m-%dT%H:%M:%S'),
    'total_vulns':len(all_vulns),'total_cves':len(cve_list),
    'critical_vulns':len(critical_cves),'hosts_scanned':len(vulns_by_host),
    'counts':dict(counts),'vulns_by_host':hosts_detail,
    'cve_list':cve_list,'critical_cves':critical_cves[:20],
    'all_vulns':all_vulns,  # TOUTES les vulns pour le rapport
    'issues':issues,
    'message':f'OpenVAS: {len(all_vulns)} vulnérabilités, {len(cve_list)} CVE sur {len(vulns_by_host)} hôtes'
}
json.dump(summary, open(f'{OUT}/summary.json','w'), indent=2, ensure_ascii=False)
json.dump(dict(vulns_by_host), open(f'{OUT}/gvm_hosts.json','w'), indent=2, ensure_ascii=False, default=list)

with open(f'{OUT}/openvas_vulns.csv','w',newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['Host','Port','Vulnérabilité','CVE','CVSS','Sévérité','Solution'])
    for ip, vulns in sorted(vulns_by_host.items()):
        for v in sorted(vulns, key=lambda x: -x['cvss']):
            w.writerow([ip,v['port'],v['name'][:80],', '.join(v['cves'][:3]) or '-',
                        v['cvss'],v['severity'],v['solution'][:120]])

print(f"\n  Résumé: {len(all_vulns)} vulns, {len(cve_list)} CVE, {len(critical_cves)} critiques")
print(f"  C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)}")
GVMPY

RC=$?
[[ $RC -eq 0 ]] && success "Module OpenVAS terminé" || warning "OpenVAS code $RC"
