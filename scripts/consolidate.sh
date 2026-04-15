#!/bin/bash
#============================================================================
# CONSOLIDATION v4.5
#   - Scoring asymptotique + scores modules (AD/Email)
#   - Catégories masquées si module non exécuté
#   - Détection historique client → tendances
#   - Cross-référence exploitabilité dans all_vulns
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
log "Consolidation v4.5"

python3 << 'PYCON'
import json, os, csv, math, glob, re
from collections import Counter
from pathlib import Path

out = os.environ['OUTPUT_DIR']
client = os.environ.get('CLIENT_NAME', '')
slug = client.lower().replace(' ', '_')

# ── Modules exécutés ──────────────────────────────────────────────────────
modules_ran_file = f'{out}/report/modules_ran.txt'
modules_ran = set()
if os.path.exists(modules_ran_file):
    modules_ran = set(open(modules_ran_file).read().strip().split(','))
    modules_ran.discard('')

# ── Load summaries ────────────────────────────────────────────────────────
modules = {}
for mod in ['discovery','smb','snmp','dns','email_security','ad','wifi','cve','ssl','openvas','exploitability','web_owasp']:
    p = f'{out}/{mod}/summary.json'
    if os.path.exists(p):
        try: modules[mod] = json.load(open(p))
        except: modules[mod] = {}

# ── Collect issues ────────────────────────────────────────────────────────
all_issues = []
for mod, data in modules.items():
    for issue in data.get('issues', []):
        issue.setdefault('module', mod)
        all_issues.append(issue)

sev_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
all_issues.sort(key=lambda x: sev_order.get(x.get('severity','LOW'), 9))
total_counts = Counter(i.get('severity','LOW') for i in all_issues)

ad = modules.get('ad', {})
openvas = modules.get('openvas', {})
exploit = modules.get('exploitability', {})
email = modules.get('email_security', {})

# ── Cross-réf exploitabilité ──────────────────────────────────────────────
# Marquer les CVE qui ont un exploit public connu
exploit_cves = set()
for e in exploit.get('exploitable_cves', []):
    if e.get('exploit_public'): exploit_cves.add(e.get('cve',''))
for e in exploit.get('msf_suggestions', []):
    exploit_cves.add(e.get('cve',''))

# Enrichir all_vulns OpenVAS avec flag exploit
all_vulns_enriched = []
for v in openvas.get('all_vulns', []):
    v2 = dict(v)
    v2['has_exploit'] = any(c in exploit_cves for c in v.get('cves', []))
    all_vulns_enriched.append(v2)

# ══════════════════════════════════════════════════════════════════════════
# SCORING — uniquement les catégories dont le module a tourné
# ══════════════════════════════════════════════════════════════════════════
def issue_score(weight, issues_list, bonus_pct=0):
    c = Counter(i.get('severity','LOW') for i in issues_list)
    raw = c.get('CRITICAL',0)*5 + c.get('HIGH',0)*2 + c.get('MEDIUM',0)*0.5 + c.get('LOW',0)*0.1
    raw *= (1 + bonus_pct)
    sub = weight * (1 - math.exp(-0.07 * raw))
    return round(sub, 1), dict(c), raw

def module_score(weight, score_0_100):
    return round(weight * score_0_100 / 100, 1)

# Map module names to ran keys
mod_ran_map = {
    'infrastructure': 'discovery', 'smb': 'smb', 'ad': 'ad', 'email': 'email',
    'vulns': 'cve', 'ssl': 'ssl', 'wifi': 'wifi', 'snmp': 'snmp', 'dns': 'dns'
}

CATEGORIES = {
    'infrastructure': {'weight': 10, 'modules': ['discovery'], 'method': 'issues'},
    'smb':            {'weight': 10, 'modules': ['smb'],       'method': 'issues'},
    'ad':             {'weight': 20, 'modules': ['ad'],        'method': 'module', 'key': ('ad','ad_score')},
    'email':          {'weight': 10, 'modules': ['email_security'], 'method': 'module', 'key': ('email_security','email_score')},
    'vulns':          {'weight': 20, 'modules': ['cve','openvas','exploitability','web_owasp'], 'method': 'issues_exploit'},
    'ssl':            {'weight': 10, 'modules': ['ssl'],       'method': 'issues'},
    'wifi':           {'weight': 10, 'modules': ['wifi'],      'method': 'issues'},
    'snmp':           {'weight':  5, 'modules': ['snmp'],      'method': 'issues'},
    'dns':            {'weight':  5, 'modules': ['dns'],       'method': 'issues'},
}

category_scores = {}
active_weight = 0  # Poids total des catégories actives

for cat, cfg in CATEGORIES.items():
    ran_key = mod_ran_map.get(cat, cat)
    # Catégorie active si module correspondant a tourné
    active = ran_key in modules_ran or any(m in modules for m in cfg['modules'])
    if not active:
        continue  # Ne pas inclure dans le scoring

    w = cfg['weight']
    active_weight += w
    cat_issues = [i for i in all_issues if i.get('module') in cfg['modules']]
    c = Counter(i.get('severity','LOW') for i in cat_issues)

    if cfg['method'] == 'module':
        mod_name, key = cfg['key']
        ms = modules.get(mod_name, {}).get(key, 0) or 0
        sub = module_score(w, ms)
        method = f'{key}={ms}/100'
        if ms == 0 and cat_issues:
            sub, c, _ = issue_score(w, cat_issues)
            method = 'issues (fallback)'
    elif cfg['method'] == 'issues_exploit':
        n_exploit = exploit.get('total_exploitable', 0)
        bonus = min(0.5, n_exploit * 0.05) if n_exploit > 0 else 0
        sub, c, _ = issue_score(w, cat_issues, bonus)
        method = f'issues + exploit +{bonus:.0%}' if bonus else 'issues'
    else:
        sub, c, _ = issue_score(w, cat_issues)
        method = 'issues'

    category_scores[cat] = {
        'weight': w, 'score': sub,
        'pct': round(sub / w * 100) if w > 0 else 0,
        'issues': len(cat_issues), 'counts': dict(c), 'method': method,
    }

# Score normalisé si toutes les catégories n'ont pas tourné
raw_score = sum(cs['score'] for cs in category_scores.values())
if active_weight > 0 and active_weight < 100:
    score = round(raw_score * 100 / active_weight)
else:
    score = round(raw_score)
score = min(100, max(0, score))

if score >= 75:   level = 'CRITIQUE'
elif score >= 50: level = 'ÉLEVÉ'
elif score >= 25: level = 'MODÉRÉ'
else:             level = 'FAIBLE'

# ══════════════════════════════════════════════════════════════════════════
# HISTORIQUE — chercher des rapports précédents du même client
# ══════════════════════════════════════════════════════════════════════════
history = []
audits_dir = '/opt/audits'
if slug and os.path.isdir(audits_dir):
    pattern = os.path.join(audits_dir, f'{slug}_*', 'report', 'consolidated.json')
    for f in sorted(glob.glob(pattern)):
        if out in f: continue  # Pas le rapport courant
        try:
            prev = json.load(open(f))
            history.append({
                'timestamp': prev.get('timestamp', ''),
                'risk_score': prev.get('risk_score', 0),
                'risk_level': prev.get('risk_level', ''),
                'total_issues': prev.get('total_issues', 0),
                'severity_counts': prev.get('severity_counts', {}),
                'version': prev.get('framework_version', '?'),
                'path': str(Path(f).parent.parent),
            })
        except: pass

# Tendance
trend = None
if history:
    prev = history[-1]
    delta_score = score - prev['risk_score']
    delta_issues = len(all_issues) - prev['total_issues']
    if delta_score < -5: trend_dir = 'improved'
    elif delta_score > 5: trend_dir = 'degraded'
    else: trend_dir = 'stable'
    trend = {
        'direction': trend_dir,
        'delta_score': delta_score,
        'delta_issues': delta_issues,
        'prev_score': prev['risk_score'],
        'prev_issues': prev['total_issues'],
        'prev_date': prev['timestamp'],
        'nb_previous': len(history),
    }

# ── Build consolidated ────────────────────────────────────────────────────
consolidated = {
    'client': client,
    'network': os.environ.get('NETWORK',''),
    'domain': os.environ.get('CLIENT_DOMAIN',''),
    'timestamp': os.environ.get('TIMESTAMP',''),
    'framework_version': '4.5',
    'modules_ran': list(modules_ran),

    'risk_score': score,
    'risk_level': level,
    'severity_counts': dict(total_counts),
    'total_issues': len(all_issues),
    'scoring': {
        'method': 'asymptotic_weighted + normalized',
        'active_weight': active_weight,
        'categories': category_scores,
    },

    'hosts': modules.get('discovery',{}).get('hosts',[]),
    'total_hosts': modules.get('discovery',{}).get('total_hosts',0),
    'smb_hosts': modules.get('discovery',{}).get('smb_hosts',[]),
    'web_hosts': modules.get('discovery',{}).get('web_hosts',[]),
    'dc_candidates': modules.get('discovery',{}).get('dc_candidates',[]),
    'snmp_hosts': modules.get('discovery',{}).get('snmp_hosts',[]),
    'dns_hosts': modules.get('discovery',{}).get('dns_hosts',[]),

    'smb': {k:v for k,v in modules.get('smb',{}).items() if k != 'issues'},
    'snmp': {k:v for k,v in modules.get('snmp',{}).items() if k != 'issues'},
    'dns': {k:v for k,v in modules.get('dns',{}).items() if k != 'issues'},
    'ad': {
        'dc_ip': ad.get('dc_ip',''), 'domain': ad.get('domain',''),
        'fqdn': ad.get('fqdn',''), 'netbios': ad.get('netbios',''),
        'dc_os': ad.get('dc_os',''), 'functional_level': ad.get('functional_level',''),
        'ad_score': ad.get('ad_score', 0), 'risk_level': ad.get('risk_level', ''),
        'findings': ad.get('findings', []), 'stats': ad.get('stats', {}),
        'security': ad.get('security', {}), 'password_policy': ad.get('password_policy', {}),
    },
    'wifi': {'total_networks': modules.get('wifi',{}).get('total_networks',0),
             'networks': modules.get('wifi',{}).get('networks',[])},
    'cve': {'total_cves': modules.get('cve',{}).get('total_cves',0),
            'web_technologies': modules.get('cve',{}).get('web_technologies',{})},
    'ssl': {'targets': modules.get('ssl',{}).get('targets',0),
            'targets_detail': modules.get('ssl',{}).get('targets_detail',{})},
    'email_security': {
        'domain': email.get('domain',''), 'email_score': email.get('email_score', 0),
        'risk_level': email.get('risk_level',''),
        'spf': email.get('spf',{}), 'dmarc': email.get('dmarc',{}),
        'dkim': email.get('dkim',{}), 'mx': email.get('mx',{}),
        'starttls': email.get('starttls',{}), 'extras': email.get('extras',{}),
        'findings': email.get('findings',[]),
    },
    'openvas': {
        'mode': openvas.get('mode','not_run'), 'connection': openvas.get('connection',''),
        'total_vulns': openvas.get('total_vulns',0), 'total_cves': openvas.get('total_cves',0),
        'critical_vulns': openvas.get('critical_vulns',0), 'hosts_scanned': openvas.get('hosts_scanned',0),
        'counts': openvas.get('counts',{}), 'vulns_by_host': openvas.get('vulns_by_host',{}),
        'critical_cves': openvas.get('critical_cves',[])[:20],
        'all_vulns': all_vulns_enriched,
        'message': openvas.get('message',''),
    },
    'exploitability': {
        'total_exploitable': exploit.get('total_exploitable',0),
        'with_public_exploit': exploit.get('with_public_exploit',0),
        'with_msf_module': exploit.get('with_msf_module',0),
        'exploitable_cves': exploit.get('exploitable_cves',[])[:30],
        'legal_warning': "Toute tentative d'exploitation nécessite une autorisation écrite préalable du client.",
    },
    'web_owasp': {k:v for k,v in modules.get('web_owasp',{}).items() if k != 'issues'},

    'history': history,
    'trend': trend,
    'issues': all_issues,
}

json.dump(consolidated, open(f'{out}/report/consolidated.json','w'), indent=2, ensure_ascii=False)

with open(f'{out}/report/vulnerabilities.csv','w',newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['Sévérité','Module','Cible','Problème','Recommandation'])
    for i in all_issues:
        w.writerow([i.get('severity',''),i.get('module',''),
                    i.get('target',i.get('network','')),i.get('issue',''),i.get('recommendation','')])

# ── Console ───────────────────────────────────────────────────────────────
print(f"\n{'═'*62}")
print(f"  SCORE: {score}/100 ({level})")
if active_weight < 100:
    print(f"  (normalisé: {active_weight} pts de modules actifs sur 100)")
print(f"  Issues: {len(all_issues)} (C:{total_counts.get('CRITICAL',0)} H:{total_counts.get('HIGH',0)} M:{total_counts.get('MEDIUM',0)} L:{total_counts.get('LOW',0)})")
print(f"{'═'*62}")
for cat, cs in category_scores.items():
    bar = '█' * (cs['pct'] // 10) + '░' * (10 - cs['pct'] // 10)
    print(f"  {cat:<16} {cs['score']:>5.1f}/{cs['weight']:<3} {bar} {cs['method']}")
print(f"{'═'*62}")
if trend:
    arrow = {'improved':'↗ Amélioré','degraded':'↘ Dégradé','stable':'→ Stable'}[trend['direction']]
    print(f"  Tendance: {arrow} ({trend['delta_score']:+d} pts, {trend['delta_issues']:+d} issues vs {trend['prev_date']})")
    print(f"  Historique: {len(history)} audit(s) précédent(s)")
PYCON

RC=$?
CONSOLIDATED="$OUTPUT_DIR/report/consolidated.json"

if [[ $RC -ne 0 ]]; then
    error "Consolidation ÉCHOUÉE (Python exit code $RC)"
    exit 1
fi

if [[ ! -s "$CONSOLIDATED" ]]; then
    error "consolidated.json non créé ou vide"
    exit 1
fi

success "Consolidation terminée"
