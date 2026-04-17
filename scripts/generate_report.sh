#!/bin/bash
#============================================================================
# GENERATE_REPORT.SH v4.5 - Rapport HTML
#   - Sections masquées si module non exécuté
#   - TOUTES CVE OpenVAS affichées, rouge si exploit connu
#   - Section historique / tendances
#   - Suggestions d'audit
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
log "Génération rapport HTML v4.5"

python3 << 'PYRPT'
import json, os, html as H_esc
from collections import Counter

out = os.environ['OUTPUT_DIR']
D = json.load(open(f'{out}/report/consolidated.json'))

# Shortcuts
score = D.get('risk_score', 0); level = D.get('risk_level', '')
hosts = D.get('hosts', []); all_issues = D.get('issues', [])
counts = Counter(i.get('severity','LOW') for i in all_issues)
network = D.get('network', ''); ts = D.get('timestamp', '')
ad = D.get('ad', {}); email = D.get('email_security', {})
openvas = D.get('openvas', {}); exploit_data = D.get('exploitability', {})
web_owasp = D.get('web_owasp', {})
scoring = D.get('scoring', {}); trend = D.get('trend')
history = D.get('history', [])
modules_ran = set(D.get('modules_ran', []))

def ran(key): return key in modules_ran or key in [m for m in modules_ran]

badge = {'CRITICAL':'b-c','HIGH':'b-h','MEDIUM':'b-m','LOW':'b-l','INFO':'b-i'}
score_clr = '#dc2626' if score>=75 else '#ea580c' if score>=50 else '#ca8a04' if score>=25 else '#16a34a'
ad_clr = {'CRITIQUE':'#dc2626','ÉLEVÉ':'#ea580c','MODÉRÉ':'#ca8a04','FAIBLE':'#16a34a'}

H = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>Audit {D.get('client','')} — {ts}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f5f9;color:#1e293b;font-size:13px;line-height:1.5}}
.wrap{{max-width:1100px;margin:0 auto;padding:16px}}
.card{{background:#fff;border-radius:12px;padding:20px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
h2{{font-size:16px;border-bottom:2px solid #e2e8f0;padding-bottom:6px;margin-bottom:12px}}
table{{width:100%;border-collapse:collapse;font-size:12px;margin:8px 0}}
th{{background:#f8fafc;padding:6px 8px;text-align:left;font-weight:600;border-bottom:2px solid #e2e8f0}}
td{{padding:5px 8px;border-bottom:1px solid #f1f5f9}}
tr:hover{{background:#f8fafc}}
.badge{{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}}
.b-c{{background:#dc2626}}.b-h{{background:#ea580c}}.b-m{{background:#ca8a04}}.b-l{{background:#16a34a}}.b-i{{background:#64748b}}
.b-ok{{background:#16a34a}}.b-nok{{background:#dc2626}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px}}
.stat{{text-align:center;padding:10px;border-radius:8px;background:#f8fafc}}
.stat .v{{font-size:22px;font-weight:800}}.stat .l{{font-size:10px;color:#64748b;margin-top:2px}}
.ok{{color:#16a34a;font-weight:600}}.truncate{{max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar-track{{height:8px;background:#e2e8f0;border-radius:4px}}.bar-fill{{height:100%;border-radius:4px}}
.legal-warning{{background:#fef2f2;border:2px solid #dc2626;border-radius:8px;padding:12px;color:#991b1b;font-weight:500;margin:8px 0}}
.degraded-banner{{background:#fefce8;border:2px solid #ca8a04;border-radius:8px;padding:10px;color:#854d0e;margin:8px 0}}
.email-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:10px 0}}
.email-card{{border:2px solid #e2e8f0;border-radius:10px;padding:14px;text-align:center}}
.email-card.good{{border-color:#16a34a;background:#f0fdf4}}.email-card.warn{{border-color:#ca8a04;background:#fefce8}}.email-card.bad{{border-color:#dc2626;background:#fef2f2}}
.ec-title{{font-weight:700;font-size:14px;margin-bottom:4px}}.ec-status{{font-size:20px;margin-bottom:4px}}.ec-detail{{font-size:11px;color:#64748b}}
.exploit-row{{background:#fef2f2 !important}}
.exploit-flag{{color:#dc2626;font-weight:700}}
.toc a{{color:#3b82f6;text-decoration:none;line-height:2}}.toc a:hover{{text-decoration:underline}}
.trend-card{{display:inline-block;padding:8px 16px;border-radius:8px;font-weight:700;font-size:14px;margin:4px}}
</style></head><body><div class="wrap">
<div class="card" style="text-align:center;padding:24px">
  <div style="font-size:22px;font-weight:800">{D.get('client','')}</div>
  <div style="font-size:12px;color:#94a3b8;margin-top:4px">Audit de sécurité — {network}</div>
  <div style="display:flex;justify-content:center;gap:24px;margin-top:12px;font-size:12px;color:#64748b">
    <span>Date: <b>{ts}</b></span>
    <span>Hôtes: <b>{len(hosts)}</b></span>
    <span>Vulnérabilités: <b>{len(all_issues)}</b></span>
  </div>
</div>
"""

# ══════════════ SOMMAIRE (dynamique) ══════════════
H += '<div class="card"><h2>Sommaire</h2><div class="toc">'
toc_items = [('#scores', '1. Scores de risque'), ('#scoring-detail', '2. Scoring par catégorie'),
             ('#exec-summary', '3. Executive Summary')]
sec_n = 4
if ran('discovery'): toc_items.append(('#inventaire', f'{sec_n}. Inventaire réseau')); sec_n += 1
if ran('ad') and ad.get('dc_ip'): toc_items.append(('#ad-audit', f'{sec_n}. Active Directory')); sec_n += 1
if ran('email') and email.get('domain'): toc_items.append(('#email-security', f'{sec_n}. Sécurité Email')); sec_n += 1
if ran('cve') or ran('openvas'): toc_items.append(('#vulns', f'{sec_n}. Vulnérabilités')); sec_n += 1
if ran('openvas') and openvas.get('mode') in ('openvas','openvas_empty'):
    toc_items.append(('#openvas-vulns', f'{sec_n}. OpenVAS — toutes CVE')); sec_n += 1
if ran('exploitability'): toc_items.append(('#exploitability', f'{sec_n}. Exploitabilité')); sec_n += 1
if ran('smb'): toc_items.append(('#smb', f'{sec_n}. Audit SMB')); sec_n += 1
if ran('snmp'): toc_items.append(('#snmp', f'{sec_n}. Audit SNMP')); sec_n += 1
if ran('dns'): toc_items.append(('#dns', f'{sec_n}. Audit DNS')); sec_n += 1
if ran('ssl'): toc_items.append(('#ssl', f'{sec_n}. SSL/TLS')); sec_n += 1
if ran('web_owasp') and web_owasp.get('mode') == 'executed': toc_items.append(('#web-owasp', f'{sec_n}. Audit Web OWASP')); sec_n += 1
if ran('cve'): toc_items.append(('#web-tech', f'{sec_n}. Technologies web')); sec_n += 1
if ran('wifi'): toc_items.append(('#wifi', f'{sec_n}. WiFi')); sec_n += 1
if history: toc_items.append(('#history', f'{sec_n}. Historique & tendances')); sec_n += 1
toc_items.append(('#remediation', f'{sec_n}. Plan de remédiation'))
toc_items.append(('#suggestions', f'{sec_n+1}. Suggestions'))

for href, label in toc_items:
    H += f'  <a href="{href}">{label}</a><br>'
H += '</div></div>'

# ══════════════ SCORES ══════════════
H += f'<div class="card" id="scores"><h2>Scores de Risque</h2><div style="display:flex;gap:16px;flex-wrap:wrap;justify-content:center">'
H += f'<div style="text-align:center;padding:16px 24px;border-radius:12px;border:3px solid {score_clr}">'
H += f'<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Score Global</div>'
H += f'<div style="font-size:42px;font-weight:900;color:{score_clr}">{score}</div>'
H += f'<div style="font-size:12px;font-weight:700;color:{score_clr}">{level}</div></div>'
if ad.get('dc_ip') and ran('ad'):
    ac = ad_clr.get(ad.get('risk_level',''),'#64748b')
    H += f'<div style="text-align:center;padding:16px 24px;border-radius:12px;border:3px solid {ac}">'
    H += f'<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Active Directory</div>'
    H += f'<div style="font-size:42px;font-weight:900;color:{ac}">{ad.get("ad_score",0)}</div>'
    H += f'<div style="font-size:12px;font-weight:700;color:{ac}">{ad.get("risk_level","")}</div></div>'
if email.get('domain') and ran('email'):
    ec = ad_clr.get(email.get('risk_level',''),'#64748b')
    H += f'<div style="text-align:center;padding:16px 24px;border-radius:12px;border:3px solid {ec}">'
    H += f'<div style="font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">Sécurité Email</div>'
    H += f'<div style="font-size:42px;font-weight:900;color:{ec}">{email.get("email_score",0)}</div>'
    H += f'<div style="font-size:11px;color:#64748b;margin-top:4px">{email.get("domain","")}</div></div>'
H += '</div></div>'

# ══════════════ SCORING PAR CATÉGORIE ══════════════
cats = scoring.get('categories', {})
if cats:
    H += '<div class="card" id="scoring-detail"><h2>📊 Scoring par Catégorie</h2>'
    H += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;margin-bottom:14px">'
    labels = {'infrastructure':'🖥 Infra','smb':'📁 SMB','ad':'🏰 AD',
              'email':'📧 Email','vulns':'🛡 Vulns','ssl':'🔐 SSL',
              'wifi':'📶 WiFi','snmp':'📡 SNMP','dns':'🌐 DNS'}
    for cat, cs in cats.items():
        pct = cs.get('pct',0)
        bc = '#dc2626' if pct>=75 else '#ea580c' if pct>=50 else '#ca8a04' if pct>=25 else '#16a34a'
        bg = '#fef2f2' if pct>=75 else '#fff7ed' if pct>=50 else '#fefce8' if pct>=25 else '#f0fdf4'
        H += f'<div style="background:{bg};border-radius:8px;padding:10px;text-align:center;border:1px solid {bc}22">'
        H += f'<div style="font-size:11px;color:#64748b">{labels.get(cat,cat)}</div>'
        H += f'<div style="font-size:22px;font-weight:800;color:{bc}">{cs["score"]:.0f}<small style="font-size:11px;font-weight:400">/{cs["weight"]}</small></div>'
        H += f'<div style="height:4px;background:#e2e8f0;border-radius:2px;margin-top:4px"><div style="height:100%;width:{pct}%;background:{bc};border-radius:2px"></div></div>'
        H += f'<div style="font-size:9px;color:#94a3b8;margin-top:3px">{cs.get("method","")}</div></div>'
    H += '</div></div>'

# ══════════════ EXECUTIVE SUMMARY (cards visuelles) ══════════════
crit_n = counts.get('CRITICAL',0); high_n = counts.get('HIGH',0)
exploitable_count = exploit_data.get('total_exploitable', 0)
ov_mode = openvas.get('mode', 'not_run')

status_items = []
if crit_n > 0: status_items.append(('🔴', f'{crit_n} critique{"s" if crit_n>1 else ""}', f'+ {high_n} élevée{"s" if high_n>1 else ""}', 'bad'))
elif high_n > 0: status_items.append(('🟠', f'{high_n} élevée{"s" if high_n>1 else ""}', f'{len(all_issues)} total', 'warn'))
else: status_items.append(('🟢', 'Aucune critique', f'{len(all_issues)} issues', 'good'))

if ran('ad') and ad.get('dc_ip'):
    ac = 'bad' if ad.get('ad_score',0)>=61 else 'warn' if ad.get('ad_score',0)>=31 else 'good'
    status_items.append(('🏰', f'AD: {ad.get("ad_score",0)}/100', ad.get('risk_level',''), ac))
if ran('email') and email.get('domain'):
    spf_ok = email.get('spf',{}).get('exists',False); dmarc_ok = email.get('dmarc',{}).get('exists',False)
    dkim_n = email.get('dkim',{}).get('selectors_found',0)
    ec = 'good' if spf_ok and dmarc_ok and dkim_n>0 else 'warn' if spf_ok else 'bad'
    status_items.append(('📧', f'Email: {email.get("email_score",0)}/100', f"SPF {'✓' if spf_ok else '✗'} DMARC {'✓' if dmarc_ok else '✗'} DKIM {dkim_n}", ec))
if ran('openvas'):
    if ov_mode == 'openvas':
        oc = 'bad' if openvas.get('critical_vulns',0) > 0 else 'good'
        status_items.append(('🔍', f'OpenVAS: {openvas.get("total_cves",0)} CVE', f'{openvas.get("critical_vulns",0)} critiques', oc))
    elif ov_mode == 'degraded':
        status_items.append(('⚠️', 'OpenVAS', 'Mode dégradé', 'warn'))
if exploitable_count > 0:
    status_items.append(('💣', f'{exploitable_count} exploitables', f'{exploit_data.get("with_public_exploit",0)} publics', 'bad'))
if trend:
    tc = {'improved':'good','degraded':'bad','stable':'warn'}[trend['direction']]
    tl = {'improved':'↗ Amélioré','degraded':'↘ Dégradé','stable':'→ Stable'}[trend['direction']]
    status_items.append(('📈', tl, f'{trend["delta_score"]:+d} pts', tc))

H += f'<div class="card" id="exec-summary"><h2>Executive Summary</h2>'
H += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px">'
for icon, title, sub, cls in status_items:
    bg = {'bad':'#fef2f2','warn':'#fffbeb','good':'#f0fdf4'}[cls]
    border = {'bad':'#fca5a5','warn':'#fcd34d','good':'#86efac'}[cls]
    color = {'bad':'#991b1b','warn':'#92400e','good':'#166534'}[cls]
    H += f'<div style="background:{bg};border:2px solid {border};border-radius:10px;padding:12px;text-align:center">'
    H += f'<div style="font-size:24px">{icon}</div>'
    H += f'<div style="font-weight:700;font-size:13px;color:{color}">{title}</div>'
    H += f'<div style="font-size:11px;color:{color};opacity:.8">{sub}</div></div>'
H += '</div>'
H += f'<p>Audit du périmètre <b>{network}</b>: <b>{len(all_issues)} vulnérabilités</b> (score: <b>{score}/100 — {level}</b>).</p></div>'

# ══════════════ SYNTHÈSE ══════════════
stats = ad.get('stats', {})
H += f'<div class="card" id="synthese"><h2>Synthèse</h2><div class="grid">'
for v, l in [(len(hosts),'Hôtes actifs'),(len(D.get('smb_hosts',[])),'Hôtes SMB'),
             (len(D.get('snmp_hosts',[])),'SNMP'),(stats.get('total_users','?'),'Users AD'),
             (stats.get('domain_admins','?'),'Domain Admins'),
             (D.get('cve',{}).get('total_cves',0)+openvas.get('total_cves',0),'CVE totales'),
             (D.get('wifi',{}).get('total_networks',0),'WiFi')]:
    H += f'<div class="stat"><div class="v">{v}</div><div class="l">{l}</div></div>'
H += '</div></div>'

# ══════════════ INVENTAIRE ══════════════
if ran('discovery') and hosts:
    H += '<div class="card" id="inventaire"><h2>Inventaire Réseau</h2><table>'
    H += '<tr><th>IP</th><th>Hostname</th><th>MAC</th><th>OS</th><th>TCP</th><th>UDP</th></tr>'
    for h in hosts:
        tcp = ', '.join(str(p['port']) if isinstance(p, dict) else str(p) for p in h.get('tcp_ports',[])) or '-'
        udp = ', '.join(str(p['port']) if isinstance(p, dict) else str(p) for p in h.get('udp_ports',[])) or '-'
        H += f"<tr><td><b>{h.get('ip','')}</b></td><td>{h.get('hostname','')}</td><td>{h.get('mac','')}</td><td class='truncate'>{h.get('os','')}</td><td>{tcp}</td><td>{udp}</td></tr>"
    H += '</table></div>'

# ══════════════ AD ══════════════
if ran('ad') and ad.get('dc_ip'):
    H += f'<div class="card" id="ad-audit"><h2>🏰 Audit Active Directory</h2>'
    H += f'<p>DC: <b>{ad.get("dc_ip","")}</b> ({ad.get("fqdn","")}) — {ad.get("dc_os","")}</p>'
    ad_findings = ad.get('findings', [])
    if ad_findings:
        H += '<table><tr><th>Catégorie</th><th>Sév.</th><th>Finding</th><th>Détail</th></tr>'
        for f in sorted(ad_findings, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9)):
            H += f"<tr><td>{f.get('category','')}</td><td><span class='badge {badge.get(f.get('severity',''),'b-l')}'>{f.get('severity','')}</span></td><td><b>{f.get('title','')}</b></td><td>{f.get('details','')[:100]}</td></tr>"
        H += '</table>'
    pwd = ad.get('password_policy', {})
    if pwd:
        H += '<h3 style="margin-top:10px">Password Policy</h3><table>'
        for k, v in pwd.items():
            H += f'<tr><td><b>{k}</b></td><td>{v}</td></tr>'
        H += '</table>'
    H += '</div>'

# ══════════════ EMAIL ══════════════
if ran('email') and email.get('domain'):
    em_score = email.get('email_score',0)
    spf = email.get('spf',{}); dmarc = email.get('dmarc',{}); dkim = email.get('dkim',{})
    mx = email.get('mx',{}); starttls = email.get('starttls',{})
    extras = email.get('extras',{})
    ec_class = lambda ok: 'good' if ok else 'bad'
    spf_ok = spf.get('exists',False); dmarc_ok = dmarc.get('exists',False)
    dkim_ok = dkim.get('selectors_found',0) > 0

    H += f'<div class="card" id="email-security"><h2>📧 Sécurité Email — {email["domain"]}</h2>'

    # Status cards
    H += '<div class="email-grid">'
    H += f'<div class="email-card {ec_class(spf_ok)}"><div class="ec-title">SPF</div>'
    H += f'<div class="ec-status">{"✓" if spf_ok else "✗"}</div>'
    H += f'<div class="ec-detail">{spf.get("policy","") or ("Présent" if spf_ok else "Absent")}</div></div>'
    H += f'<div class="email-card {ec_class(dmarc_ok)}"><div class="ec-title">DMARC</div>'
    H += f'<div class="ec-status">{"✓" if dmarc_ok else "✗"}</div>'
    dp = dmarc.get("policy","")
    H += f'<div class="ec-detail">{"p=" + dp if dp else ("Présent" if dmarc_ok else "Absent")}</div></div>'
    H += f'<div class="email-card {ec_class(dkim_ok)}"><div class="ec-title">DKIM</div>'
    H += f'<div class="ec-status">{dkim.get("selectors_found",0)} sél.</div>'
    H += f'<div class="ec-detail">{"trouvé(s)" if dkim_ok else "Aucun"}</div></div>'
    H += '</div>'

    # ── SPF détail ────────────────────────────────────────────────────
    H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">📋 Configuration SPF</summary>'
    if spf.get('record'):
        H += f'<div style="background:#f8fafc;padding:8px 12px;border-radius:6px;font-family:monospace;font-size:11px;word-break:break-all;margin-bottom:6px">{spf["record"]}</div>'
        mechanisms = spf.get('mechanisms', [])
        if mechanisms:
            H += '<div style="font-size:12px;margin-bottom:6px">'
            for mech in mechanisms:
                color = '#dc2626' if mech == '+all' else '#ca8a04' if mech in ('~all','?all') else '#16a34a' if mech == '-all' else '#64748b'
                H += f'<span style="display:inline-block;padding:1px 6px;margin:2px;border-radius:3px;background:{color}11;color:{color};border:1px solid {color}33;font-size:10px">{mech}</span> '
            H += '</div>'
        spf_issues = spf.get('issues', [])
        if spf_issues:
            for si in spf_issues:
                H += f'<div style="color:#dc2626;font-size:11px">⚠ {si}</div>'
        elif spf.get('policy') == '-all':
            H += '<div style="color:#16a34a;font-size:11px">✓ SPF strict (-all) — bonne pratique</div>'
    else:
        H += '<div style="color:#dc2626">✗ Aucun enregistrement SPF publié</div>'
    H += '</details>'

    # ── DMARC détail ──────────────────────────────────────────────────
    H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">📋 Configuration DMARC</summary>'
    if dmarc.get('record'):
        H += f'<div style="background:#f8fafc;padding:8px 12px;border-radius:6px;font-family:monospace;font-size:11px;word-break:break-all;margin-bottom:6px">{dmarc["record"]}</div>'
        H += '<table style="font-size:12px"><tr><th>Tag</th><th>Valeur</th><th>Signification</th></tr>'
        pol = dmarc.get('policy','')
        pol_desc = {'none':'Monitoring seulement (aucun blocage)','quarantine':'Emails suspects en spam','reject':'Emails frauduleux rejetés'}.get(pol, pol)
        pol_color = {'none':'#dc2626','quarantine':'#ca8a04','reject':'#16a34a'}.get(pol, '#64748b')
        H += f'<tr><td><b>p</b></td><td style="color:{pol_color};font-weight:700">{pol}</td><td>{pol_desc}</td></tr>'
        sp = dmarc.get('sub_policy','')
        if sp: H += f'<tr><td><b>sp</b></td><td>{sp}</td><td>Policy sous-domaines</td></tr>'
        rua = dmarc.get('rua','')
        H += f'<tr><td><b>rua</b></td><td>{rua or "<span style=color:#dc2626>non configuré</span>"}</td><td>Rapports agrégés</td></tr>'
        ruf = dmarc.get('ruf','')
        if ruf: H += f'<tr><td><b>ruf</b></td><td>{ruf}</td><td>Rapports forensic</td></tr>'
        pct = dmarc.get('pct', 100)
        pct_color = '#16a34a' if pct == 100 else '#ca8a04'
        H += f'<tr><td><b>pct</b></td><td style="color:{pct_color}">{pct}%</td><td>Pourcentage emails soumis à la policy</td></tr>'
        H += '</table>'
    else:
        H += '<div style="color:#dc2626">✗ Aucun enregistrement DMARC publié</div>'
    H += '</details>'

    # ── DKIM détail ───────────────────────────────────────────────────
    H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">📋 Configuration DKIM</summary>'
    selectors = dkim.get('selectors', [])
    if selectors:
        H += '<table style="font-size:12px"><tr><th>Sélecteur</th><th>Type</th><th>Clé publique (extrait)</th></tr>'
        for sel in selectors:
            kt = sel.get('key_type', 'rsa').upper()
            rec = sel.get('record', '')[:120]
            H += f'<tr><td><b>{sel.get("selector","")}</b>._domainkey.{email["domain"]}</td>'
            H += f'<td><span class="badge b-i">{kt}</span></td>'
            H += f'<td style="font-family:monospace;font-size:10px;word-break:break-all">{rec}...</td></tr>'
        H += '</table>'
    else:
        H += '<div style="color:#dc2626">✗ Aucun sélecteur DKIM trouvé parmi les 20+ testés</div>'
    H += '</details>'

    # ── MX + STARTTLS ─────────────────────────────────────────────────
    mx_records = mx.get('records', [])
    if mx_records:
        H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">📋 Serveurs MX & STARTTLS</summary>'
        H += '<table style="font-size:12px"><tr><th>Priorité</th><th>Serveur</th></tr>'
        for m in mx_records:
            H += f'<tr><td>{m.get("priority","")}</td><td><b>{m.get("host","")}</b></td></tr>'
        H += '</table>'
        if starttls.get('tested'):
            tls_ok = starttls.get('ok', False)
            tls_color = '#16a34a' if tls_ok else '#dc2626'
            H += f'<div style="margin-top:4px;color:{tls_color};font-size:12px">STARTTLS: {"✓ supporté" if tls_ok else "✗ non supporté"} ({starttls.get("mx_primary","")})</div>'
        H += '</details>'

    # ── Extras: MTA-STS, DANE, BIMI ──────────────────────────────────
    H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">📋 Protections avancées</summary>'
    H += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px">'
    for name, has_it, desc in [
        ('MTA-STS', extras.get('mta_sts',False), 'Mode strict pour TLS sur le transport mail'),
        ('DANE/TLSA', extras.get('dane',False), 'Validation certificat MX via DNSSEC'),
        ('BIMI', extras.get('bimi',False), 'Logo de marque dans les clients mail')
    ]:
        bg = '#f0fdf4' if has_it else '#f8fafc'
        bc = '#16a34a' if has_it else '#e2e8f0'
        icon = '✓' if has_it else '✗'
        H += f'<div style="background:{bg};border:1px solid {bc};border-radius:6px;padding:8px;text-align:center">'
        H += f'<div style="font-weight:700;font-size:12px">{icon} {name}</div>'
        H += f'<div style="font-size:10px;color:#64748b">{desc}</div></div>'
    H += '</div></details>'

    # ── Findings ──────────────────────────────────────────────────────
    em_findings = email.get('findings', [])
    if em_findings:
        H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">⚠ Problèmes identifiés</summary>'
        H += '<table><tr><th>Cat.</th><th>Sév.</th><th>Problème</th><th>Recommandation</th></tr>'
        for f in em_findings:
            bc = badge.get(f.get('severity',''),'b-l')
            H += f"<tr><td>{f.get('category','')}</td><td><span class='badge {bc}'>{f.get('severity','')}</span></td>"
            H += f"<td>{f.get('title','')}<br><small style='color:#64748b'>{f.get('details','')[:150]}</small></td>"
            H += f"<td>{f.get('recommendation','')}</td></tr>"
        H += '</table></details>'
    H += '</div>'

# ══════════════ VULNÉRABILITÉS (core) ══════════════
core_issues = [i for i in all_issues if i.get('module') not in ('ad','openvas','exploitability','email_security')]
if core_issues:
    H += '<div class="card" id="vulns"><h2>Vulnérabilités</h2><table>'
    H += '<tr><th>Module</th><th>Cible</th><th>Sév.</th><th>Problème</th><th>Recommandation</th></tr>'
    mod_labels = {'discovery':'Discovery','smb':'SMB','cve':'CVE','ssl':'SSL','wifi':'WiFi',
                  'snmp':'SNMP','dns':'DNS'}
    for i in core_issues[:100]:
        H += f"<tr><td>{mod_labels.get(i.get('module',''),i.get('module',''))}</td><td><b>{i.get('target','')}</b></td>"
        H += f"<td><span class='badge {badge.get(i['severity'],'b-l')}'>{i['severity']}</span></td>"
        H += f"<td>{i.get('issue','')[:120]}</td><td>{i.get('recommendation','')[:100]}</td></tr>"
    H += '</table></div>'

# ══════════════ OPENVAS — TOUTES CVE ══════════════
if ran('openvas') and openvas.get('mode') in ('openvas','openvas_empty'):
    all_ov_vulns = openvas.get('all_vulns', [])
    H += f'<div class="card" id="openvas-vulns"><h2>🔍 OpenVAS — Toutes vulnérabilités ({len(all_ov_vulns)})</h2>'
    H += f'<div class="grid" style="margin-bottom:10px">'
    H += f'<div class="stat"><div class="v">{openvas.get("hosts_scanned",0)}</div><div class="l">Hôtes scannés</div></div>'
    H += f'<div class="stat"><div class="v">{openvas.get("total_vulns",0)}</div><div class="l">Vulnérabilités</div></div>'
    H += f'<div class="stat"><div class="v">{openvas.get("total_cves",0)}</div><div class="l">CVE uniques</div></div>'
    H += f'<div class="stat" style="border:2px solid {"#dc2626" if openvas.get("critical_vulns",0)>0 else "#e2e8f0"}">'
    H += f'<div class="v" style="color:#dc2626">{openvas.get("critical_vulns",0)}</div><div class="l">Critiques (CVSS≥8)</div></div>'
    H += '</div>'

    if all_ov_vulns:
        H += '<table><tr><th>Hôte</th><th>Port</th><th>CVSS</th><th>Sév.</th><th>Vulnérabilité</th><th>CVE</th><th>Exploit</th><th>Solution</th></tr>'
        for v in sorted(all_ov_vulns, key=lambda x: -x.get('cvss', 0)):
            has_ex = v.get('has_exploit', False)
            row_class = ' class="exploit-row"' if has_ex else ''
            ex_flag = '<span class="exploit-flag">⚠ EXPLOIT</span>' if has_ex else '—'
            cve_str = ', '.join(v.get('cves',[])[:3]) or '—'
            H += f"<tr{row_class}><td><b>{v.get('host','')}</b></td><td>{v.get('port','')}</td>"
            H += f"<td><b>{v.get('cvss',0)}</b></td>"
            sev = v.get('severity', '')
            bc = badge.get(sev, 'b-l')
            H += f"<td><span class='badge {bc}'>{sev}</span></td>"
            H += f"<td>{v.get('name','')[:80]}</td><td><code>{cve_str}</code></td>"
            H += f"<td>{ex_flag}</td><td class='truncate'>{v.get('solution','')[:80]}</td></tr>"
        H += '</table>'
    H += '</div>'
elif ran('openvas') and openvas.get('mode') == 'degraded':
    H += f'<div class="card" id="openvas-vulns"><h2>🔍 OpenVAS</h2>'
    H += f'<div class="degraded-banner">⚠ Mode dégradé: {openvas.get("reason","")}. Résultats basés sur Nmap vulners.</div></div>'

# ══════════════ EXPLOITABILITÉ ══════════════
if ran('exploitability') and exploit_data.get('total_exploitable', 0) > 0:
    H += '<div class="card" id="exploitability"><h2>💣 Exploitabilité (indicative)</h2>'
    H += f'<div class="legal-warning">⚠ {exploit_data.get("legal_warning","")}</div>'
    H += f'<p><b>{exploit_data.get("total_exploitable",0)}</b> CVE exploitables: '
    H += f'<b>{exploit_data.get("with_public_exploit",0)}</b> avec exploit public, '
    H += f'<b>{exploit_data.get("with_msf_module",0)}</b> avec module Metasploit.</p>'
    ecves = exploit_data.get('exploitable_cves',[])
    if ecves:
        H += '<table><tr><th>CVE</th><th>CVSS</th><th>Hôtes</th><th>Service</th><th>Exploit public</th><th>Module MSF</th></tr>'
        for e in ecves[:30]:
            H += f"<tr><td><b>{e.get('cve','')}</b></td><td>{e.get('cvss','')}</td>"
            H += f"<td>{', '.join(e.get('hosts',[])[:2])}</td><td>{e.get('service','')[:40]}</td>"
            H += f"<td>{'✅' if e.get('exploit_public') else '—'}</td>"
            H += f"<td>{'✅' if e.get('msf_available') else '—'}</td></tr>"
        H += '</table>'
    H += '</div>'

# ══════════════ SMB ══════════════
if ran('smb'):
    smb_data   = D.get('smb', {})
    smb_issues = [i for i in all_issues if i.get('module') == 'smb']
    shares_inv = smb_data.get('shares_inventory', {})
    total_shares = sum(len(v) for v in shares_inv.values())
    accessible   = sum(1 for lst in shares_inv.values()
                       for s in lst if s.get('permissions',''))
    H += f'<div class="card" id="smb"><h2>📁 Audit SMB</h2>'
    H += f'<div class="grid" style="margin-bottom:10px">'
    H += f'<div class="stat"><div class="v">{smb_data.get("total",len(shares_inv))}</div><div class="l">Hôtes SMB</div></div>'
    H += f'<div class="stat"><div class="v">{total_shares}</div><div class="l">Shares listés</div></div>'
    H += f'<div class="stat" style="border:2px solid {"#dc2626" if accessible else "#e2e8f0"}"><div class="v" style="color:{"#dc2626" if accessible else "#1e293b"}">{accessible}</div><div class="l">Accessibles (anon)</div></div>'
    H += f'<div class="stat" style="border:2px solid {"#dc2626" if smb_data.get("counts",{}).get("CRITICAL",0) else "#e2e8f0"}"><div class="v">{len(smb_issues)}</div><div class="l">Issues</div></div>'
    H += '</div>'
    if shares_inv:
        H += '<h3 style="margin:8px 0 4px">Inventaire des shares</h3>'
        H += '<table><tr><th>IP</th><th>Share</th><th>Accès anonyme</th><th>Commentaire</th></tr>'
        for ip, sh_list in sorted(shares_inv.items()):
            for sh in sh_list:
                p = sh.get('permissions','') or '—'
                color = '#dc2626' if 'WRITE' in p else ('#f59e0b' if 'READ' in p else '#64748b')
                p_html = f'<b style="color:{color}">{p}</b>'
                H += f"<tr><td><b>{ip}</b></td><td>{sh.get('name','')}</td><td>{p_html}</td><td style='font-size:11px;color:#64748b'>{sh.get('comment','')}</td></tr>"
        H += '</table>'
    if smb_issues:
        H += '<h3 style="margin:8px 0 4px">Issues détectées</h3>'
        H += '<table><tr><th>Cible</th><th>Sév.</th><th>Problème</th></tr>'
        for i in smb_issues:
            H += f"<tr><td><b>{i.get('target','')}</b></td><td><span class='badge {badge.get(i.get(\"severity\",'LOW'),'b-l')}'>{i.get('severity','')}</span></td><td>{i.get('issue','')}</td></tr>"
        H += '</table>'
    if not shares_inv and not smb_issues:
        H += '<p class="ok">✓ Aucun share accessible anonymement détecté</p>'
    H += '</div>'

# ══════════════ SNMP ══════════════
if ran('snmp'):
    snmp_data = D.get('snmp',{})
    snmp_devices = snmp_data.get('devices',[])
    write_hosts = snmp_data.get('write_access_hosts',[])
    H += '<div class="card" id="snmp"><h2>📡 Audit SNMP</h2>'

    if write_hosts:
        H += '<div class="legal-warning">⚠ WRITE ACCESS détecté sur: <b>' + ', '.join(write_hosts) + '</b> — Reconfiguration à distance possible !</div>'

    if snmp_devices:
        # Overview
        H += f'<div class="grid" style="margin-bottom:10px">'
        H += f'<div class="stat"><div class="v">{len(snmp_devices)}</div><div class="l">Devices SNMP</div></div>'
        H += f'<div class="stat" style="border:2px solid {"#dc2626" if write_hosts else "#e2e8f0"}"><div class="v" style="color:{"#dc2626" if write_hosts else "#1e293b"}">{len(write_hosts)}</div><div class="l">Write Access</div></div>'
        total_procs = sum(len(d.get('processes',[])) for d in snmp_devices)
        total_sw = sum(len(d.get('software',[])) for d in snmp_devices)
        H += f'<div class="stat"><div class="v">{total_procs}</div><div class="l">Processus</div></div>'
        H += f'<div class="stat"><div class="v">{total_sw}</div><div class="l">Logiciels</div></div>'
        H += '</div>'

        # Device table
        H += '<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Community</th><th>Write</th><th>Processus</th><th>Logiciels</th></tr>'
        for d in snmp_devices:
            comms = ', '.join(d.get('communities',['public']))
            wr = '<span class="badge b-c">⚠ OUI</span>' if d.get('write_access') else '—'
            wr_comm = f' ({d.get("write_community","")})' if d.get('write_access') else ''
            procs = len(d.get('processes',[]))
            sw = len(d.get('software',[]))
            H += f"<tr><td><b>{d.get('ip','')}</b></td><td>{d.get('hostname','')}</td>"
            H += f"<td>{d.get('os_guess','') or d.get('description','')[:50]}</td>"
            H += f"<td><span class='badge b-nok'>{comms}</span></td>"
            H += f"<td>{wr}{wr_comm}</td><td>{procs}</td><td>{sw}</td></tr>"
        H += '</table>'

        # Per-device details
        for d in snmp_devices:
            procs = d.get('processes',[])
            sw = d.get('software',[])
            tcp = d.get('tcp_ports',[])
            intfs = d.get('interfaces',[])
            if procs or sw or tcp:
                H += f'<details><summary style="cursor:pointer;font-size:12px;margin:6px 0"><b>{d["ip"]}</b> — {d.get("os_guess","")}'
                if d.get("description"): H += f' <span style="color:#64748b;font-size:10px">({d["description"][:60]})</span>'
                H += '</summary><div style="padding:0 12px">'
                if d.get('uptime'): H += f'<p style="font-size:11px;color:#64748b">Uptime: {d["uptime"]}</p>'
                if procs:
                    dangerous = {'telnetd','ftpd','rsh','rlogin','rexecd'}
                    sensitive = {'sshd','httpd','apache2','nginx','mysqld','postgres','smbd','named','dhcpd','snmpd','cupsd','dovecot','postfix','openvpn'}
                    H += f'<p style="font-size:12px;font-weight:700;margin-top:6px">Processus ({len(procs)}):</p><div style="font-size:11px">'
                    for p in sorted(set(procs)):
                        pl = p.lower()
                        if pl in dangerous: H += f'<span style="background:#fef2f2;color:#dc2626;padding:1px 4px;margin:1px;border-radius:3px;font-weight:700">⚠ {p}</span> '
                        elif pl in sensitive: H += f'<span style="background:#fffbeb;color:#92400e;padding:1px 4px;margin:1px;border-radius:3px">{p}</span> '
                        else: H += f'<span style="color:#64748b">{p}</span> '
                    H += '</div>'
                if sw:
                    H += f'<p style="font-size:12px;font-weight:700;margin-top:6px">Logiciels ({len(sw)}):</p><div style="font-size:11px">'
                    for s in sorted(set(sw))[:30]:
                        H += f'<span style="display:inline-block;background:#f1f5f9;padding:1px 4px;margin:1px;border-radius:3px;font-size:10px">{s[:60]}</span> '
                    if len(sw) > 30: H += f'<span style="color:#94a3b8">... +{len(sw)-30}</span>'
                    H += '</div>'
                if tcp:
                    H += f'<p style="font-size:12px;font-weight:700;margin-top:6px">Ports TCP ouverts:</p>'
                    H += f'<div style="font-size:11px;color:#64748b">{", ".join(str(p) for p in tcp[:30])}</div>'
                H += '</div></details>'
    else:
        H += '<p class="ok">✓ Aucun device SNMP exposé</p>'

    # SNMP issues
    snmp_issues = [i for i in all_issues if i.get('module')=='snmp']
    if snmp_issues:
        H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 6px">⚠ Vulnérabilités SNMP</summary>'
        H += '<table><tr><th>Cible</th><th>Sév.</th><th>Problème</th><th>Recommandation</th></tr>'
        for i in snmp_issues:
            bc = badge.get(i['severity'],'b-l')
            H += f"<tr><td><b>{i.get('target','')}</b></td><td><span class='badge {bc}'>{i['severity']}</span></td>"
            H += f"<td>{i['issue']}</td><td>{i.get('recommendation','')}</td></tr>"
        H += '</table></details>'
    H += '</div>'

# ══════════════ DNS ══════════════
if ran('dns'):
    dns_issues = [i for i in all_issues if i.get('module')=='dns']
    H += '<div class="card" id="dns"><h2>🌐 Audit DNS</h2>'
    if dns_issues:
        H += '<table><tr><th>Cible</th><th>Sév.</th><th>Problème</th></tr>'
        for i in dns_issues: H += f"<tr><td><b>{i.get('target','')}</b></td><td><span class='badge {badge.get(i['severity'],'b-l')}'>{i['severity']}</span></td><td>{i['issue']}</td></tr>"
        H += '</table>'
    else: H += '<p class="ok">✓ OK</p>'
    H += '</div>'

# ══════════════ SSL ══════════════
if ran('ssl'):
    ssl_data    = D.get('ssl', {})
    ssl_targets = ssl_data.get('targets_detail', {})
    ssl_issues  = [i for i in all_issues if i.get('module')=='ssl']
    H += '<div class="card" id="ssl"><h2>🔐 SSL/TLS</h2>'

    # Stats
    exp_soon = sum(1 for d in ssl_targets.values() if isinstance(d.get('cert_days_remaining'), int) and d['cert_days_remaining'] < 90)
    exp_red  = sum(1 for d in ssl_targets.values() if isinstance(d.get('cert_days_remaining'), int) and d['cert_days_remaining'] < 0)
    H += '<div class="grid" style="margin-bottom:10px">'
    H += f'<div class="stat"><div class="v">{ssl_data.get("targets",0)}</div><div class="l">Cibles testées</div></div>'
    H += f'<div class="stat"><div class="v">{len(ssl_issues)}</div><div class="l">Issues SSL/TLS</div></div>'
    H += f'<div class="stat" style="border:2px solid {"#dc2626" if exp_red else "#e2e8f0"}"><div class="v" style="color:{"#dc2626" if exp_red else "#ca8a04" if exp_soon else "#1e293b"}">{exp_soon}</div><div class="l">Certs &lt; 90 j</div></div>'
    H += '</div>'

    # Tableau certificats
    if ssl_targets:
        H += '<details open><summary style="cursor:pointer;font-weight:700;margin:6px 0 4px">🔏 Certificats actifs</summary>'
        H += '<table><tr><th>Hôte:Port</th><th>Sujet (CN)</th><th>Émetteur</th><th>Expiration</th><th>Jours restants</th><th>Protocoles</th></tr>'
        for tgt, det in sorted(ssl_targets.items()):
            days = det.get('cert_days_remaining', '')
            protos = ', '.join(det.get('protocols', []))
            if isinstance(days, int):
                ds = 'color:#dc2626;font-weight:700' if days < 0 else 'color:#ea580c;font-weight:700' if days < 30 else 'color:#ca8a04' if days < 90 else ''
                dv = str(days)
            else:
                ds = ''; dv = '—'
            ps = 'color:#dc2626;font-weight:700' if any(p in protos for p in ('SSLv2','SSLv3','TLSv1.0','TLSv1.1')) else 'color:#16a34a'
            ss = '<span class="badge b-m">auto-signé</span> ' if det.get('cert_selfsigned') else ''
            H += f"<tr><td><b>{tgt}</b></td>"
            H += f"<td>{ss}{det.get('cert_cn','') or '—'}</td>"
            H += f"<td style='font-size:11px;color:#64748b'>{det.get('cert_issuer','') or '—'}</td>"
            H += f"<td>{det.get('cert_expiry','') or '—'}</td>"
            H += f"<td style='{ds}'>{dv}</td>"
            H += f"<td style='{ps};font-size:11px'>{protos or '—'}</td></tr>"
        H += '</table></details>'

    # Issues SSL
    if ssl_issues:
        H += '<details open><summary style="cursor:pointer;font-weight:700;margin:10px 0 4px">⚠ Vulnérabilités SSL/TLS</summary>'
        H += '<table><tr><th>Cible</th><th>Sév.</th><th>Problème</th><th>Recommandation</th></tr>'
        for i in sorted(ssl_issues, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9)):
            bc = badge.get(i.get('severity','LOW'),'b-l')
            H += f"<tr><td><b>{i.get('target','')}</b></td><td><span class='badge {bc}'>{i.get('severity','')}</span></td>"
            H += f"<td>{i.get('issue','')}</td><td style='font-size:11px;color:#64748b'>{i.get('recommendation','')}</td></tr>"
        H += '</table></details>'
    elif not ssl_targets:
        H += '<p class="ok">✓ OK</p>'
    H += '</div>'

# ══════════════ WEB OWASP ══════════════
if ran('web_owasp') and web_owasp.get('mode') == 'executed':
    ow_findings = web_owasp.get('owasp_findings', [])
    ow_by_cat   = web_owasp.get('by_owasp_category', {})
    ow_counts   = web_owasp.get('counts', {})
    ow_waf      = web_owasp.get('waf_detected', {})
    ow_cms      = web_owasp.get('cms_detected', {})
    ow_targets  = web_owasp.get('targets_scanned', 0)

    ow_badge_color = '#dc2626' if ow_counts.get('CRITICAL',0)>0 else '#ea580c' if ow_counts.get('HIGH',0)>0 else '#ca8a04' if ow_counts.get('MEDIUM',0)>0 else '#64748b'

    H += f'<div class="card" id="web-owasp"><h2>🌐 Audit Web OWASP Top 10 2021</h2>'

    # Stats overview
    H += '<div class="grid" style="margin-bottom:12px">'
    H += f'<div class="stat"><div class="v">{ow_targets}</div><div class="l">Cibles scannées</div></div>'
    H += f'<div class="stat"><div class="v">{len(ow_findings)}</div><div class="l">Findings OWASP</div></div>'
    H += f'<div class="stat" style="border:2px solid {"#dc2626" if ow_counts.get("CRITICAL",0)>0 else "#e2e8f0"}"><div class="v" style="color:#dc2626">{ow_counts.get("CRITICAL",0)}</div><div class="l">Critiques</div></div>'
    H += f'<div class="stat" style="border:2px solid {"#ea580c" if ow_counts.get("HIGH",0)>0 else "#e2e8f0"}"><div class="v" style="color:#ea580c">{ow_counts.get("HIGH",0)}</div><div class="l">Élevés</div></div>'
    H += f'<div class="stat"><div class="v">{ow_counts.get("MEDIUM",0)}</div><div class="l">Moyens</div></div>'
    H += '</div>'

    # WAF + CMS quick info
    if ow_waf or ow_cms:
        H += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">'
        for tgt, waf_name in ow_waf.items():
            if waf_name:
                H += f'<span style="background:#f0fdf4;border:1px solid #86efac;border-radius:6px;padding:4px 10px;font-size:11px">🛡 WAF: <b>{waf_name}</b> ({tgt})</span>'
            else:
                H += f'<span style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:4px 10px;font-size:11px">⚠ Pas de WAF ({tgt})</span>'
        for tgt, cms_info in ow_cms.items():
            if isinstance(cms_info, dict):
                H += f'<span style="background:#eff6ff;border:1px solid #93c5fd;border-radius:6px;padding:4px 10px;font-size:11px">📦 CMS: <b>{cms_info.get("cms","")}</b> {cms_info.get("version","")}</span>'
        H += '</div>'

    # Catégories OWASP
    owasp_colors = {
        'A01': '#dc2626', 'A02': '#ea580c', 'A03': '#dc2626',
        'A05': '#ca8a04', 'A06': '#ea580c', 'A09': '#64748b',
    }
    if ow_by_cat:
        H += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;margin-bottom:12px">'
        for oid, cat_info in sorted(ow_by_cat.items()):
            c = cat_info.get('count', 0)
            sev = cat_info.get('severities', {})
            bc = owasp_colors.get(oid, '#64748b')
            has_crit = sev.get('CRITICAL', 0) > 0 or sev.get('HIGH', 0) > 0
            bg = '#fef2f2' if has_crit else '#fff7ed' if sev.get('MEDIUM', 0) > 0 else '#f8fafc'
            H += f'<div style="background:{bg};border:1px solid {bc}33;border-radius:8px;padding:10px;text-align:center">'
            H += f'<div style="font-size:11px;color:#64748b">{oid}</div>'
            H += f'<div style="font-size:10px;color:#94a3b8;margin-bottom:4px">{cat_info.get("label","")[:25]}</div>'
            H += f'<div style="font-size:22px;font-weight:800;color:{bc}">{c}</div>'
            badges = ""
            if sev.get('CRITICAL'): badges += f'<span class="badge b-c">{sev["CRITICAL"]}C</span> '
            if sev.get('HIGH'):     badges += f'<span class="badge b-h">{sev["HIGH"]}H</span> '
            if sev.get('MEDIUM'):   badges += f'<span class="badge b-m">{sev["MEDIUM"]}M</span> '
            H += f'<div style="margin-top:4px">{badges}</div></div>'
        H += '</div>'

    # Findings par catégorie OWASP (tableaux dépliables)
    owasp_label_full = {
        'A01': 'A01 — Broken Access Control',
        'A02': 'A02 — Cryptographic Failures',
        'A03': 'A03 — Injection',
        'A05': 'A05 — Security Misconfiguration',
        'A06': 'A06 — Vulnerable Components',
        'A09': 'A09 — Security Logging & Monitoring',
    }
    from collections import defaultdict as _dd
    findings_by_cat = _dd(list)
    for f in ow_findings:
        findings_by_cat[f.get('owasp_id', 'A?')].append(f)

    for oid in sorted(findings_by_cat.keys()):
        cat_findings = sorted(findings_by_cat[oid],
                              key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x.get('severity','LOW'), 9))
        crit_cnt = sum(1 for f in cat_findings if f.get('severity') in ('CRITICAL','HIGH'))
        details_open = 'open' if crit_cnt > 0 else ''
        H += f'<details {details_open}><summary style="cursor:pointer;font-weight:700;margin:8px 0 4px;font-size:13px">'
        H += f'<span style="color:{owasp_colors.get(oid,"#64748b")}">{owasp_label_full.get(oid,oid)}</span>'
        H += f' <span style="color:#64748b;font-weight:400">— {len(cat_findings)} finding(s)</span></summary>'
        H += '<table><tr><th>Cible</th><th>Sév.</th><th>Finding</th><th>Evidence</th><th>Recommandation</th></tr>'
        for f in cat_findings:
            bc = badge.get(f.get('severity',''), 'b-l')
            H += f"<tr><td><b>{f.get('target','')}</b></td>"
            H += f"<td><span class='badge {bc}'>{f.get('severity','')}</span></td>"
            H += f"<td>{f.get('finding','')[:100]}</td>"
            H += f"<td style='font-size:10px;color:#64748b'>{f.get('evidence','')[:80]}</td>"
            H += f"<td>{f.get('recommendation','')[:100]}</td></tr>"
        H += '</table></details>'

    H += '</div>'

# ══════════════ WEB TECH ══════════════
if ran('cve'):
    wt = D.get('cve',{}).get('web_technologies',{})
    if wt:
        H += '<div class="card" id="web-tech"><h2>🌍 Technologies Web</h2>'
        for url, techs in wt.items():
            H += f'<p><b>{url}</b>: '
            if isinstance(techs, list):
                H += ', '.join(f'<span class="badge b-i">{t}</span>' for t in techs[:10])
            else: H += str(techs)[:200]
            H += '</p>'
        H += '</div>'

# ══════════════ WIFI ══════════════
if ran('wifi'):
    nets = D.get('wifi',{}).get('networks',[])
    H += '<div class="card" id="wifi"><h2>📶 WiFi</h2>'
    if nets:
        H += '<table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Encryption</th><th>Signal</th></tr>'
        for n in nets:
            enc = n.get('encryption','')
            enc_badge = 'b-nok' if enc in ('WEP','OPEN','') else 'b-m' if 'WPA ' in enc else 'b-ok'
            H += f"<tr><td><b>{n.get('ssid','')}</b></td><td>{n.get('bssid','')}</td><td>{n.get('channel','')}</td><td><span class='badge {enc_badge}'>{enc}</span></td><td>{n.get('signal','')}</td></tr>"
        H += '</table>'
    else: H += '<p class="ok">✓ Aucun réseau détecté</p>'
    H += '</div>'

# ══════════════ HISTORIQUE & TENDANCES ══════════════
if history:
    H += '<div class="card" id="history"><h2>📈 Historique & Tendances</h2>'
    if trend:
        tc = {'improved':'#16a34a','degraded':'#dc2626','stable':'#ca8a04'}[trend['direction']]
        tl = {'improved':'↗ Amélioré','degraded':'↘ Dégradé','stable':'→ Stable'}[trend['direction']]
        H += f'<div style="text-align:center;margin-bottom:14px">'
        H += f'<div class="trend-card" style="background:{tc}11;color:{tc};border:2px solid {tc}">{tl} ({trend["delta_score"]:+d} pts)</div>'
        H += f'<p style="color:#64748b;font-size:11px;margin-top:4px">vs audit du {trend["prev_date"]} ({trend["prev_score"]}/100 → {score}/100)</p>'
        H += '</div>'

    # Timeline table
    all_audits = history + [{'timestamp': ts, 'risk_score': score, 'risk_level': level,
                             'total_issues': len(all_issues), 'severity_counts': dict(counts),
                             'version': '4.5', 'path': out}]
    H += '<table><tr><th>Date</th><th>Score</th><th>Niveau</th><th>Issues</th><th>Critiques</th><th>Élevées</th><th>Version</th></tr>'
    for a in all_audits:
        is_current = a.get('path', '') == out
        style = ' style="font-weight:700;background:#eff6ff"' if is_current else ''
        sc = a.get('severity_counts', {})
        H += f"<tr{style}><td>{a.get('timestamp','')}{' (actuel)' if is_current else ''}</td>"
        H += f"<td><b>{a.get('risk_score',0)}</b>/100</td><td>{a.get('risk_level','')}</td>"
        H += f"<td>{a.get('total_issues',0)}</td><td>{sc.get('CRITICAL',0)}</td><td>{sc.get('HIGH',0)}</td>"
        H += f"<td>v{a.get('version','?')}</td></tr>"
    H += '</table>'

    # Simple bar chart
    if len(all_audits) >= 2:
        H += '<div style="margin-top:12px"><h3 style="font-size:13px;margin-bottom:6px">Évolution du score</h3>'
        H += '<div style="display:flex;align-items:flex-end;gap:6px;height:120px;padding:4px">'
        max_s = max(a.get('risk_score',1) for a in all_audits)
        for a in all_audits:
            s = a.get('risk_score', 0)
            h = max(4, int(100 * s / max(max_s, 1)))
            c = '#dc2626' if s>=75 else '#ea580c' if s>=50 else '#ca8a04' if s>=25 else '#16a34a'
            is_current = a.get('path','') == out
            border = 'border:2px solid #1e293b;' if is_current else ''
            H += f'<div style="display:flex;flex-direction:column;align-items:center;flex:1">'
            H += f'<div style="font-size:10px;font-weight:700;color:{c}">{s}</div>'
            H += f'<div style="width:100%;height:{h}px;background:{c};border-radius:4px 4px 0 0;{border}"></div>'
            H += f'<div style="font-size:8px;color:#94a3b8;margin-top:2px">{a.get("timestamp","")[:8]}</div></div>'
        H += '</div></div>'
    H += '</div>'

# ══════════════ REMÉDIATION ══════════════
H += '<div class="card" id="remediation"><h2>Plan de Remédiation</h2><table>'
H += '<tr><th>#</th><th>Priorité</th><th>Action</th><th>Cible</th><th>Module</th></tr>'
for idx, i in enumerate(all_issues[:50], 1):
    H += f"<tr><td>{idx}</td><td><span class='badge {badge.get(i['severity'],'b-l')}'>{i['severity']}</span></td>"
    H += f"<td>{i.get('recommendation','')[:100] or i.get('issue','')[:100]}</td>"
    H += f"<td>{i.get('target','')}</td><td>{i.get('module','')}</td></tr>"
H += '</table></div>'

# ══════════════ SUGGESTIONS ══════════════
H += '<div class="card" id="suggestions"><h2>💡 Suggestions d\'amélioration</h2>'
suggestions = []
if not ran('wifi'): suggestions.append(('📶', 'Audit WiFi', 'Ajouter --wifi wlan0 pour scanner les réseaux sans fil'))
if not ran('email'): suggestions.append(('📧', 'Audit Email', 'Ajouter --domain votredomaine.ch pour SPF/DKIM/DMARC'))
if not ran('openvas') or ov_mode == 'degraded':
    suggestions.append(('🔍', 'OpenVAS', 'Installer GVM pour un scan de vulnérabilités complet'))
if not ran('ad'): suggestions.append(('🏰', 'Active Directory', 'Ajouter --dc IP pour un audit AD approfondi'))
if not ran('web_owasp'): suggestions.append(('🌐', 'Audit Web OWASP', 'Le module web_owasp n\'a pas tourné — relancer avec des hôtes web actifs'))

# Suggestions d'audit supplémentaires
suggestions.append(('🔐', 'Politique de mots de passe', 'Tester la robustesse des mots de passe AD avec CrackMapExec + wordlists'))
if not ran('web_owasp'):
    suggestions.append(('🌐', 'Test d\'intrusion web', 'Compléter avec un audit OWASP (Burp Suite, ZAP) sur les apps web identifiées'))
suggestions.append(('📱', 'Audit physique', 'Vérifier les accès physiques, ports USB exposés, imprimantes réseau'))
suggestions.append(('🛡️', 'Segmentation réseau', 'Valider l\'isolation des VLANs et les règles de pare-feu inter-segments'))
suggestions.append(('📋', 'Conformité', 'Évaluer la conformité RGPD, nLPD (Suisse), ISO 27001 selon le contexte client'))
suggestions.append(('🔄', 'Audit récurrent', 'Planifier un re-test trimestriel pour suivre l\'évolution via l\'historique'))

if suggestions:
    H += '<table><tr><th></th><th>Domaine</th><th>Recommandation</th></tr>'
    for icon, title, desc in suggestions:
        H += f'<tr><td style="font-size:18px">{icon}</td><td><b>{title}</b></td><td>{desc}</td></tr>'
    H += '</table>'
H += '</div>'

# ══════════════ FOOTER ══════════════
H += f'<div class="card" style="text-align:center;color:#94a3b8;font-size:11px;padding:14px">Rapport généré le {ts} — PME IT Audit Framework v4.5</div>'
H += '</div></body></html>'

with open(f'{out}/report/rapport_audit.html', 'w') as f:
    f.write(H)
print(f"Rapport: {out}/report/rapport_audit.html")
PYRPT

RC=$?
REPORT="$OUTPUT_DIR/report/rapport_audit.html"

if [[ $RC -ne 0 ]]; then
    error "Génération rapport ÉCHOUÉE (Python exit code $RC)"
    error "Relancer: bash scripts/generate_report.sh"
    exit 1
fi

if [[ ! -s "$REPORT" ]]; then
    error "Rapport HTML non créé ou vide"
    error "Vérifier les logs ci-dessus pour l'erreur Python"
    exit 1
fi

SIZE=$(stat -c%s "$REPORT" 2>/dev/null || echo 0)
if [[ "$SIZE" -lt 500 ]]; then
    error "Rapport HTML trop petit (${SIZE} bytes) — probable erreur"
    exit 1
fi

success "Rapport HTML généré ($SIZE bytes)"
log "$REPORT"
