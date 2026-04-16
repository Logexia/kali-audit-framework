#!/bin/bash
#============================================================================
# GENERATE_REPORT_DOCX: Rapport d'audit professionnel au format Word (.docx)
# v4.5.1 — python-docx, sections dynamiques selon modules exécutés,
#           inventaire réseau, AD, Email, SMB, DNS, SSL, OWASP, remédiation
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/report"

# ── Vérification / installation python-docx ────────────────────────────
if ! python3 -c "import docx" &>/dev/null 2>&1; then
    log "python-docx absent — installation..."
    if pip3 install python-docx --quiet 2>/dev/null || pip install python-docx --quiet 2>/dev/null; then
        success "python-docx installé"
    else
        warning "python-docx non disponible — rapport DOCX ignoré"
        exit 0
    fi
fi

if [[ ! -s "$OUT/consolidated.json" ]]; then
    warning "consolidated.json absent — rapport DOCX ignoré"
    exit 0
fi

log "Génération rapport DOCX..."

python3 << 'PY'
import json, os, sys
from datetime import datetime

try:
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
except ImportError as e:
    print(f"python-docx import error: {e}", file=sys.stderr); sys.exit(0)

# ── Données ───────────────────────────────────────────────────────────
output_dir = os.environ['OUTPUT_DIR']
D = json.load(open(f'{output_dir}/report/consolidated.json'))

score       = D.get('risk_score', 0)
risk_level  = D.get('risk_level', 'INCONNU')
client      = D.get('client', os.environ.get('CLIENT_NAME', 'Client'))
network     = D.get('network', os.environ.get('NETWORK', ''))
ts          = D.get('timestamp', datetime.now().strftime('%Y-%m-%d'))
domain      = D.get('domain', '')
hosts       = D.get('hosts', [])
all_issues  = D.get('issues', [])
modules_ran = set(D.get('modules_ran', []))
scoring     = D.get('scoring', {})
cats        = scoring.get('categories', {})
sev_counts  = D.get('severity_counts', {})
ad          = D.get('ad', {})
email_sec   = D.get('email_security', {})
smb_data    = D.get('smb', {})
dns_data    = D.get('dns', {})
ssl_data    = D.get('ssl', {})
snmp_data   = D.get('snmp', {})
wifi_data   = D.get('wifi', {})
openvas     = D.get('openvas', {})
exploit_data= D.get('exploitability', {})
web_owasp   = D.get('web_owasp', {})
trend       = D.get('trend')
cve_data    = D.get('cve', {})

def ran(key): return key in modules_ran

# ── Constantes couleurs ────────────────────────────────────────────────
SEV_COLOR = {
    'CRITICAL': RGBColor(0xDC, 0x26, 0x26),
    'HIGH':     RGBColor(0xEA, 0x58, 0x0C),
    'MEDIUM':   RGBColor(0xCA, 0x8A, 0x04),
    'LOW':      RGBColor(0x16, 0xA3, 0x4A),
    'INFO':     RGBColor(0x64, 0x74, 0x8B),
}
SEV_BG = {
    'CRITICAL': 'FECACA',
    'HIGH':     'FED7AA',
    'MEDIUM':   'FEF08A',
    'LOW':      'BBF7D0',
    'INFO':     'E2E8F0',
}
SCORE_COLOR = (
    'DC2626' if score >= 80 else
    'EA580C' if score >= 60 else
    'CA8A04' if score >= 30 else
    '16A34A'
)

# ── Helpers document ──────────────────────────────────────────────────
def set_cell_bg(cell, hex_color):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    # Supprimer ancien shd s'il existe
    for old in tcPr.findall(qn('w:shd')): tcPr.remove(old)
    shd = OxmlElement('w:shd')
    shd.set(qn('w:fill'), hex_color)
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:val'), 'clear')
    tcPr.append(shd)

def set_table_borders(table, color='CBD5E1', sz='4'):
    tbl = table._tbl
    tblPr = tbl.tblPr
    # Supprimer ancien tblBorders
    for old in tblPr.findall(qn('w:tblBorders')): tblPr.remove(old)
    borders = OxmlElement('w:tblBorders')
    for b in ('top','left','bottom','right','insideH','insideV'):
        el = OxmlElement(f'w:{b}')
        el.set(qn('w:val'), 'single')
        el.set(qn('w:sz'), sz)
        el.set(qn('w:space'), '0')
        el.set(qn('w:color'), color)
        borders.append(el)
    tblPr.append(borders)

def cell_text(cell, text, size=9, bold=False, color=None, align=None):
    cell.text = ''
    p = cell.paragraphs[0]
    if align: p.alignment = align
    run = p.add_run(str(text or ''))
    run.font.size = Pt(size)
    run.bold = bold
    if color: run.font.color.rgb = color

def header_row(table, headers, bg='1E293B', fg='FFFFFF', size=9):
    row = table.rows[0]
    fg_rgb = RGBColor(int(fg[:2],16), int(fg[2:4],16), int(fg[4:],16))
    for i, h in enumerate(headers):
        c = row.cells[i]
        c.text = ''
        run = c.paragraphs[0].add_run(h)
        run.bold = True
        run.font.size = Pt(size)
        run.font.color.rgb = fg_rgb
        set_cell_bg(c, bg)

def new_table(doc, headers, widths=None, border_color='CBD5E1'):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = 'Table Grid'
    set_table_borders(t, border_color)
    if widths:
        for i, w in enumerate(widths):
            t.columns[i].width = Cm(w)
    header_row(t, headers)
    return t

def sev_row(table, vals, sev_col=1):
    row = table.add_row()
    for i, v in enumerate(vals):
        cell_text(row.cells[i], v)
    sev = vals[sev_col] if sev_col < len(vals) else ''
    if sev in SEV_BG:
        set_cell_bg(row.cells[sev_col], SEV_BG[sev])
    return row

def h(doc, text, level=1):
    return doc.add_heading(text, level=level)

# ── Créer document ────────────────────────────────────────────────────
doc = Document()

# Marges
for sect in doc.sections:
    sect.top_margin    = Cm(2.0)
    sect.bottom_margin = Cm(2.0)
    sect.left_margin   = Cm(2.5)
    sect.right_margin  = Cm(2.0)

# Police par défaut
doc.styles['Normal'].font.name = 'Calibri'
doc.styles['Normal'].font.size = Pt(10)

# ══════════════════════════════════════════════════════════════════════
# PAGE DE TITRE
# ══════════════════════════════════════════════════════════════════════
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(48)
run = p.add_run('RAPPORT D\'AUDIT DE SÉCURITÉ')
run.bold = True; run.font.size = Pt(26)
run.font.color.rgb = RGBColor(0x1E, 0x29, 0x3B)

p2 = doc.add_paragraph()
p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
run2 = p2.add_run('Audit de sécurité du Système d\'Information')
run2.font.size = Pt(13); run2.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

doc.add_paragraph()

# Tableau métadonnées
t_meta = doc.add_table(rows=5, cols=2)
t_meta.style = 'Table Grid'
t_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_meta, '94A3B8')
meta_rows = [
    ('Client',    client),
    ('Réseau',    network or '—'),
    ('Domaine',   domain or '—'),
    ('Date',      ts[:10] if len(ts) >= 10 else ts),
    ('Framework', f"v{D.get('framework_version','4.5')} — Logexia Sàrl"),
]
for i, (k, v) in enumerate(meta_rows):
    r = t_meta.rows[i]
    cell_text(r.cells[0], k, size=11, bold=True)
    cell_text(r.cells[1], v, size=11)
    set_cell_bg(r.cells[0], 'F1F5F9')

doc.add_paragraph()

# Score global
p_sc = doc.add_paragraph()
p_sc.alignment = WD_ALIGN_PARAGRAPH.CENTER
run_sc = p_sc.add_run(f'Score de Risque Global : {score}/100 — {risk_level}')
run_sc.bold = True; run_sc.font.size = Pt(15)
run_sc.font.color.rgb = RGBColor(
    int(SCORE_COLOR[:2],16), int(SCORE_COLOR[2:4],16), int(SCORE_COLOR[4:],16))

doc.add_paragraph()

# Sévérités résumées
t_sv = doc.add_table(rows=1, cols=5)
t_sv.style = 'Table Grid'
t_sv.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_sv)
header_row(t_sv, ['CRITIQUE','ÉLEVÉ','MOYEN','FAIBLE','INFO'])
row_sv = t_sv.add_row()
for i, (sev, label) in enumerate([('CRITICAL',''),('HIGH',''),
                                    ('MEDIUM',''),('LOW',''),('INFO','')]):
    val = str(sev_counts.get(sev, 0))
    cell_text(row_sv.cells[i], val, size=14, bold=True,
              align=WD_ALIGN_PARAGRAPH.CENTER)
    set_cell_bg(row_sv.cells[i], SEV_BG[sev])

doc.add_paragraph()

# Confidentialité
p_conf = doc.add_paragraph()
p_conf.alignment = WD_ALIGN_PARAGRAPH.CENTER
rc = p_conf.add_run('CONFIDENTIEL — Réservé aux personnes habilitées')
rc.bold = True; rc.font.size = Pt(10)
rc.font.color.rgb = RGBColor(0xDC, 0x26, 0x26)

p_brand = doc.add_paragraph()
p_brand.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_brand.paragraph_format.space_before = Pt(16)
rb = p_brand.add_run('Logexia Sàrl — Audit & Sécurité — Suisse')
rb.font.size = Pt(9); rb.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)

doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 1. RÉSUMÉ EXÉCUTIF
# ══════════════════════════════════════════════════════════════════════
h(doc, '1. Résumé Exécutif')

p_intro = doc.add_paragraph()
p_intro.add_run(f"L'audit du réseau {network or client} a identifié ").font.size = Pt(10)
r_bold = p_intro.add_run(f"{D.get('total_issues',0)} vulnérabilités")
r_bold.bold = True; r_bold.font.size = Pt(10)
p_intro.add_run(f" sur {len(hosts)} hôtes actifs ({len([i for i in all_issues if i.get('severity')=='CRITICAL'])} critiques, "
                f"{len([i for i in all_issues if i.get('severity')=='HIGH'])} élevées).").font.size = Pt(10)

# Tendance
if trend:
    direction = trend.get('direction','')
    delta = trend.get('delta_score', 0)
    prev = trend.get('prev_score', 0)
    sym = '↘ Dégradation' if direction == 'degraded' else ('↗ Amélioration' if direction == 'improved' else '→ Stable')
    p_tr = doc.add_paragraph()
    r_tr = p_tr.add_run(f'{sym}: {delta:+d} pts vs audit précédent (score précédent: {prev}/100)')
    r_tr.font.size = Pt(10); r_tr.italic = True
    r_tr.font.color.rgb = SEV_COLOR.get('CRITICAL' if direction == 'degraded' else 'LOW',
                                         RGBColor(0,0,0))

doc.add_paragraph()

# Top findings
crit_high = [i for i in all_issues if i.get('severity') in ('CRITICAL','HIGH')][:10]
if crit_high:
    h(doc, 'Constats prioritaires', 2)
    t_top = new_table(doc, ['Sév.', 'Cible', 'Problème', 'Module'])
    for iss in crit_high:
        sev = iss.get('severity','')
        row = t_top.add_row()
        cell_text(row.cells[0], sev, bold=True, color=SEV_COLOR.get(sev))
        cell_text(row.cells[1], iss.get('target','')[:30])
        cell_text(row.cells[2], iss.get('issue','')[:90])
        cell_text(row.cells[3], iss.get('module',''))
        set_cell_bg(row.cells[0], SEV_BG.get(sev, 'E2E8F0'))

doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 2. SCORING PAR CATÉGORIE
# ══════════════════════════════════════════════════════════════════════
h(doc, '2. Scoring par Catégorie')

labels = {
    'infrastructure': 'Infrastructure réseau',
    'smb':  'SMB / Partages fichiers',
    'ad':   'Active Directory',
    'email':'Sécurité Email',
    'vulns':'Vulnérabilités (CVE)',
    'ssl':  'SSL/TLS',
    'wifi': 'WiFi',
    'snmp': 'SNMP',
    'dns':  'DNS',
}
if cats:
    t_sc2 = new_table(doc, ['Catégorie', 'Poids', 'Score/100', 'Issues', 'Niveau de risque'])
    for cat, cs in sorted(cats.items(), key=lambda x: -x[1].get('weight', 0)):
        pct = cs.get('pct', 0)
        iss_c = cs.get('issues', 0)
        sev_c = ('CRITICAL' if pct >= 80 else 'HIGH' if pct >= 60
                 else 'MEDIUM' if pct >= 30 else 'LOW')
        r_label = ('Critique' if pct >= 80 else 'Élevé' if pct >= 60
                   else 'Modéré' if pct >= 30 else 'Faible')
        row = t_sc2.add_row()
        cell_text(row.cells[0], labels.get(cat, cat.capitalize()))
        cell_text(row.cells[1], f"{cs.get('weight',0)}%", align=WD_ALIGN_PARAGRAPH.CENTER)
        cell_text(row.cells[2], str(pct), align=WD_ALIGN_PARAGRAPH.CENTER)
        cell_text(row.cells[3], str(iss_c), align=WD_ALIGN_PARAGRAPH.CENTER)
        cell_text(row.cells[4], r_label, bold=True)
        set_cell_bg(row.cells[4], SEV_BG.get(sev_c, 'E2E8F0'))

doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 3. INVENTAIRE RÉSEAU
# ══════════════════════════════════════════════════════════════════════
if ran('discovery') and hosts:
    h(doc, '3. Inventaire Réseau')

    p_inv = doc.add_paragraph()
    p_inv.add_run(f'{len(hosts)} hôtes actifs détectés').bold = True
    p_inv.add_run(f' sur le réseau {network}.').font.size = Pt(10)
    doc.add_paragraph()

    t_inv = new_table(doc, ['IP', 'Hostname', 'OS', 'Ports TCP ouverts', 'Ports UDP'])
    for host in hosts:
        tcp_s = ', '.join(
            str(p['port']) if isinstance(p, dict) else str(p)
            for p in host.get('tcp_ports', []))[:80] or '—'
        udp_s = ', '.join(
            str(p['port']) if isinstance(p, dict) else str(p)
            for p in host.get('udp_ports', []))[:50] or '—'
        row = t_inv.add_row()
        cell_text(row.cells[0], host.get('ip',''), bold=True)
        cell_text(row.cells[1], host.get('hostname','')[:28] or '—')
        cell_text(row.cells[2], host.get('os','')[:45] or '—')
        cell_text(row.cells[3], tcp_s, size=8)
        cell_text(row.cells[4], udp_s, size=8)

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 4. ACTIVE DIRECTORY
# ══════════════════════════════════════════════════════════════════════
if ran('ad') and ad.get('dc_ip'):
    h(doc, '4. Active Directory')

    p_dc = doc.add_paragraph()
    p_dc.add_run('DC : ').bold = True
    p_dc.add_run(f"{ad.get('dc_ip','')} | {ad.get('fqdn','')} | {ad.get('dc_os','')}")
    p_dc.runs[-1].font.size = Pt(10)

    p_ads = doc.add_paragraph()
    p_ads.add_run('Score AD : ').bold = True
    r_ads = p_ads.add_run(f"{ad.get('ad_score',0)}/100 — {ad.get('risk_level','')}")
    r_ads.font.size = Pt(11); r_ads.bold = True
    sc_ad = ad.get('ad_score', 0)
    sev_ad = 'CRITICAL' if sc_ad >= 80 else 'HIGH' if sc_ad >= 60 else 'MEDIUM' if sc_ad >= 30 else 'LOW'
    r_ads.font.color.rgb = SEV_COLOR.get(sev_ad, RGBColor(0,0,0))

    # Stats
    stats = ad.get('stats', {})
    doc.add_paragraph()
    t_adst = new_table(doc, ['Utilisateurs','Domain Admins','Inactifs >90j',
                               'Admins inactifs', 'Sans pré-auth Kerberos'])
    row_st = t_adst.add_row()
    for i, v in enumerate([stats.get('total_users','?'),
                            stats.get('domain_admins','?'),
                            stats.get('inactive_90d','?'),
                            len(stats.get('inactive_admins',[])) if isinstance(stats.get('inactive_admins',[]),list) else stats.get('inactive_admins','?'),
                            stats.get('no_preauth','?')]):
        cell_text(row_st.cells[i], str(v), size=12, bold=True,
                  align=WD_ALIGN_PARAGRAPH.CENTER)
    # Colorer les valeurs non-zéro en orange
    for i in range(1, 5):
        try:
            if int(str(row_st.cells[i].text)) > 0:
                set_cell_bg(row_st.cells[i], SEV_BG['MEDIUM'])
        except: pass

    # Findings AD
    ad_findings = [f for f in ad.get('findings', [])
                   if f.get('severity') in ('CRITICAL','HIGH','MEDIUM','LOW')]
    if ad_findings:
        doc.add_paragraph()
        h(doc, 'Findings Active Directory', 2)
        t_adf = new_table(doc, ['Catégorie', 'Sév.', 'Finding', 'Détail', 'Recommandation'])
        for f in sorted(ad_findings,
                        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9)):
            sev = f.get('severity','')
            row = t_adf.add_row()
            cell_text(row.cells[0], f.get('category','')[:20], size=8)
            cell_text(row.cells[1], sev, size=8, bold=True)
            cell_text(row.cells[2], f.get('title','')[:60], size=8)
            cell_text(row.cells[3], f.get('details','')[:60], size=8)
            cell_text(row.cells[4], f.get('recommendation','')[:60], size=8)
            set_cell_bg(row.cells[1], SEV_BG.get(sev, 'E2E8F0'))

    # Politique MDP
    pw = ad.get('password_policy', {})
    if pw:
        doc.add_paragraph()
        h(doc, 'Politique de mots de passe', 2)
        pw_labels = {
            'minPwdLength': 'Longueur minimale',
            'lockoutThreshold': 'Seuil de verrouillage',
            'pwdHistoryLength': 'Historique MDP',
            'complexity': 'Complexité requise',
        }
        t_pw = new_table(doc, ['Paramètre', 'Valeur'])
        for k, v in pw.items():
            row = t_pw.add_row()
            cell_text(row.cells[0], pw_labels.get(k, k))
            cell_text(row.cells[1], str(v))
            # Flag valeurs faibles
            if k == 'minPwdLength' and isinstance(v, int):
                if v < 8:   set_cell_bg(row.cells[1], SEV_BG['CRITICAL'])
                elif v < 12: set_cell_bg(row.cells[1], SEV_BG['MEDIUM'])
            if k == 'lockoutThreshold' and v == 0:
                set_cell_bg(row.cells[1], SEV_BG['HIGH'])

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 5. SÉCURITÉ EMAIL
# ══════════════════════════════════════════════════════════════════════
if ran('email') and email_sec.get('domain'):
    h(doc, '5. Sécurité Email')

    em_score = email_sec.get('email_score', 0)
    p_em = doc.add_paragraph()
    p_em.add_run(f"Domaine analysé : {email_sec.get('domain','')} | ").font.size = Pt(10)
    r_ems = p_em.add_run(f"Score : {em_score}/100 — {email_sec.get('risk_level','')}")
    r_ems.bold = True; r_ems.font.size = Pt(10)
    sev_em = 'CRITICAL' if em_score >= 80 else 'HIGH' if em_score >= 60 else 'MEDIUM' if em_score >= 30 else 'LOW'
    r_ems.font.color.rgb = SEV_COLOR.get(sev_em, RGBColor(0,0,0))

    doc.add_paragraph()
    spf    = email_sec.get('spf', {})
    dmarc  = email_sec.get('dmarc', {})
    dkim   = email_sec.get('dkim', {})
    tls    = email_sec.get('starttls', {})
    extras = email_sec.get('extras', {})

    t_em = new_table(doc, ['Mécanisme', 'Statut', 'Détails'])
    em_rows = [
        ('SPF',
         ('OK' if spf.get('exists') and spf.get('policy','').startswith('-') else
          'Partiel' if spf.get('exists') else 'Absent'),
         spf.get('record','')[:70] or f"Policy: {spf.get('policy','—')}"),
        ('DMARC',
         ('OK' if dmarc.get('policy') in ('quarantine','reject') else
          'Partiel' if dmarc.get('exists') else 'Absent'),
         f"Policy: {dmarc.get('policy','—')} | rua: {dmarc.get('rua','—')[:30]}"),
        ('DKIM',
         (f"{dkim.get('selectors_found',0)} sélecteur(s)" if dkim.get('selectors_found',0) > 0 else 'Non trouvé'),
         ''),
        ('STARTTLS',
         'OK' if tls.get('ok') else 'Absent',
         tls.get('mx_primary','')[:40]),
        ('MTA-STS',  'OK' if extras.get('mta_sts') else 'Non configuré', ''),
        ('DANE/TLSA','OK' if extras.get('dane')    else 'Non configuré', ''),
        ('BIMI',     'OK' if extras.get('bimi')    else 'Non configuré', ''),
    ]
    for name, status, detail in em_rows:
        row = t_em.add_row()
        cell_text(row.cells[0], name, bold=True)
        cell_text(row.cells[1], status)
        cell_text(row.cells[2], detail, size=8)
        bg = ('BBF7D0' if status == 'OK'
              else 'FECACA' if status == 'Absent'
              else 'FEF08A' if status == 'Partiel'
              else 'F1F5F9')
        set_cell_bg(row.cells[1], bg)

    # Findings email
    em_findings = [f for f in email_sec.get('findings', [])
                   if f.get('severity') in ('CRITICAL','HIGH','MEDIUM','LOW')]
    if em_findings:
        doc.add_paragraph()
        h(doc, 'Issues Email', 2)
        t_emf = new_table(doc, ['Sév.', 'Finding', 'Recommandation'])
        for f in sorted(em_findings,
                        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9)):
            sev = f.get('severity','')
            row = t_emf.add_row()
            cell_text(row.cells[0], sev, bold=True)
            cell_text(row.cells[1], f.get('title', f.get('issue',''))[:80])
            cell_text(row.cells[2], f.get('recommendation','')[:80], size=8)
            set_cell_bg(row.cells[0], SEV_BG.get(sev,'E2E8F0'))

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 6. VULNÉRABILITÉS (CVE + OpenVAS)
# ══════════════════════════════════════════════════════════════════════
if ran('cve') or ran('openvas'):
    h(doc, '6. Vulnérabilités')

    total_cves = cve_data.get('total_cves', 0) + openvas.get('total_cves', 0)
    p_v = doc.add_paragraph()
    p_v.add_run(f'{total_cves} CVE identifiées').bold = True
    p_v.add_run(f' | OpenVAS: {openvas.get("total_vulns",0)} vulnérabilités '
                f'sur {openvas.get("hosts_scanned",0)} hôtes.').font.size = Pt(10)

    # Top issues CVE/OpenVAS
    vuln_issues = sorted(
        [i for i in all_issues if i.get('module') in ('cve','openvas')],
        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x.get('severity','INFO'),9)
    )[:50]

    if vuln_issues:
        doc.add_paragraph()
        h(doc, 'Issues CVE', 2)
        t_vi = new_table(doc, ['Cible', 'Sév.', 'Problème', 'Recommandation'])
        for iss in vuln_issues:
            sev = iss.get('severity','')
            row = t_vi.add_row()
            cell_text(row.cells[0], iss.get('target','')[:25], bold=True)
            cell_text(row.cells[1], sev, bold=True)
            cell_text(row.cells[2], iss.get('issue','')[:80], size=8)
            cell_text(row.cells[3], iss.get('recommendation','')[:80], size=8)
            set_cell_bg(row.cells[1], SEV_BG.get(sev,'E2E8F0'))

    # OpenVAS — top 30 par CVSS
    all_ov = sorted(openvas.get('all_vulns', []), key=lambda x: -x.get('cvss', 0))[:30]
    if all_ov:
        doc.add_paragraph()
        h(doc, 'OpenVAS — Top 30 par CVSS', 2)
        t_ov = new_table(doc, ['Hôte', 'CVSS', 'Sév.', 'Vulnérabilité', 'Exploit'])
        for v in all_ov:
            sev = v.get('severity','')
            row = t_ov.add_row()
            cell_text(row.cells[0], v.get('host','')[:20], bold=True)
            cell_text(row.cells[1], str(v.get('cvss','')),
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            cell_text(row.cells[2], sev, bold=True)
            cell_text(row.cells[3], v.get('name','')[:80], size=8)
            cell_text(row.cells[4], 'Oui' if v.get('has_exploit') else '—',
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            set_cell_bg(row.cells[2], SEV_BG.get(sev,'E2E8F0'))
            if v.get('has_exploit'):
                set_cell_bg(row.cells[4], SEV_BG['HIGH'])

    # Exploitabilité
    ecves = exploit_data.get('exploitable_cves', [])
    if ecves:
        doc.add_paragraph()
        h(doc, 'CVE Exploitables', 2)
        p_ex = doc.add_paragraph()
        p_ex.add_run(f"{exploit_data.get('with_public_exploit',0)} exploits publics | "
                     f"{exploit_data.get('with_msf_module',0)} modules Metasploit").font.size = Pt(10)
        doc.add_paragraph()
        t_ex = new_table(doc, ['CVE', 'CVSS', 'Hôtes', 'Service', 'Exploit', 'MSF'])
        for e in ecves[:25]:
            row = t_ex.add_row()
            cell_text(row.cells[0], e.get('cve',''), bold=True)
            cell_text(row.cells[1], str(e.get('cvss','')),
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            cell_text(row.cells[2], ', '.join(e.get('hosts',[])[:3])[:30], size=8)
            cell_text(row.cells[3], e.get('service','')[:30], size=8)
            cell_text(row.cells[4], 'Oui' if e.get('exploit_public') else '—',
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            cell_text(row.cells[5], 'Oui' if e.get('msf_available') else '—',
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            if e.get('exploit_public'): set_cell_bg(row.cells[4], SEV_BG['HIGH'])
            if e.get('msf_available'): set_cell_bg(row.cells[5], SEV_BG['MEDIUM'])

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 7. AUDIT SMB
# ══════════════════════════════════════════════════════════════════════
if ran('smb'):
    h(doc, '7. Audit SMB')

    shares_inv = smb_data.get('shares_inventory', {})
    smb_issues = [i for i in all_issues if i.get('module') == 'smb']
    total_sh   = sum(len(v) for v in shares_inv.values())
    accessible = sum(1 for lst in shares_inv.values()
                     for s in lst if s.get('permissions',''))

    p_smb = doc.add_paragraph()
    p_smb.add_run(f'{smb_data.get("total",len(shares_inv))} hôtes SMB | ').font.size = Pt(10)
    p_smb.add_run(f'{total_sh} shares listés').bold = True
    p_smb.add_run(f' | ').font.size = Pt(10)
    r_acc = p_smb.add_run(f'{accessible} accessibles anonymement')
    r_acc.bold = True; r_acc.font.size = Pt(10)
    if accessible > 0: r_acc.font.color.rgb = SEV_COLOR['HIGH']

    if shares_inv:
        doc.add_paragraph()
        h(doc, 'Inventaire des partages', 2)
        t_sh = new_table(doc, ['IP', 'Share', 'Accès anonyme', 'Commentaire'])
        for ip, sh_list in sorted(shares_inv.items()):
            for sh in sh_list:
                p_val = sh.get('permissions','') or '—'
                row = t_sh.add_row()
                cell_text(row.cells[0], ip, bold=True)
                cell_text(row.cells[1], sh.get('name',''))
                cell_text(row.cells[2], p_val, bold='—' not in p_val)
                cell_text(row.cells[3], sh.get('comment','')[:50], size=8)
                if 'WRITE' in p_val:
                    set_cell_bg(row.cells[2], SEV_BG['HIGH'])
                elif 'READ' in p_val:
                    set_cell_bg(row.cells[2], SEV_BG['MEDIUM'])

    if smb_issues:
        doc.add_paragraph()
        h(doc, 'Issues SMB', 2)
        t_si = new_table(doc, ['Cible', 'Sév.', 'Problème', 'Recommandation'])
        for iss in sorted(smb_issues,
                          key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9)):
            sev = iss.get('severity','')
            row = t_si.add_row()
            cell_text(row.cells[0], iss.get('target','')[:25], bold=True)
            cell_text(row.cells[1], sev, bold=True)
            cell_text(row.cells[2], iss.get('issue','')[:80])
            cell_text(row.cells[3], iss.get('recommendation','')[:80], size=8)
            set_cell_bg(row.cells[1], SEV_BG.get(sev,'E2E8F0'))

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 8. DNS
# ══════════════════════════════════════════════════════════════════════
if ran('dns'):
    h(doc, '8. Audit DNS')

    dns_issues = [i for i in all_issues if i.get('module') == 'dns']
    p_dns = doc.add_paragraph()
    p_dns.add_run(f"Domaine : {dns_data.get('domain','—')} | ").font.size = Pt(10)
    dnssec = dns_data.get('dnssec', False)
    r_dnssec = p_dns.add_run(f"DNSSEC : {'Configuré' if dnssec else 'Non configuré'}")
    r_dnssec.font.size = Pt(10); r_dnssec.bold = True
    r_dnssec.font.color.rgb = SEV_COLOR['LOW' if dnssec else 'MEDIUM']
    p_dns.add_run(f" | {dns_data.get('records_found',0)} enregistrements").font.size = Pt(10)

    if dns_issues:
        doc.add_paragraph()
        t_dns = new_table(doc, ['Cible', 'Sév.', 'Problème', 'Recommandation'])
        for iss in sorted(dns_issues,
                          key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9)):
            sev = iss.get('severity','')
            row = t_dns.add_row()
            cell_text(row.cells[0], iss.get('target','')[:30], bold=True)
            cell_text(row.cells[1], sev, bold=True)
            cell_text(row.cells[2], iss.get('issue','')[:80])
            cell_text(row.cells[3], iss.get('recommendation','')[:80], size=8)
            set_cell_bg(row.cells[1], SEV_BG.get(sev,'E2E8F0'))
    else:
        doc.add_paragraph('Aucun problème DNS critique détecté.').runs[0].italic = True

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 9. SSL / TLS
# ══════════════════════════════════════════════════════════════════════
if ran('ssl'):
    h(doc, '9. SSL/TLS')

    ssl_issues      = [i for i in all_issues if i.get('module') == 'ssl']
    targets_detail  = ssl_data.get('targets_detail', {})

    p_ssl = doc.add_paragraph(f"{ssl_data.get('targets',0)} cibles testées | {len(ssl_issues)} issues SSL/TLS.")
    p_ssl.runs[0].font.size = Pt(10)

    # Certificats
    if targets_detail:
        doc.add_paragraph()
        h(doc, 'Certificats', 2)
        t_cert = new_table(doc, ['Hôte:Port', 'Sujet', 'Expiration', 'Jours restants'])
        for host_port, det in list(targets_detail.items())[:20]:
            days = det.get('cert_days_remaining', '')
            row = t_cert.add_row()
            cell_text(row.cells[0], host_port[:35], bold=True)
            cell_text(row.cells[1], det.get('cert_subject','')[:45], size=8)
            cell_text(row.cells[2], det.get('validity','')[:20], size=8)
            cell_text(row.cells[3], str(days) if days != '' else '—',
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            if isinstance(days, int):
                if days < 0:    set_cell_bg(row.cells[3], SEV_BG['CRITICAL'])
                elif days < 30: set_cell_bg(row.cells[3], SEV_BG['HIGH'])
                elif days < 90: set_cell_bg(row.cells[3], SEV_BG['MEDIUM'])

    # Issues SSL
    if ssl_issues:
        doc.add_paragraph()
        h(doc, 'Vulnérabilités SSL/TLS', 2)
        t_ssl = new_table(doc, ['Cible', 'Sév.', 'Problème', 'Recommandation'])
        for iss in sorted(ssl_issues,
                          key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x.get('severity','LOW'),9))[:40]:
            sev = iss.get('severity','')
            row = t_ssl.add_row()
            cell_text(row.cells[0], iss.get('target','')[:30], bold=True)
            cell_text(row.cells[1], sev, bold=True)
            cell_text(row.cells[2], iss.get('issue','')[:80])
            cell_text(row.cells[3], iss.get('recommendation','')[:80], size=8)
            set_cell_bg(row.cells[1], SEV_BG.get(sev,'E2E8F0'))

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 10. WEB — OWASP TOP 10 2021
# ══════════════════════════════════════════════════════════════════════
if ran('web_owasp') and web_owasp.get('mode') == 'executed':
    h(doc, '10. Audit Web — OWASP Top 10 2021')

    wo_counts = web_owasp.get('counts', {})
    p_wo = doc.add_paragraph()
    p_wo.add_run(f"{web_owasp.get('targets_scanned',0)} URL analysées | ").font.size = Pt(10)
    p_wo.add_run(f"C:{wo_counts.get('CRITICAL',0)} H:{wo_counts.get('HIGH',0)} "
                 f"M:{wo_counts.get('MEDIUM',0)} L:{wo_counts.get('LOW',0)}").font.size = Pt(10)

    # WAF / CMS
    waf = web_owasp.get('waf_detected', {})
    cms = web_owasp.get('cms_detected', {})
    waf_det  = [f"{u}: {w}" for u, w in waf.items() if w]
    cms_det  = [f"{u}: {c.get('cms','')} {c.get('version','')}" for u, c in cms.items()]
    if waf_det or cms_det:
        p_wc = doc.add_paragraph()
        if waf_det:
            p_wc.add_run('WAF : ').bold = True
            p_wc.add_run(', '.join(waf_det[:5])).font.size = Pt(10)
        if cms_det:
            p_wc.add_run(' | CMS : ').bold = True
            p_wc.add_run(', '.join(cms_det[:5])).font.size = Pt(10)

    # Par catégorie OWASP
    by_cat = web_owasp.get('by_owasp_category', {})
    if by_cat:
        doc.add_paragraph()
        h(doc, 'Résultats par catégorie OWASP', 2)
        t_owasp = new_table(doc, ['ID', 'Catégorie OWASP', 'Findings', 'Sév. max.'])
        for oid, odata in sorted(by_cat.items()):
            sev_d = odata.get('severities', {})
            max_sev = next(
                (s for s in ('CRITICAL','HIGH','MEDIUM','LOW') if sev_d.get(s,0) > 0),
                'INFO')
            row = t_owasp.add_row()
            cell_text(row.cells[0], oid, bold=True)
            cell_text(row.cells[1], odata.get('label','')[:55])
            cell_text(row.cells[2], str(odata.get('count',0)),
                      align=WD_ALIGN_PARAGRAPH.CENTER)
            cell_text(row.cells[3], max_sev, bold=True)
            set_cell_bg(row.cells[3], SEV_BG.get(max_sev,'E2E8F0'))

    # Findings OWASP détail
    owasp_findings = web_owasp.get('owasp_findings', [])
    if owasp_findings:
        doc.add_paragraph()
        h(doc, 'Findings détaillés', 2)
        t_owf = new_table(doc, ['ID', 'Cible', 'Sév.', 'Finding', 'Recommandation'])
        for f in sorted(owasp_findings,
                        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x.get('severity','INFO'),9))[:40]:
            sev = f.get('severity','')
            row = t_owf.add_row()
            cell_text(row.cells[0], f.get('owasp_id',''), bold=True)
            cell_text(row.cells[1], f.get('target','')[:25], size=8)
            cell_text(row.cells[2], sev, bold=True)
            cell_text(row.cells[3], f.get('finding','')[:70], size=8)
            cell_text(row.cells[4], f.get('recommendation','')[:70], size=8)
            set_cell_bg(row.cells[2], SEV_BG.get(sev,'E2E8F0'))

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 11. SNMP
# ══════════════════════════════════════════════════════════════════════
if ran('snmp') and snmp_data.get('devices'):
    h(doc, '11. Audit SNMP')

    devices     = snmp_data.get('devices', [])
    write_hosts = snmp_data.get('write_access_hosts', [])

    p_sn = doc.add_paragraph(f"{len(devices)} équipements SNMP | "
                              f"Write access : {len(write_hosts)}")
    p_sn.runs[0].font.size = Pt(10)

    if write_hosts:
        p_wr = doc.add_paragraph()
        r_wr = p_wr.add_run(f'WRITE ACCESS détecté : {", ".join(write_hosts)}')
        r_wr.bold = True; r_wr.font.size = Pt(10)
        r_wr.font.color.rgb = SEV_COLOR['CRITICAL']

    doc.add_paragraph()
    t_sn = new_table(doc, ['IP', 'Description', 'Communautés SNMP', 'Accès écriture'])
    for d in devices:
        row = t_sn.add_row()
        cell_text(row.cells[0], d.get('ip',''), bold=True)
        cell_text(row.cells[1],
                  (d.get('description','') or d.get('os_guess',''))[:55], size=8)
        cell_text(row.cells[2], ', '.join(d.get('communities',[]))[:35])
        cell_text(row.cells[3], 'OUI' if d.get('write_access') else '—',
                  align=WD_ALIGN_PARAGRAPH.CENTER)
        if d.get('write_access'):
            set_cell_bg(row.cells[3], SEV_BG['CRITICAL'])

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# 12. WIFI
# ══════════════════════════════════════════════════════════════════════
if ran('wifi') and wifi_data.get('networks'):
    h(doc, '12. Audit WiFi')

    networks = wifi_data.get('networks', [])
    open_nets = [n for n in networks if not n.get('encryption') or n.get('encryption') in ('OPEN','')]
    wep_nets  = [n for n in networks if n.get('encryption','') == 'WEP']

    p_wf = doc.add_paragraph(f"{len(networks)} réseaux détectés | "
                              f"{len(open_nets)} ouverts | {len(wep_nets)} WEP")
    p_wf.runs[0].font.size = Pt(10)
    if open_nets:
        r_op = p_wf.add_run(f' — {len(open_nets)} réseau(x) OUVERT(S) !')
        r_op.bold = True; r_op.font.color.rgb = SEV_COLOR['CRITICAL']

    doc.add_paragraph()
    t_wf = new_table(doc, ['SSID', 'BSSID', 'Canal', 'Chiffrement', 'Signal (dBm)'])
    for n in sorted(networks, key=lambda x: str(x.get('signal','')), reverse=True):
        enc = n.get('encryption','OPEN') or 'OPEN'
        row = t_wf.add_row()
        cell_text(row.cells[0], n.get('ssid','[Masqué]')[:35])
        cell_text(row.cells[1], n.get('bssid','')[:17], size=8)
        cell_text(row.cells[2], str(n.get('channel','')),
                  align=WD_ALIGN_PARAGRAPH.CENTER)
        cell_text(row.cells[3], enc, bold=enc in ('OPEN','WEP',''))
        cell_text(row.cells[4], str(n.get('signal','')),
                  align=WD_ALIGN_PARAGRAPH.CENTER)
        if enc in ('OPEN', ''):   set_cell_bg(row.cells[3], SEV_BG['CRITICAL'])
        elif enc == 'WEP':        set_cell_bg(row.cells[3], SEV_BG['HIGH'])
        elif enc.startswith('WPA2'): set_cell_bg(row.cells[3], SEV_BG['INFO'])

    doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════
# PLAN DE REMÉDIATION
# ══════════════════════════════════════════════════════════════════════
h(doc, 'Plan de Remédiation Prioritaire')

p_rem = doc.add_paragraph(
    'Actions classées par sévérité. Les éléments CRITIQUES et ÉLEVÉS '
    'doivent être traités en priorité absolue.')
p_rem.runs[0].font.size = Pt(10); p_rem.runs[0].italic = True
doc.add_paragraph()

rem_issues = sorted(
    all_issues,
    key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x.get('severity','INFO'),9)
)[:60]

if rem_issues:
    t_rem = new_table(doc, ['#', 'Sév.', 'Module', 'Cible', 'Problème', 'Action recommandée'])
    for n_i, iss in enumerate(rem_issues, 1):
        sev = iss.get('severity','')
        row = t_rem.add_row()
        cell_text(row.cells[0], str(n_i), align=WD_ALIGN_PARAGRAPH.CENTER)
        cell_text(row.cells[1], sev, bold=True)
        cell_text(row.cells[2], iss.get('module','')[:12], size=8)
        cell_text(row.cells[3], iss.get('target','')[:25], bold=True, size=8)
        cell_text(row.cells[4], iss.get('issue','')[:80], size=8)
        cell_text(row.cells[5], iss.get('recommendation','')[:90], size=8)
        set_cell_bg(row.cells[1], SEV_BG.get(sev,'E2E8F0'))

# ══════════════════════════════════════════════════════════════════════
# PIED DE PAGE FINAL
# ══════════════════════════════════════════════════════════════════════
doc.add_paragraph()
p_foot = doc.add_paragraph()
p_foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
r_foot = p_foot.add_run(
    f'Logexia Sàrl — Rapport d\'audit — {ts[:10]} — CONFIDENTIEL')
r_foot.font.size = Pt(8)
r_foot.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)

# ══════════════════════════════════════════════════════════════════════
# SAUVEGARDE
# ══════════════════════════════════════════════════════════════════════
out_path = f'{output_dir}/report/rapport_audit.docx'
doc.save(out_path)
size_kb = round(os.path.getsize(out_path) / 1024)
print(f"Rapport DOCX: {out_path} ({size_kb} Ko)")
PY

RC=$?
if [[ $RC -ne 0 ]]; then error "Génération DOCX ÉCHOUÉE (code $RC)"; exit 1; fi
if [[ ! -s "$OUTPUT_DIR/report/rapport_audit.docx" ]]; then error "rapport_audit.docx vide"; exit 1; fi
success "Rapport DOCX: $OUTPUT_DIR/report/rapport_audit.docx"
