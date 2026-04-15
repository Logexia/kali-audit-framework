#!/bin/bash
#============================================================================
# MODULE 09 — WEB AUDIT OWASP TOP 10 2021 v4.5
#
#   A01: Broken Access Control  (gobuster/feroxbuster, sensitive files,
#                                directory listing, admin interfaces)
#   A02: Cryptographic Failures (cookies sans Secure/HttpOnly, login HTTP,
#                                HSTS manquant)
#   A03: Injection              (sqlmap detection-only, paramètres reflétés)
#   A05: Security Misconfiguration (headers manquants, méthodes HTTP,
#                                   version serveur exposée)
#   A06: Vulnerable Components  (whatweb, wpscan, PHP obsolète, CMS)
#   A09: Sec. Logging & Monitoring (wafw00f WAF detection)
#
#   Cibles: web_hosts du module Discovery + --urls FILE (URLS_FILE)
#   Sorties: web_owasp/{hosts/{slug}/,sensitive_files.json,
#             security_headers.json,summary.json}
#============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/web_owasp"
mkdir -p "$OUT/hosts"

log "Module 09 — Web Audit OWASP Top 10"

# ══════════════════════════════════════════════════════════════════════════
# CIBLES WEB
# ══════════════════════════════════════════════════════════════════════════
TARGETS_FILE="$OUT/targets.txt"
> "$TARGETS_FILE"

# Depuis discovery/summary.json (web_hosts = IPs avec port 80/443 ouverts)
DISC_SUMMARY="$OUTPUT_DIR/discovery/summary.json"
if [[ -f "$DISC_SUMMARY" ]]; then
    python3 - >> "$TARGETS_FILE" 2>/dev/null << 'PYTGT'
import json, os, sys
try:
    d = json.load(open(os.environ['OUTPUT_DIR'] + '/discovery/summary.json'))
    hosts = {h['ip']: h for h in d.get('hosts', [])}
    for ip in d.get('web_hosts', []):
        h = hosts.get(ip, {})
        tcp = []
        for p in h.get('tcp_ports', []):
            if isinstance(p, int): tcp.append(p)
            elif isinstance(p, dict): tcp.append(p.get('port', 0))
        http_ports  = [po for po in tcp if po in (80, 8080, 8000, 8008, 8888)]
        https_ports = [po for po in tcp if po in (443, 8443, 4443)]
        if http_ports:
            for po in http_ports:
                print(f'http://{ip}' if po == 80 else f'http://{ip}:{po}')
        if https_ports:
            for po in https_ports:
                print(f'https://{ip}' if po == 443 else f'https://{ip}:{po}')
        if not http_ports and not https_ports:
            print(f'http://{ip}')
            print(f'https://{ip}')
except Exception as e:
    sys.stderr.write(f'[!] discovery parse: {e}\n')
PYTGT
fi

# Depuis URLS_FILE si fourni
if [[ -n "${URLS_FILE:-}" && -f "$URLS_FILE" ]]; then
    grep -v '^#' "$URLS_FILE" | grep -v '^[[:space:]]*$' >> "$TARGETS_FILE" || true
fi

# Dédupliquer
sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
mapfile -t ALL_TARGETS < "$TARGETS_FILE"

if [[ ${#ALL_TARGETS[@]} -eq 0 ]]; then
    warning "Aucune cible web — module sauté"
    cat > "$OUT/summary.json" << 'SKIP'
{"mode":"skipped","reason":"Aucune cible web détectée (discovery non exécuté ou aucun port HTTP/HTTPS ouvert)","targets_scanned":0,"owasp_findings":[],"security_headers_summary":{},"waf_detected":{},"cms_detected":{},"issues":[],"counts":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}}
SKIP
    exit 0
fi

log "Cibles web: ${#ALL_TARGETS[@]}"

# ══════════════════════════════════════════════════════════════════════════
# VÉRIFICATION OUTILS
# ══════════════════════════════════════════════════════════════════════════
HAS_GOBUSTER=0; HAS_FEROX=0; HAS_WHATWEB=0
HAS_WAFW00F=0; HAS_WPSCAN=0; HAS_SQLMAP=0

command -v gobuster    &>/dev/null && HAS_GOBUSTER=1 && success "gobuster"    || warning "gobuster absent (apt install gobuster)"
command -v feroxbuster &>/dev/null && HAS_FEROX=1    && success "feroxbuster" || true
command -v whatweb     &>/dev/null && HAS_WHATWEB=1  && success "whatweb"     || warning "whatweb absent"
command -v wafw00f     &>/dev/null && HAS_WAFW00F=1  && success "wafw00f"     || warning "wafw00f absent"
command -v wpscan      &>/dev/null && HAS_WPSCAN=1   && success "wpscan"      || warning "wpscan absent"
command -v sqlmap      &>/dev/null && HAS_SQLMAP=1   && success "sqlmap"      || warning "sqlmap absent"

# Wordlist pour dirbusting
WORDLIST="/usr/share/wordlists/dirb/common.txt"
[[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/dirb/wordlists/common.txt"
[[ ! -f "$WORDLIST" ]] && { warning "Wordlist dirb introuvable — dirbusting limité"; WORDLIST=""; }

# ══════════════════════════════════════════════════════════════════════════
# LISTES DE CHEMINS SENSIBLES
# ══════════════════════════════════════════════════════════════════════════
SENSITIVE_PATHS=(
    "/.git/config" "/.git/HEAD" "/.git/COMMIT_EDITMSG"
    "/.env" "/.env.local" "/.env.backup" "/.env.production" "/.env.staging"
    "/backup.zip" "/backup.tar.gz" "/backup.sql" "/dump.sql" "/db.sql"
    "/wp-config.php" "/wp-config.php.bak" "/wp-config.php.old" "/wp-config.bak"
    "/phpinfo.php" "/info.php" "/test.php" "/debug.php" "/check.php"
    "/server-status" "/server-info" "/.DS_Store" "/.htaccess"
    "/config.php" "/config.inc.php" "/configuration.php" "/settings.php"
    "/web.config" "/crossdomain.xml" "/clientaccesspolicy.xml"
    "/elmah.axd" "/trace.axd" "/WebResource.axd" "/ScriptResource.axd"
    "/id_rsa" "/id_rsa.pub" "/id_dsa" "/.ssh/authorized_keys"
    "/.bash_history" "/.bashrc" "/etc/passwd"
)

ADMIN_PATHS=(
    "/admin" "/admin/" "/admin/login" "/admin/login.php"
    "/wp-admin" "/wp-admin/" "/wp-login.php"
    "/phpmyadmin" "/phpmyadmin/" "/pma" "/pma/"
    "/mysql" "/adminer.php" "/adminer" "/dbadmin"
    "/manager" "/manager/html" "/administrator" "/webadmin"
    "/panel" "/cpanel" "/whm" "/plesk"
    "/console" "/webconsole"
    "/actuator" "/actuator/env" "/actuator/health" "/actuator/mappings"
    "/_ah/admin" "/__admin" "/solr/admin" "/jmx-console"
    "/jenkins" "/grafana" "/kibana" "/portainer"
)

# ══════════════════════════════════════════════════════════════════════════
# SCAN PAR CIBLE
# ══════════════════════════════════════════════════════════════════════════
LIVE_TARGETS=()

for TARGET_URL in "${ALL_TARGETS[@]}"; do
    # Slug lisible pour le répertoire
    HOST_SLUG=$(echo "$TARGET_URL" | sed 's|://|__|' | sed 's|[/:]|_|g' | sed 's|_*$||')
    HOST_DIR="$OUT/hosts/$HOST_SLUG"
    mkdir -p "$HOST_DIR/sqlmap"

    # Sauvegarder l'URL réelle pour reconstruction Python
    echo "$TARGET_URL" > "$HOST_DIR/target_url.txt"

    # ── Alive check ──────────────────────────────────────────────────────
    HTTP_CODE=$(curl -sk --max-time 10 --connect-timeout 6 \
        -o /dev/null -w '%{http_code}' "$TARGET_URL" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "000" ]]; then
        log "  $TARGET_URL → non répondant (skip)"
        continue
    fi
    log "  $TARGET_URL → HTTP $HTTP_CODE"
    LIVE_TARGETS+=("$TARGET_URL")

    # ── A05/A02: Headers + Body ───────────────────────────────────────────
    log "  [A05/A02] Headers: $TARGET_URL"
    curl -sk --max-time 20 --connect-timeout 6 \
        -D "$HOST_DIR/headers_raw.txt" \
        -o "$HOST_DIR/body_sample.html" \
        -L --max-redirs 3 \
        -A "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
        "$TARGET_URL" 2>/dev/null || true

    # Test méthodes HTTP dangereuses (A05)
    > "$HOST_DIR/methods.txt"
    for METHOD in TRACE PUT DELETE; do
        CODE=$(curl -sk --max-time 8 --connect-timeout 5 \
            -o /dev/null -w '%{http_code}' \
            -X "$METHOD" "$TARGET_URL" 2>/dev/null || echo "000")
        echo "${METHOD}:${CODE}" >> "$HOST_DIR/methods.txt"
    done

    # ── A01: Fichiers sensibles ───────────────────────────────────────────
    log "  [A01] Fichiers sensibles: $TARGET_URL"
    > "$HOST_DIR/sensitive_hits.txt"
    for PATH_CHK in "${SENSITIVE_PATHS[@]}" "${ADMIN_PATHS[@]}"; do
        CODE=$(curl -sk --max-time 8 --connect-timeout 5 \
            -o /dev/null -w '%{http_code}' \
            "${TARGET_URL}${PATH_CHK}" 2>/dev/null || echo "000")
        if [[ "$CODE" == "200" || "$CODE" == "403" ]]; then
            SZ=$(curl -sk --max-time 8 --connect-timeout 5 \
                -o /dev/null -w '%{size_download}' \
                "${TARGET_URL}${PATH_CHK}" 2>/dev/null || echo "0")
            echo "${PATH_CHK}:${CODE}:${SZ}" >> "$HOST_DIR/sensitive_hits.txt"
            [[ "$CODE" == "200" ]] && log "    ⚠  TROUVÉ: ${PATH_CHK} → HTTP ${CODE} (${SZ}B)"
        fi
    done

    # ── A01: Dirbusting ──────────────────────────────────────────────────
    if [[ -n "$WORDLIST" ]]; then
        if [[ $HAS_GOBUSTER -eq 1 ]]; then
            log "  [A01] Gobuster: $TARGET_URL"
            timeout 180 gobuster dir \
                -u "$TARGET_URL" \
                -w "$WORDLIST" \
                -t 25 \
                --timeout 10s \
                -q \
                --no-error \
                -o "$HOST_DIR/gobuster.txt" \
                2>/dev/null || true
        elif [[ $HAS_FEROX -eq 1 ]]; then
            log "  [A01] Feroxbuster: $TARGET_URL"
            timeout 180 feroxbuster \
                --url "$TARGET_URL" \
                --wordlist "$WORDLIST" \
                --threads 25 \
                --timeout 10 \
                --quiet \
                --output "$HOST_DIR/gobuster.txt" \
                --no-recursion \
                --silent \
                2>/dev/null || true
        fi
    fi

    # ── A06: Détection technologique ─────────────────────────────────────
    if [[ $HAS_WHATWEB -eq 1 ]]; then
        log "  [A06] WhatWeb: $TARGET_URL"
        timeout 30 whatweb --color=never \
            --log-json="$HOST_DIR/whatweb.json" \
            --aggression 1 \
            "$TARGET_URL" 2>/dev/null || true
    fi

    # ── A09: Détection WAF ───────────────────────────────────────────────
    if [[ $HAS_WAFW00F -eq 1 ]]; then
        log "  [A09] wafw00f: $TARGET_URL"
        timeout 30 wafw00f "$TARGET_URL" > "$HOST_DIR/wafw00f.txt" 2>/dev/null || true
    fi

    # ── A06: WordPress — scan si CMS détecté ─────────────────────────────
    IS_WP=0
    if [[ -f "$HOST_DIR/whatweb.json" ]]; then
        grep -qi "wordpress" "$HOST_DIR/whatweb.json" 2>/dev/null && IS_WP=1
    fi
    if [[ -f "$HOST_DIR/body_sample.html" ]] && grep -qi "wp-content\|wp-includes\|wordpress" \
            "$HOST_DIR/body_sample.html" 2>/dev/null; then
        IS_WP=1
    fi

    if [[ $IS_WP -eq 1 && $HAS_WPSCAN -eq 1 ]]; then
        log "  [A06] WordPress détecté — wpscan: $TARGET_URL"
        timeout 180 wpscan \
            --url "$TARGET_URL" \
            --no-banner \
            --disable-tls-checks \
            --format json \
            --output "$HOST_DIR/wpscan.json" \
            2>/dev/null || true
    fi

    # ── A03: SQLmap (détection uniquement, pas d'exploitation) ───────────
    if [[ $HAS_SQLMAP -eq 1 ]]; then
        if grep -qi '<form' "$HOST_DIR/body_sample.html" 2>/dev/null; then
            log "  [A03] sqlmap forms-detection: $TARGET_URL"
            timeout 180 sqlmap \
                --url "$TARGET_URL" \
                --batch \
                --level 1 \
                --risk 1 \
                --forms \
                --crawl 1 \
                --output-dir "$HOST_DIR/sqlmap" \
                --disable-coloring \
                2>/dev/null || true
        fi
    fi

done

success "${#LIVE_TARGETS[@]} cibles web répondantes scannées"

# ══════════════════════════════════════════════════════════════════════════
# ANALYSE PYTHON — génération summary.json
# ══════════════════════════════════════════════════════════════════════════
python3 << 'PY'
import json, os, re, glob
from pathlib import Path
from collections import Counter, defaultdict

out = os.environ['OUTPUT_DIR'] + '/web_owasp'

owasp_findings = []
issues = []
security_headers_summary = {}
waf_detected = {}
cms_detected = {}
seen_keys = set()

def add_finding(owasp_id, owasp_title, target, finding, severity, evidence, recommendation):
    """Ajouter un finding dédupliqué."""
    key = f"{owasp_id}|{target}|{finding[:80]}"
    if key in seen_keys:
        return
    seen_keys.add(key)
    owasp_findings.append({
        'owasp_id': owasp_id,
        'title': owasp_title,
        'target': target,
        'finding': finding,
        'severity': severity,
        'evidence': evidence,
        'recommendation': recommendation,
    })
    issues.append({
        'target': target,
        'severity': severity,
        'issue': f'{owasp_id}: {finding}',
        'recommendation': recommendation,
        'module': 'web_owasp',
    })

# ── Métadonnées headers de sécurité ──────────────────────────────────────
SECURITY_HEADERS = [
    ('Strict-Transport-Security',  'HSTS',               'HIGH'),
    ('Content-Security-Policy',    'CSP',                'MEDIUM'),
    ('X-Frame-Options',            'X-Frame-Options',    'MEDIUM'),
    ('X-Content-Type-Options',     'X-Content-Type-Options', 'LOW'),
    ('Referrer-Policy',            'Referrer-Policy',    'LOW'),
    ('Permissions-Policy',         'Permissions-Policy', 'LOW'),
]

# Sévérité par chemin sensible
SENSITIVE_CRITICAL = {
    '.git/config', '.git/head', '.env', '.env.local',
    '.env.backup', '.env.production', '.env.staging',
    'backup.sql', 'dump.sql', 'db.sql',
    'id_rsa', 'id_dsa', '.ssh/authorized_keys', '.bash_history',
}
SENSITIVE_HIGH = {
    'wp-config.php', 'wp-config.php.bak', 'wp-config.bak',
    'phpinfo.php', 'info.php', 'debug.php', 'test.php',
    'server-status', 'server-info', 'backup.zip', 'backup.tar.gz',
    'config.inc.php', 'configuration.php', 'settings.php',
    'elmah.axd', 'trace.axd', 'actuator/env',
}
SENSITIVE_MEDIUM = {
    'phpmyadmin', 'pma', 'adminer.php', 'adminer', 'dbadmin',
    'wp-admin', 'wp-login.php', 'administrator', 'manager', 'manager/html',
    'webadmin', 'panel', 'cpanel', 'whm', 'plesk', 'console',
    'actuator', 'actuator/health', 'actuator/mappings',
    '_ah/admin', '__admin', 'solr/admin', 'jmx-console',
    'jenkins', 'grafana', 'kibana', 'portainer',
}

REC_BY_PATH = {
    '.git/config':       "Bloquer l'accès au répertoire .git dans le serveur web (deny from all / location ~* /.git)",
    '.env':              "Ne jamais exposer les fichiers .env — les déplacer hors du webroot",
    'wp-config.php':     "Restreindre l'accès à wp-config.php (Apache: deny from all, Nginx: deny all)",
    'phpinfo.php':       "Supprimer phpinfo.php de la production — expose la configuration PHP",
    'server-status':     "Restreindre /server-status aux IP d'administration uniquement",
    'phpmyadmin':        "Restreindre phpMyAdmin aux IP d'administration ou le désactiver",
    'wp-admin':          "Protéger /wp-admin avec IP whitelist ou authentification à deux facteurs",
    'backup.zip':        "Supprimer les sauvegardes accessibles publiquement du webroot",
    'adminer.php':       "Supprimer adminer.php de la production ou restreindre aux IP admin",
    'actuator/env':      "Sécuriser Spring Actuator — désactiver env endpoint ou restreindre au loopback",
    'id_rsa':            "Supprimer immédiatement les clés SSH exposées et les révoquer",
    'dump.sql':          "Supprimer les dumps SQL du webroot immédiatement",
}
DEFAULT_REC = "Restreindre l'accès à cette ressource (règle serveur web ou déplacer hors du webroot)"

# ══════════════════════════════════════════════════════════════════════════
# Parcours des répertoires hôtes
# ══════════════════════════════════════════════════════════════════════════
host_dirs = sorted(glob.glob(f'{out}/hosts/*/'))
live_count = 0

for hdir in host_dirs:
    hdir = hdir.rstrip('/')

    # Récupérer l'URL depuis target_url.txt
    tu = Path(f'{hdir}/target_url.txt')
    if not tu.exists():
        continue
    url = tu.read_text().strip()
    if not url:
        continue

    # Vérifier que la cible a répondu (body_sample.html ou headers_raw.txt existent)
    if not Path(f'{hdir}/headers_raw.txt').exists() and not Path(f'{hdir}/body_sample.html').exists():
        continue
    live_count += 1

    # ══════════════════════════════════════════════════════════════════
    # A05 + A02: Headers de sécurité & Cookies
    # ══════════════════════════════════════════════════════════════════
    headers_file = Path(f'{hdir}/headers_raw.txt')
    if headers_file.exists():
        raw = headers_file.read_text(errors='replace')
        headers_lc = {}
        cookies_raw = []

        for line in raw.splitlines():
            if ':' in line and not line.startswith('HTTP/'):
                k, _, v = line.partition(':')
                k_l = k.strip().lower()
                headers_lc[k_l] = v.strip()
                if k_l == 'set-cookie':
                    cookies_raw.append(v.strip())

        server_hdr = headers_lc.get('server', '')
        xpb_hdr    = headers_lc.get('x-powered-by', '')

        # ── Headers de sécurité manquants ──────────────────────────
        hdr_status = {}
        for hdr, label, sev in SECURITY_HEADERS:
            present = hdr.lower() in headers_lc
            hdr_status[hdr] = present
            if not present:
                if hdr == 'Strict-Transport-Security' and not url.startswith('https://'):
                    continue
                add_finding(
                    'A05', 'Security Misconfiguration', url,
                    f'Header {hdr} manquant',
                    sev,
                    f'Header "{hdr}" absent de la réponse HTTP',
                    f'Ajouter le header {hdr} dans la configuration serveur web',
                )
        security_headers_summary[url] = hdr_status

        # ── Version serveur exposée ─────────────────────────────────
        if server_hdr and re.search(r'\d', server_hdr):
            add_finding(
                'A05', 'Security Misconfiguration', url,
                f'Version serveur exposée dans header Server',
                'MEDIUM',
                f'Server: {server_hdr}',
                'Masquer la version: ServerTokens Prod (Apache) / server_tokens off (Nginx)',
            )
        if xpb_hdr:
            add_finding(
                'A05', 'Security Misconfiguration', url,
                f'Header X-Powered-By exposé: {xpb_hdr}',
                'LOW',
                f'X-Powered-By: {xpb_hdr}',
                "Supprimer X-Powered-By: Header unset 'X-Powered-By' / expose_php=Off",
            )

        # ── Méthodes HTTP dangereuses ───────────────────────────────
        methods_file = Path(f'{hdir}/methods.txt')
        if methods_file.exists():
            for line in methods_file.read_text().splitlines():
                if ':' not in line:
                    continue
                method, code = line.split(':', 1)
                code = code.strip()
                if code not in ('405', '403', '501', '000', '404', '400'):
                    sev = 'HIGH' if method == 'TRACE' else 'MEDIUM'
                    add_finding(
                        'A05', 'Security Misconfiguration', url,
                        f'Méthode HTTP {method} activée (HTTP {code})',
                        sev,
                        f'HTTP {method} → {code}',
                        f'Désactiver la méthode {method}: TraceEnable off (Apache) / limit (Nginx)',
                    )

        # ── A02: Cookies sans flags de sécurité ─────────────────────
        cookies_parsed = []
        for raw_c in cookies_raw:
            parts = [p.strip() for p in raw_c.split(';')]
            if not parts:
                continue
            name = parts[0].split('=')[0].strip()
            flags_lc = [p.lower() for p in parts[1:]]
            secure   = 'secure'   in flags_lc
            httponly = 'httponly' in flags_lc
            samesite = next((p.split('=', 1)[1].strip() if '=' in p else 'present'
                             for p in parts[1:] if 'samesite' in p.lower()), None)
            cookies_parsed.append({'name': name, 'secure': secure,
                                   'httponly': httponly, 'samesite': samesite})

            if not secure and url.startswith('https://'):
                add_finding(
                    'A02', 'Cryptographic Failures', url,
                    f"Cookie '{name}' sans flag Secure",
                    'MEDIUM',
                    f"Set-Cookie: {name}=... (Secure absent sur HTTPS)",
                    f"Ajouter le flag Secure au cookie {name}",
                )
            if not httponly:
                add_finding(
                    'A02', 'Cryptographic Failures', url,
                    f"Cookie '{name}' sans flag HttpOnly",
                    'MEDIUM',
                    f"Set-Cookie: {name}=... (HttpOnly absent — risque XSS)",
                    f"Ajouter le flag HttpOnly au cookie {name}",
                )
            if not samesite:
                add_finding(
                    'A02', 'Cryptographic Failures', url,
                    f"Cookie '{name}' sans attribut SameSite",
                    'LOW',
                    f"Set-Cookie: {name}=... (SameSite absent — risque CSRF)",
                    f"Ajouter SameSite=Strict ou SameSite=Lax au cookie {name}",
                )

        with open(f'{hdir}/cookies.json', 'w') as f:
            json.dump(cookies_parsed, f, indent=2, ensure_ascii=False)

    # ── A02: Formulaire login sur HTTP ─────────────────────────────────
    if url.startswith('http://'):
        body_file = Path(f'{hdir}/body_sample.html')
        if body_file.exists():
            body = body_file.read_text(errors='replace').lower()
            if re.search(r'<form[^>]*>', body) and re.search(r'type=["\']?password', body):
                add_finding(
                    'A02', 'Cryptographic Failures', url,
                    'Formulaire de login sur HTTP (non chiffré)',
                    'HIGH',
                    'Champ password détecté dans un formulaire sur HTTP',
                    'Forcer la redirection vers HTTPS (301) pour tous les formulaires de login',
                )

    # ══════════════════════════════════════════════════════════════════
    # A01: Fichiers sensibles accessibles
    # ══════════════════════════════════════════════════════════════════
    sens_file = Path(f'{hdir}/sensitive_hits.txt')
    if sens_file.exists():
        for line in sens_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(':')
            if len(parts) < 2:
                continue
            path_chk = parts[0].lstrip('/')
            code     = parts[1]
            size     = parts[2] if len(parts) > 2 else '0'

            if code != '200':
                continue  # Ne reporter que les 200 (pas les 403)

            path_lc = path_chk.lower()
            if any(s in path_lc for s in SENSITIVE_CRITICAL):
                sev = 'CRITICAL'
            elif any(s in path_lc for s in SENSITIVE_HIGH):
                sev = 'HIGH'
            elif any(s in path_lc for s in SENSITIVE_MEDIUM):
                sev = 'MEDIUM'
            else:
                sev = 'LOW'

            rec = REC_BY_PATH.get(path_lc, DEFAULT_REC)
            for k, v in REC_BY_PATH.items():
                if k in path_lc:
                    rec = v
                    break

            add_finding(
                'A01', 'Broken Access Control', url,
                f'Ressource sensible accessible: /{path_chk}',
                sev,
                f'HTTP 200 sur {url}/{path_chk} (taille: {size} bytes)',
                rec,
            )

    # ── A01: Résultats gobuster (répertoires ouverts) ───────────────────
    gob_file = Path(f'{hdir}/gobuster.txt')
    if gob_file.exists():
        gob_text = gob_file.read_text(errors='replace')
        dir_listing = []
        for line in gob_text.splitlines():
            if re.search(r'\(Status: 200\)', line) and line.strip().startswith('/'):
                m = re.match(r'^(/\S+)', line.strip())
                if m:
                    dir_listing.append(m.group(1))
        if len(dir_listing) > 30:
            add_finding(
                'A01', 'Broken Access Control', url,
                f'Surface d\'attaque élevée: {len(dir_listing)} chemins accessibles (200 OK)',
                'MEDIUM',
                f'Gobuster: {len(dir_listing)} chemins en HTTP 200',
                'Restreindre l\'accès aux répertoires non nécessaires, appliquer le principe du moindre privilège',
            )

    # ══════════════════════════════════════════════════════════════════
    # A06: WhatWeb — Détection CMS & composants
    # ══════════════════════════════════════════════════════════════════
    ww_file = Path(f'{hdir}/whatweb.json')
    if ww_file.exists():
        try:
            ww_raw = ww_file.read_text(errors='replace').strip()
            if not ww_raw:
                raise ValueError("empty")
            ww_data = json.loads(ww_raw)
            if isinstance(ww_data, list):
                ww_data = ww_data[0] if ww_data else {}
            plugins = ww_data.get('plugins', {}) if isinstance(ww_data, dict) else {}

            CMS_NAMES = {
                'wordpress', 'joomla', 'drupal', 'typo3', 'contao', 'magento',
                'opencart', 'prestashop', 'dotnetnuke', 'sharepoint', 'shopify',
                'wix', 'squarespace',
            }

            for plugin_name, plugin_data in plugins.items():
                pn_l = plugin_name.lower()
                versions = []
                if isinstance(plugin_data, dict):
                    versions = plugin_data.get('version', [])
                elif isinstance(plugin_data, list):
                    for pd in plugin_data:
                        if isinstance(pd, dict):
                            versions.extend(pd.get('version', []))

                if pn_l in CMS_NAMES:
                    ver = versions[0] if versions else 'inconnue'
                    cms_detected[url] = {'cms': plugin_name, 'version': ver}
                    add_finding(
                        'A06', 'Vulnerable Components', url,
                        f'CMS {plugin_name} version {ver} détectée',
                        'INFO',
                        f'WhatWeb: {plugin_name} {ver}',
                        f'Maintenir {plugin_name} à jour, surveiller les CVE, désactiver le listing de version',
                    )

                if pn_l == 'php' and versions:
                    ver = versions[0]
                    if re.match(r'^[56]\.', ver) or re.match(r'^7\.[0-3]\.', ver):
                        add_finding(
                            'A06', 'Vulnerable Components', url,
                            f'PHP version obsolète et non supportée: {ver}',
                            'HIGH',
                            f'WhatWeb: PHP {ver} (EOL)',
                            'Mettre à jour PHP vers une version activement supportée (>= 8.1)',
                        )
                    elif re.match(r'^7\.[4-9]\.', ver):
                        add_finding(
                            'A06', 'Vulnerable Components', url,
                            f'PHP 7.x en fin de support: {ver}',
                            'MEDIUM',
                            f'WhatWeb: PHP {ver}',
                            'Planifier la migration vers PHP 8.1+',
                        )

                if pn_l in ('apache', 'nginx', 'iis', 'lighttpd') and versions:
                    ver = versions[0]
                    add_finding(
                        'A06', 'Vulnerable Components', url,
                        f'Version serveur web exposée: {plugin_name} {ver}',
                        'INFO',
                        f'WhatWeb: {plugin_name} {ver}',
                        'Masquer la version serveur et surveiller les CVE',
                    )

        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    # A06: WPScan — WordPress audit approfondi
    # ══════════════════════════════════════════════════════════════════
    wp_file = Path(f'{hdir}/wpscan.json')
    if wp_file.exists():
        try:
            wp = json.loads(wp_file.read_text(errors='replace'))

            # Version WordPress
            wp_ver = wp.get('version', {})
            if isinstance(wp_ver, dict) and wp_ver.get('number'):
                ver_num = wp_ver['number']
                status  = wp_ver.get('status', '')
                if status == 'insecure':
                    add_finding(
                        'A06', 'Vulnerable Components', url,
                        f'WordPress version obsolète: {ver_num}',
                        'HIGH',
                        f'wpscan: WordPress {ver_num} (statut: insecure)',
                        'Mettre à jour WordPress vers la dernière version stable immédiatement',
                    )

            # Plugins vulnérables
            for slug, pdata in (wp.get('plugins') or {}).items():
                if not isinstance(pdata, dict):
                    continue
                for vuln in (pdata.get('vulnerabilities') or []):
                    v_title = vuln.get('title', slug)
                    cvss_score = 0
                    if isinstance(vuln.get('cvss'), dict):
                        cvss_score = vuln['cvss'].get('score', 0)
                    sev = 'CRITICAL' if cvss_score >= 9 else 'HIGH' if cvss_score >= 7 else 'MEDIUM'
                    add_finding(
                        'A06', 'Vulnerable Components', url,
                        f'Plugin WordPress vulnérable: {slug}',
                        sev,
                        f'wpscan: {v_title} (CVSS: {cvss_score})',
                        f'Mettre à jour ou désactiver le plugin {slug}',
                    )

            # Thèmes vulnérables
            for slug, tdata in (wp.get('themes') or {}).items():
                if not isinstance(tdata, dict):
                    continue
                for vuln in (tdata.get('vulnerabilities') or []):
                    add_finding(
                        'A06', 'Vulnerable Components', url,
                        f'Thème WordPress vulnérable: {slug}',
                        'MEDIUM',
                        f'wpscan: {vuln.get("title", slug)}',
                        f'Mettre à jour ou désactiver le thème {slug}',
                    )

            # Utilisateurs énumérables
            users = wp.get('users') or {}
            if len(users) > 0:
                u_list = list(users.keys())[:5]
                add_finding(
                    'A01', 'Broken Access Control', url,
                    f'Énumération utilisateurs WordPress possible ({len(users)} trouvés)',
                    'MEDIUM',
                    f'wpscan users: {", ".join(u_list)}',
                    'Désactiver l\'API REST /wp-json/wp/v2/users ou masquer les logins auteurs',
                )

        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    # A09: WAF detection (wafw00f)
    # ══════════════════════════════════════════════════════════════════
    waf_file = Path(f'{hdir}/wafw00f.txt')
    if waf_file.exists():
        waf_text = waf_file.read_text(errors='replace')
        # Patterns de sortie wafw00f
        waf_match = re.search(
            r'is behind (?:the )?(.+?) ?(?:WAF|Web Application Firewall)|'
            r'Detected WAF:\s*(.+)|'
            r'is behind:\s*(.+)',
            waf_text, re.IGNORECASE
        )
        if waf_match:
            waf_name = next((g for g in waf_match.groups() if g), 'WAF détecté').strip()
            waf_detected[url] = waf_name
        elif re.search(r'No WAF detected|does not seem to be behind|no web application firewall',
                       waf_text, re.IGNORECASE):
            waf_detected[url] = None
            add_finding(
                'A09', 'Security Logging & Monitoring', url,
                'Aucun WAF détecté sur cette application web',
                'LOW',
                'wafw00f: No WAF detected',
                'Envisager un WAF (ModSecurity, Cloudflare WAF, AWS WAF) pour les applications exposées',
            )

    # ══════════════════════════════════════════════════════════════════
    # A03: SQLmap — résultats injection SQL
    # ══════════════════════════════════════════════════════════════════
    sqlmap_dir = Path(f'{hdir}/sqlmap')
    if sqlmap_dir.exists():
        for log_f in sqlmap_dir.rglob('*.log'):
            try:
                log_txt = log_f.read_text(errors='replace')
                if re.search(r'is vulnerable|sqlmap identified|injection point', log_txt, re.IGNORECASE):
                    param_m = re.search(r"parameter ['\"]?(\w+)['\"]? (?:is|appears to be) vulnerable",
                                        log_txt, re.IGNORECASE)
                    param = param_m.group(1) if param_m else 'paramètre inconnu'
                    add_finding(
                        'A03', 'Injection', url,
                        f'Injection SQL détectée — paramètre: {param}',
                        'CRITICAL',
                        f'sqlmap: {param} vulnérable (log: {log_f.name})',
                        'Utiliser des requêtes préparées (PreparedStatement / PDO) — ne jamais interpoler l\'entrée utilisateur dans les requêtes SQL',
                    )
            except Exception:
                pass
        # Chercher dans les fichiers CSV sqlmap aussi
        for csv_f in sqlmap_dir.rglob('*.csv'):
            try:
                csv_txt = csv_f.read_text(errors='replace')
                if len(csv_txt) > 50:  # Résultats présents = données extraites
                    add_finding(
                        'A03', 'Injection', url,
                        'Données extraites via injection SQL (sqlmap)',
                        'CRITICAL',
                        f'sqlmap CSV: {csv_f.name}',
                        'URGENT: Corriger les injections SQL, auditer les données exposées',
                    )
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════
# BUILD SUMMARY.JSON
# ══════════════════════════════════════════════════════════════════════════
counts = Counter(f['severity'] for f in owasp_findings)
by_cat = defaultdict(list)
for f in owasp_findings:
    by_cat[f['owasp_id']].append(f)

owasp_labels = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable Components',
    'A09': 'Security Logging & Monitoring',
}

by_category_summary = {}
for oid, findings in by_cat.items():
    c = Counter(f['severity'] for f in findings)
    by_category_summary[oid] = {
        'label': owasp_labels.get(oid, oid),
        'count': len(findings),
        'severities': dict(c),
    }

summary = {
    'mode':          'executed',
    'targets_scanned': live_count,
    'owasp_findings':  owasp_findings,
    'by_owasp_category': by_category_summary,
    'security_headers_summary': security_headers_summary,
    'waf_detected':  waf_detected,
    'cms_detected':  cms_detected,
    'issues':        issues,
    'counts': {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH':     counts.get('HIGH', 0),
        'MEDIUM':   counts.get('MEDIUM', 0),
        'LOW':      counts.get('LOW', 0),
        'INFO':     counts.get('INFO', 0),
    },
}

json.dump(summary, open(f'{out}/summary.json', 'w'), indent=2, ensure_ascii=False)

# Rapport console
total_f = len(owasp_findings)
print(f"\nOWASP: {total_f} findings sur {live_count} cibles")
print(f"  C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)} I:{counts.get('INFO',0)}")
for oid, info in sorted(by_category_summary.items()):
    print(f"  {oid} {info['label']}: {info['count']} findings")
PY

RC=$?
if [[ $RC -ne 0 ]]; then
    error "Module web_owasp ÉCHOUÉ (Python exit $RC)"
    exit 1
fi

if [[ ! -s "$OUT/summary.json" ]]; then
    error "web_owasp/summary.json non créé ou vide"
    exit 1
fi

SZ=$(stat -c%s "$OUT/summary.json" 2>/dev/null || echo 0)
if [[ "$SZ" -lt 50 ]]; then
    error "web_owasp/summary.json trop petit (${SZ} bytes)"
    exit 1
fi

success "Module web_owasp terminé (summary: ${SZ} bytes)"
