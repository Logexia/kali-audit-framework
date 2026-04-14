#!/bin/bash
#============================================================================
# 06 - WIFI: Réseaux, chiffrement, WPS, vulnérabilités
# [NON-REGRESSION] Inchangé depuis v4
#============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
OUT="$OUTPUT_DIR/wifi"
IFACE="${WIFI_INTERFACE:-}"

if [[ -z "$IFACE" ]]; then IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1); fi
if [[ -z "$IFACE" ]]; then
    warning "Aucune interface WiFi"; echo '{"status":"no_interface","networks":[],"issues":[]}' > "$OUT/summary.json"; exit 0
fi
log "Interface WiFi: $IFACE"

log "Scan passif WiFi (iw)"
iw dev "$IFACE" scan 2>/dev/null > "$OUT/iw_scan_raw.txt" || true

MON=""
if command -v airmon-ng &>/dev/null; then
    airmon-ng check kill 2>/dev/null || true; airmon-ng start "$IFACE" 2>/dev/null || true
    for c in "${IFACE}mon" "wlan0mon" "wlan1mon"; do iw dev "$c" info &>/dev/null 2>&1 && { MON="$c"; break; }; done
    if [[ -n "$MON" ]]; then
        log "Capture airodump (90s)"
        timeout 92 airodump-ng "$MON" --write "$OUT/capture" --write-interval 10 --output-format csv,netxml --band abg 2>/dev/null &
        wait $! 2>/dev/null || true
    fi
fi
if command -v wash &>/dev/null && [[ -n "$MON" ]]; then
    log "Scan WPS (45s)"; timeout 47 wash -i "$MON" > "$OUT/wps_raw.txt" 2>/dev/null || true
fi
if [[ -n "$MON" ]]; then airmon-ng stop "$MON" 2>/dev/null || true; systemctl start NetworkManager 2>/dev/null || true; fi

python3 << 'WIFIPY'
import json, os, re, csv, glob
from collections import Counter

out = os.environ['OUTPUT_DIR'] + '/wifi'
networks = []; issues = []

current = None
try:
    for line in open(f'{out}/iw_scan_raw.txt'):
        line = line.rstrip()
        m = re.match(r'^BSS ([0-9a-f:]+)', line)
        if m:
            if current: networks.append(current)
            current = {'bssid':m.group(1),'ssid':'','channel':'','frequency':'','signal':'','encryption':'OPEN','cipher':'','auth':'','wps':False,'wps_locked':None,'hidden':False,'source':'iw'}
            continue
        if not current: continue
        s = line.strip()
        if s.startswith('SSID:'): ssid = s[5:].strip(); current['ssid'] = ssid; current['hidden'] = not ssid
        elif s.startswith('freq:'): current['frequency'] = s.split(':',1)[1].strip()
        elif s.startswith('signal:'): current['signal'] = s.split(':',1)[1].strip()
        elif 'primary channel:' in s.lower() or 'DS Parameter set: channel' in s:
            m2 = re.search(r'(\d+)', s)
            if m2: current['channel'] = m2.group(1)
        elif s.startswith('RSN:'): current['encryption'] = 'WPA2' if current['encryption']=='OPEN' else current['encryption']+'/WPA2'
        elif s.startswith('WPA:'): current['encryption'] = 'WPA' if 'WPA2' not in current['encryption'] else 'WPA/WPA2'
        elif 'Pairwise ciphers:' in s: current['cipher'] = s.split(':',1)[1].strip()
        elif 'Authentication suites:' in s: current['auth'] = s.split(':',1)[1].strip()
        elif 'WPS' in s and ':' in s: current['wps'] = True
    if current: networks.append(current)
except: pass

seen = {n['bssid'].upper() for n in networks}
for csvf in glob.glob(f'{out}/capture*.csv'):
    try:
        lines = open(csvf, encoding='utf-8', errors='ignore').readlines(); in_ap = False
        for line in lines:
            line = line.strip()
            if line.startswith('BSSID') and 'channel' in line.lower(): in_ap = True; continue
            if not line: in_ap = False; continue
            if not in_ap: continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 14: continue
            bssid = parts[0].strip()
            if not re.match(r'^[0-9A-Fa-f:]{17}$', bssid) or bssid.upper() in seen: continue
            seen.add(bssid.upper()); ssid = parts[13].strip() if len(parts)>13 else ''
            networks.append({'bssid':bssid.lower(),'ssid':ssid,'channel':parts[3].strip(),'frequency':'','signal':parts[8].strip()+' dBm','encryption':parts[5].strip() if len(parts)>5 else '','cipher':parts[6].strip() if len(parts)>6 else '','auth':parts[7].strip() if len(parts)>7 else '','wps':False,'wps_locked':None,'hidden':not ssid or ssid.startswith('<len'),'source':'airodump'})
    except: pass

try:
    for l in open(f'{out}/wps_raw.txt'):
        parts = l.split()
        if len(parts) >= 6 and re.match(r'^[0-9A-Fa-f:]{17}$', parts[0]):
            for n in networks:
                if n['bssid'].upper() == parts[0].upper(): n['wps'] = True; n['wps_locked'] = len(parts)>4 and parts[4].lower()=='yes'
except: pass

for n in networks:
    ssid = n.get('ssid','') or f"(caché {n['bssid']})"; enc = n.get('encryption','').upper(); bssid = n.get('bssid','')
    if enc in ('OPEN','OPN','') and n.get('ssid'): issues.append({'bssid':bssid,'network':ssid,'severity':'CRITICAL','issue':f'Réseau ouvert: "{ssid}"','recommendation':'Activer WPA2-AES ou WPA3'})
    elif 'WEP' in enc: issues.append({'bssid':bssid,'network':ssid,'severity':'CRITICAL','issue':f'WEP sur "{ssid}"','recommendation':'Migrer vers WPA2-AES'})
    elif 'WPA' in enc and 'WPA2' not in enc and 'WPA3' not in enc: issues.append({'bssid':bssid,'network':ssid,'severity':'HIGH','issue':f'WPA1 seul sur "{ssid}"','recommendation':'Migrer vers WPA2-AES'})
    if 'TKIP' in n.get('cipher','').upper() and 'CCMP' not in n.get('cipher','').upper(): issues.append({'bssid':bssid,'network':ssid,'severity':'MEDIUM','issue':f'TKIP seul sur "{ssid}"','recommendation':'Passer en AES/CCMP'})
    if n.get('wps') and not n.get('wps_locked',True): issues.append({'bssid':bssid,'network':ssid,'severity':'HIGH','issue':f'WPS non verrouillé sur "{ssid}"','recommendation':'Désactiver WPS'})
    if n.get('hidden'): issues.append({'bssid':bssid,'network':ssid,'severity':'LOW','issue':f'SSID masqué ({bssid})','recommendation':'Le masquage SSID n\'est pas une protection'})

seen_i = set(); unique = []
for i in issues:
    k = f"{i.get('bssid','')}-{i['severity']}-{i['issue'][:40]}"
    if k not in seen_i: seen_i.add(k); unique.append(i)
issues = unique

with open(f'{out}/wifi_networks.csv','w',newline='') as f:
    w = csv.writer(f, delimiter=';')
    w.writerow(['BSSID','SSID','Canal','Signal','Chiffrement','Cipher','Auth','WPS','Caché'])
    for n in networks: w.writerow([n.get('bssid',''),n.get('ssid',''),n.get('channel',''),n.get('signal',''),n.get('encryption',''),n.get('cipher',''),n.get('auth',''),'Oui' if n.get('wps') else 'Non','Oui' if n.get('hidden') else 'Non'])

counts = Counter(i['severity'] for i in issues)
json.dump({'total_networks':len(networks),'networks':networks,'issues':issues,'counts':dict(counts)}, open(f'{out}/summary.json','w'), indent=2, ensure_ascii=False)
print(f"WiFi: {len(networks)} réseaux, {len(issues)} issues")
WIFIPY
