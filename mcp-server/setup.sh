#!/bin/bash
KALI_HOST="192.168.1.68"; KALI_USER="audit"; SSH_KEY="$HOME/.ssh/audit_kali"
echo "PME IT Audit Framework v4.1 — Setup"
echo "  D) Déployer  T) Tester SSH  R) Audit distant  N) Config n8n"
read -p "Choix: " c
case $c in
    D|d) ssh -i "$SSH_KEY" "$KALI_USER@$KALI_HOST" "sudo mkdir -p /opt/kali-audit-framework /opt/audits && sudo chown -R $KALI_USER: /opt/kali-audit-framework /opt/audits"
         SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
         scp -i "$SSH_KEY" -r "$SCRIPT_DIR"/* "$KALI_USER@$KALI_HOST:/opt/kali-audit-framework/"
         ssh -i "$SSH_KEY" "$KALI_USER@$KALI_HOST" "chmod +x /opt/kali-audit-framework/audit.sh /opt/kali-audit-framework/modules/*.sh /opt/kali-audit-framework/scripts/*.sh"
         ssh -i "$SSH_KEY" "$KALI_USER@$KALI_HOST" "sudo apt update -qq && sudo apt install -y -qq nmap smbclient enum4linux sslscan whatweb nikto testssl.sh nbtscan ldap-utils aircrack-ng reaver python3-impacket dnsrecon dnsenum snmp snmp-mibs-downloader onesixtyone exploitdb 2>/dev/null"
         echo "[✓] DÉPLOYÉ" ;;
    T|t) ssh -i "$SSH_KEY" -o ConnectTimeout=5 "$KALI_USER@$KALI_HOST" "echo 'SSH OK'; whoami; uname -a" ;;
    R|r) read -p "Client: " cl; read -p "Réseau: " net; read -p "DC: " dc
         CMD="sudo /opt/kali-audit-framework/audit.sh --client '$cl' --network '$net' --modules all"
         [[ -n "$dc" ]] && CMD+=" --dc $dc"; ssh -i "$SSH_KEY" "$KALI_USER@$KALI_HOST" "$CMD" ;;
    N|n) echo "n8n: Webhook→SSH→Respond | Host:$KALI_HOST User:$KALI_USER Key:$SSH_KEY" ;;
esac
