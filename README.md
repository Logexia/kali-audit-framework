# PME IT Audit Framework v4.5

Framework d'audit de sécurité informatique pour PME, conçu pour Kali Linux. Pipeline en 6 phases couvrant la découverte réseau, l'énumération, l'Active Directory, les vulnérabilités CVE, le SSL/TLS, le Web OWASP et le WiFi. Génère automatiquement un rapport HTML et un rapport DOCX.

---

## Table des matières

1. [Prérequis](#prérequis)
2. [Installation](#installation)
3. [Démarrage rapide](#démarrage-rapide)
4. [Référence des options](#référence-des-options)
5. [Exemples de commandes](#exemples-de-commandes)
   - [Audit réseau interne complet](#audit-réseau-interne-complet)
   - [Audit IPs externes](#audit-ips-externes)
   - [Audits ciblés](#audits-ciblés)
6. [Scan OpenVAS](#scan-openvas)
7. [Variables d'environnement](#variables-denvironnement)
8. [Modules disponibles](#modules-disponibles)
9. [Résultats et rapports](#résultats-et-rapports)
10. [Structure des sorties](#structure-des-sorties)
11. [Dépendances](#dépendances)

---

## Prérequis

- Kali Linux 2023.x ou supérieur (ou Debian/Ubuntu avec outils sécurité)
- Python 3.8+
- Exécution en root ou avec `sudo` (requis pour Nmap, airmon-ng, etc.)
- Accès réseau à la cible

---

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/votre-org/kali-audit-framework.git
cd kali-audit-framework

# Outils essentiels (Nmap, SMB, DNS, SNMP, SSL)
sudo apt update && sudo apt install -y \
    nmap smbclient enum4linux crackmapexec \
    sslscan testssl.sh snmpwalk snmp-check \
    dnsrecon dnsenum nbtscan ldap-utils \
    nikto whatweb python3-pip

# Outils recommandés (Web, AD, WiFi)
sudo apt install -y \
    gobuster feroxbuster wafw00f sqlmap wpscan \
    aircrack-ng wash onesixtyone \
    bloodhound-python impacket-scripts \
    searchsploit

# Dépendances Python
pip3 install python-docx

# Rendre exécutable
chmod +x audit.sh
```

---

## Démarrage rapide

```bash
# Audit minimal (discovery + CVE)
sudo bash audit.sh --client "ACME" --network 192.168.1.0/24

# Audit complet réseau interne
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --dc 192.168.1.10 \
  --wifi wlan0

# Résultats dans /opt/audits/acme_corp_YYYYMMDD_HHMMSS/
```

---

## Référence des options

| Option | Description | Exemple |
|--------|-------------|---------|
| `--client NAME` | **Obligatoire.** Nom du client | `--client "ACME Corp"` |
| `--network CIDR` | **Obligatoire.** Réseau cible | `--network 192.168.1.0/24` |
| `--domain FQDN` | Domaine pour audit email SPF/DKIM/DMARC | `--domain acme.ch` |
| `--dc IP` | IP du contrôleur de domaine | `--dc 192.168.1.10` |
| `--urls FILE` | Fichier d'URLs pour scan SSL (une par ligne) | `--urls urls.txt` |
| `--wifi IFACE` | Interface WiFi pour audit sans fil | `--wifi wlan0` |
| `--output DIR` | Répertoire de sortie personnalisé | `--output /tmp/audit` |
| `--modules LIST` | Exécuter uniquement ces modules (virgules) | `--modules discovery,cve,ssl` |
| `--exclude-module NAME` | Exclure un module (répétable) | `--exclude-module wifi` |
| `--skip-openvas` | Forcer le mode dégradé OpenVAS | |
| `--list-modules` | Lister tous les modules disponibles | |
| `--help` | Afficher l'aide | |

---

## Exemples de commandes

### Audit réseau interne complet

```bash
# Audit interne standard avec AD, email, WiFi
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --dc 192.168.1.10 \
  --wifi wlan0

# Audit interne sans WiFi ni SNMP
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --dc 192.168.1.10 \
  --exclude-module wifi \
  --exclude-module snmp

# Audit interne avec OpenVAS (GVM installé)
GVM_USER=admin GVM_PASS=secret sudo -E bash audit.sh \
  --client "ACME Corp" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --dc 192.168.1.10

# Réseau /16 avec répertoire de sortie dédié
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 10.0.0.0/16 \
  --domain acme.ch \
  --output /srv/audits/acme-2024
```

---

### Audit IPs externes

Pour un audit d'IPs exposées sur Internet, certains modules ne sont pas applicables (AD, SMB, SNMP, WiFi) car les ports correspondants sont généralement filtrés par les firewalls périmètre. Les modules utiles sont : `discovery`, `cve`, `ssl`, `web_owasp`, `dns`, `email`.

```bash
# Audit externe standard — plage d'IPs publiques
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 203.0.113.0/28 \
  --domain acme.ch \
  --exclude-module ad \
  --exclude-module smb \
  --exclude-module snmp \
  --exclude-module wifi \
  --skip-openvas

# Audit externe ciblé — modules pertinents uniquement
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 203.0.113.0/28 \
  --domain acme.ch \
  --modules discovery,dns,email,cve,ssl,web_owasp

# Audit externe avec liste d'URLs HTTPS pour SSL détaillé
cat > /tmp/urls_acme.txt <<EOF
https://www.acme.ch
https://mail.acme.ch
https://vpn.acme.ch
https://app.acme.ch
EOF

sudo bash audit.sh \
  --client "ACME Corp" \
  --network 203.0.113.0/28 \
  --domain acme.ch \
  --urls /tmp/urls_acme.txt \
  --modules discovery,dns,email,cve,ssl,web_owasp

# IP unique exposée (serveur web public)
sudo bash audit.sh \
  --client "ACME Corp" \
  --network 203.0.113.42/32 \
  --domain acme.ch \
  --modules discovery,cve,ssl,web_owasp

# Plusieurs plages non contiguës — lancer en parallèle
sudo bash audit.sh --client "ACME DMZ" --network 203.0.113.0/28 \
  --domain acme.ch --modules discovery,cve,ssl,web_owasp &
sudo bash audit.sh --client "ACME Cloud" --network 198.51.100.0/29 \
  --domain acme.ch --modules discovery,cve,ssl,web_owasp &
wait
```

> **Note** : Pour un audit externe avec OpenVAS, retirez `--skip-openvas` et fournissez les credentials GVM via variables d'environnement (voir section [Scan OpenVAS](#scan-openvas)).

---

### Audits ciblés

```bash
# Discovery seul — inventaire rapide du réseau
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --modules discovery

# Audit SSL uniquement sur une liste d'URLs
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --urls /tmp/urls.txt \
  --modules ssl

# Audit AD seul (après avoir un DC identifié)
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --dc 192.168.1.10 \
  --modules ad

# Audit email seul (vérification SPF/DKIM/DMARC)
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --modules email

# Audit Web OWASP Top 10
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --modules web_owasp

# CVE + exploitabilité
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --modules cve,exploitability

# Discovery + CVE + SSL (périmètre rapide)
sudo bash audit.sh \
  --client "ACME" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --modules discovery,cve,ssl
```

---

## Scan OpenVAS

OpenVAS (Greenbone Vulnerability Manager) est optionnel. Si GVM n'est pas installé, le module est ignoré automatiquement. Avec `--skip-openvas`, il est forcé à passer même si GVM est présent.

### Installation de GVM sur Kali

```bash
sudo apt install -y gvm
sudo gvm-setup        # ~10-20 min (téléchargement des NVTs)
sudo gvm-start
sudo gvm-check-setup  # vérifier que tout est OK
```

### Lancement avec OpenVAS

```bash
# Variables d'environnement pour les credentials GVM
GVM_USER=admin GVM_PASS=votre_mot_de_passe sudo -E bash audit.sh \
  --client "ACME Corp" \
  --network 192.168.1.0/24 \
  --domain acme.ch \
  --dc 192.168.1.10

# Ou exporter les variables avant
export GVM_USER=admin
export GVM_PASS=votre_mot_de_passe
sudo -E bash audit.sh --client "ACME Corp" --network 192.168.1.0/24
```

> **Durée** : Un scan OpenVAS complet sur un /24 peut prendre 1-3 heures selon le nombre d'hôtes. Prévoir une fenêtre de maintenance.

---

## Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `GVM_USER` | Nom d'utilisateur GVM/OpenVAS | `admin` |
| `GVM_PASS` | Mot de passe GVM/OpenVAS | `admin` |
| `GVM_HOST` | Hôte GVM (si distant) | `127.0.0.1` |
| `GVM_PORT` | Port GVM | `9390` |

---

## Modules disponibles

| Module | Phase | Description | Prérequis |
|--------|-------|-------------|-----------|
| `discovery` | 1 — Discovery | Scan Nmap, inventaire hôtes/ports/services/OS | `nmap` |
| `smb` | 2 — Enumeration | Partages SMB, versions, signing, permissions | `smbclient`, `crackmapexec` |
| `snmp` | 2 — Enumeration | Community strings, topologie, équipements | `snmpwalk`, `onesixtyone` |
| `dns` | 2 — Enumeration | Zone transfer, sous-domaines, enregistrements | `dnsrecon`, `dnsenum` |
| `email` | 2 — Enumeration | SPF, DKIM, DMARC, MX, STARTTLS | `dig`, `--domain` requis |
| `ad` | 3 — Active Directory | PingCastle-style, scoring, BloodHound, Kerberoasting | `ldapsearch`, `impacket` |
| `wifi` | 4 — Vuln Scan | Réseaux WiFi, chiffrement, WPS, PMKID | `aircrack-ng`, `--wifi` requis |
| `cve` | 4 — Vuln Scan | CVE via Nmap vulners, WhatWeb, Nikto | `nmap`, `nikto` |
| `openvas` | 4 — Vuln Scan | Scan complet Greenbone/OpenVAS | GVM installé |
| `exploitability` | 4 — Vuln Scan | Searchsploit + MSF lookup (indicatif) | `searchsploit` |
| `ssl` | 4 — Vuln Scan | Protocoles TLS, certificats, faiblesses (BEAST, POODLE…) | `testssl`, `sslscan` |
| `web_owasp` | 4 — Vuln Scan | OWASP Top 10 : headers, SQLi, XSS, CMS, WAF | `gobuster`, `sqlmap`, `wafw00f` |

---

## Résultats et rapports

Après un audit, trois fichiers sont générés dans `$OUTPUT_DIR/report/` :

| Fichier | Description |
|---------|-------------|
| `rapport_audit.html` | Rapport HTML interactif avec scoring, tableaux colorés, tendances |
| `rapport_audit.docx` | Rapport Word professionnel (client-ready) |
| `consolidated.json` | Données brutes JSON (toutes phases) |

### Score de risque

Le score global (0-100) est calculé de façon asymptotique à partir des findings :

| Niveau | Points | Couleur |
|--------|--------|---------|
| CRITICAL | 25 pts | Rouge foncé |
| HIGH | 10 pts | Rouge |
| MEDIUM | 4 pts | Orange |
| LOW | 1 pt | Jaune |

**Interprétation** : 0-30 = Faible, 31-60 = Modéré, 61-80 = Élevé, 81-100 = Critique

### Historique et tendances

Si des rapports précédents existent pour le même client dans `/opt/audits/`, le rapport HTML inclut automatiquement une section **Tendances** montrant l'évolution du score et du nombre de vulnérabilités audit par audit.

---

## Structure des sorties

```
/opt/audits/acme_corp_20240115_143022/
├── audit.log                    # Log complet de l'audit
├── audit_config.json            # Configuration utilisée
├── discovery/
│   ├── hosts.xml                # Résultats Nmap XML
│   ├── hosts.txt                # Hôtes actifs
│   └── summary.json            # Inventaire structuré
├── smb/
│   ├── shares_null.txt          # Partages accès anonyme (CME)
│   ├── shares_guest.txt         # Partages accès guest (CME)
│   └── summary.json
├── snmp/
│   └── summary.json
├── dns/
│   └── summary.json
├── email_security/
│   └── summary.json
├── ad/
│   ├── bloodhound/              # Fichiers BloodHound (.zip)
│   └── summary.json
├── cve/
│   └── summary.json
├── openvas/
│   └── summary.json
├── exploitability/
│   └── summary.json
├── ssl/
│   └── summary.json
├── web_owasp/
│   └── summary.json
├── wifi/
│   └── summary.json
└── report/
    ├── consolidated.json        # Données consolidées toutes phases
    ├── modules_ran.txt          # Liste des modules exécutés
    ├── rapport_audit.html       # Rapport HTML
    └── rapport_audit.docx       # Rapport DOCX
```

---

## Dépendances

### Outils obligatoires

| Outil | Usage | Installation |
|-------|-------|--------------|
| `nmap` | Discovery, CVE scan | `apt install nmap` |
| `smbclient` | Enumération SMB | `apt install smbclient` |
| `python3` | Consolidation, rapports | Inclus Kali |
| `dig` | DNS, email | `apt install dnsutils` |

### Outils recommandés

| Outil | Module | Installation |
|-------|--------|--------------|
| `crackmapexec` / `nxc` | smb | `apt install crackmapexec` |
| `enum4linux` | smb | `apt install enum4linux` |
| `testssl.sh` | ssl | `apt install testssl.sh` |
| `sslscan` | ssl | `apt install sslscan` |
| `nikto` | cve | `apt install nikto` |
| `whatweb` | cve | `apt install whatweb` |
| `snmpwalk` | snmp | `apt install snmp` |
| `onesixtyone` | snmp | `apt install onesixtyone` |
| `dnsrecon` | dns | `apt install dnsrecon` |
| `dnsenum` | dns | `apt install dnsenum` |
| `ldapsearch` | ad | `apt install ldap-utils` |
| `impacket-*` | ad | `apt install impacket-scripts` |
| `bloodhound-python` | ad | `pip3 install bloodhound` |
| `gobuster` | web_owasp | `apt install gobuster` |
| `sqlmap` | web_owasp | `apt install sqlmap` |
| `wafw00f` | web_owasp | `pip3 install wafw00f` |
| `wpscan` | web_owasp | `apt install wpscan` |
| `aircrack-ng` | wifi | `apt install aircrack-ng` |
| `wash` | wifi | `apt install reaver` |
| `searchsploit` | exploitability | `apt install exploitdb` |
| `gvm` / `openvas` | openvas | `apt install gvm` |
| `python-docx` | rapport DOCX | `pip3 install python-docx` |

---

## Licence

Usage interne et pentesting autorisé uniquement. Respecter les lois en vigueur (nLPD Suisse, RGPD, Computer Fraud and Abuse Act selon juridiction). Ne jamais utiliser contre des systèmes sans autorisation écrite préalable.
