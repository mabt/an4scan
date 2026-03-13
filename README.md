# AN4SCAN - Magento 2 Malware Scanner

Scanner de securite defensif pour les installations Magento 2. Detecte les fichiers infectes, les backdoors PHP, les skimmers de cartes bancaires (Magecart), le code obfusque, les injections en base de donnees, les problemes de permissions, les CVEs connues et les tentatives d'exploitation dans les logs.

Inspire par des outils comme [eComscan](https://sansec.io/ecomscan), AN4SCAN est un outil open-source et gratuit concu pour etre utilise en audit, forensics ou surveillance continue.

---

## Fonctionnalites

| Module | Flag | Description |
|--------|------|-------------|
| **File Scan** | *(toujours actif)* | 60+ signatures regex : skimmers CC, backdoors, webshells, obfuscation, patterns Magento specifiques |
| **Version + CVEs** | `--version-check` | Detection automatique de la version Magento + base de 25+ CVEs critiques avec patches recommandes |
| **Database Scan** | `--db` | Analyse les tables `core_config_data`, `cms_block`, `cms_page`, `email_template` + verifie les admin users suspects et les cron jobs |
| **Log Analysis** | `--logs` | Analyse les access logs Apache/Nginx pour detecter les tentatives d'exploitation, brute force admin, injections SQL |
| **Permission Check** | `--permissions` | Detecte fichiers/dossiers world-writable, SUID/SGID sur scripts, `env.php` world-readable |
| **Modified Files** | `--mtime` | Compare les dates de modification des fichiers core vs `composer.lock`, detecte les PHP recents dans `pub/media`, `var`, etc. |
| **YARA Scan** | `--yara` | 7 regles YARA integrees + support de regles externes (Sansec, THOR, custom) |
| **Integrity Check** | `--integrity` | Verifie les overrides de fichiers core dans `app/code/Magento` |
| **Timeline** | *(automatique)* | Reconstruction chronologique de l'infection a partir des mtimes, logs et findings |
| **Tout activer** | `--all` | Active tous les modules ci-dessus |

---

## Prerequis

- **Python 3.8+** (aucune dependance externe pour le scan de base)
- **mysql client** (optionnel, pour `--db`)
- **yara-python** (optionnel, pour `--yara`)

```bash
# Optionnel : installer le support YARA
pip install yara-python
```

---

## Installation

```bash
git clone https://github.com/mabt/an4scan.git
cd an4scan
chmod +x an4scan.py
```

Ou directement :

```bash
curl -sO https://raw.githubusercontent.com/mabt/an4scan/main/an4scan.py
chmod +x an4scan.py
```

---

## Utilisation

### Scan basique

```bash
python3 an4scan.py /var/www/magento2
```

### Scan complet (tous les modules)

```bash
python3 an4scan.py /var/www/magento2 --all
```

### Exemples courants

```bash
# Rapport JSON pour integration CI/CD
python3 an4scan.py /var/www/magento2 --json > report.json

# Seulement les alertes critiques et hautes, 8 workers
python3 an4scan.py /var/www/magento2 -s HIGH -w 8

# Detection de version + CVEs uniquement
python3 an4scan.py /var/www/magento2 --version-check

# Scan DB + permissions + fichiers modifies dans les 14 derniers jours
python3 an4scan.py /var/www/magento2 --db --permissions --mtime --mtime-days 14

# Analyse des access logs (auto-detection ou chemin specifique)
python3 an4scan.py /var/www/magento2 --logs
python3 an4scan.py /var/www/magento2 --logs --log-path /var/log/nginx/access.log

# Scan YARA avec regles externes
python3 an4scan.py /var/www/magento2 --yara --yara-rules /path/to/rules/

# Exclure des chemins (faux positifs connus)
python3 an4scan.py /var/www/magento2 --whitelist vendor/custom app/code/MyModule

# Sauvegarder le rapport
python3 an4scan.py /var/www/magento2 --all -o rapport.txt

# Mode verbose (affiche les erreurs de scan)
python3 an4scan.py /var/www/magento2 --all -v
```

---

## Options completes

```
positional arguments:
  path                    Chemin vers la racine Magento 2

options:
  -h, --help              Aide
  -j, --json              Sortie JSON
  -s, --severity          Niveau minimum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  -w, --workers           Nombre de workers paralleles (defaut: 4)
  -v, --verbose           Sortie detaillee
  -o, --output FILE       Sauvegarder le rapport dans un fichier
  --whitelist PATH...     Chemins a exclure du scan
  --integrity             Verifier l'integrite des fichiers core
  --db                    Scanner la base de donnees
  --permissions           Verifier les permissions fichiers
  --mtime                 Detecter les fichiers core modifies recemment
  --mtime-days N          Fenetre de temps pour --mtime (defaut: 7 jours)
  --yara                  Activer le scan YARA
  --yara-rules PATH       Chemin vers des regles YARA supplementaires
  --version-check         Detecter la version et verifier les CVEs connues
  --logs                  Analyser les access logs
  --log-path PATH...      Chemin(s) vers les fichiers de log (auto-detection sinon)
  --all                   Activer tous les modules
```

---

## Detection de version et CVEs

Le module `--version-check` :

1. **Detecte la version** depuis `composer.lock`, `composer.json`, ou le framework Magento
2. **Identifie l'edition** (Community/Open Source ou Enterprise/Commerce)
3. **Verifie le statut EOL** (End of Life) de la version
4. **Compare avec 25+ CVEs connues** et indique les patches a appliquer

### Base de CVEs integree

Couvre les vulnerabilites critiques de 2022 a 2025 :

| CVE | Severite | Description |
|-----|----------|-------------|
| CVE-2025-24434 | CRITICAL | Privilege escalation via REST API |
| CVE-2024-34102 | CRITICAL | **CosmicSting** - XXE/SSRF leading to RCE (exploite activement) |
| CVE-2024-39401 | CRITICAL | OS Command Injection - RCE authentifie |
| CVE-2024-20720 | CRITICAL | OS Command Injection via layout template (exploite activement) |
| CVE-2022-24086 | CRITICAL | **Template injection** - Pre-auth RCE (exploite massivement) |
| ... | ... | Et 20+ autres CVEs HIGH/CRITICAL |

Exemple de sortie :
```
  MAGENTO VERSION
  ────────────────────────────────────
    Version:  2.4.6-p3
    Edition:  Community (Open Source)
    Source:   composer.lock (product-community-edition)

  KNOWN VULNERABILITIES (CVEs)
  ────────────────────────────────────
  [CRITICAL] CVE-2024-34102
             CosmicSting - XXE/SSRF leading to RCE (ACTIVELY EXPLOITED)
             Affected: <= 2.4.6-p6 | Fix: APSB24-40 / Upgrade to 2.4.7-p1+
```

---

## Analyse des access logs

Le module `--logs` analyse les fichiers de logs Apache/Nginx pour identifier les tentatives d'exploitation.

### Auto-detection des logs

Sans `--log-path`, AN4SCAN cherche automatiquement dans :
- `/var/log/apache2/access.log`
- `/var/log/nginx/access.log`
- `/var/log/httpd/access_log`
- Logs cPanel/Plesk

### Patterns detectes (LOG-001 a LOG-012)

- **CosmicSting** (CVE-2024-34102) - tentatives d'exploitation XXE
- **Template injection** (CVE-2022-24086) - RCE via checkout
- **Brute force admin** - detection par frequence (10+ tentatives = alerte)
- **Upload de fichiers PHP** dans media/pub/static
- **Acces direct a des backdoors** (shell.php, wso.php, etc.)
- **Injections SQL** dans les parametres URL
- **Path traversal** (../../)
- **Enumeration API REST** massive
- **Creation non autorisee de tokens API**

### Rapport des IPs suspectes

Les IPs les plus actives sont regroupees avec le nombre de hits et les patterns detectes :

```
  TOP SUSPICIOUS IPs (from access logs)
  ────────────────────────────────────
    185.220.101.42     47 hits | Patterns: LOG-003, LOG-005, LOG-008
    91.242.217.81      23 hits | Patterns: LOG-001, LOG-006
```

---

## Timeline d'infection

Quand `--mtime` ou `--logs` est active, AN4SCAN construit automatiquement une **chronologie de l'infection** en croisant :

- Les dates de modification des fichiers malveillants detectes
- Les dates de creation des admin users suspects
- Les timestamps des tentatives d'exploitation dans les logs
- La date de dernier `composer update` (point de reference)

```
  INFECTION TIMELINE
  ────────────────────────────────────
  2024-08-15T03:22:11  · Last composer update (reference point)
  2024-09-03T14:33:02  → CosmicSting XXE exploit attempt (CVE-2024-34102)
  2024-09-03T14:35:18  → CosmicSting XXE exploit attempt (CVE-2024-34102)
  2024-09-03T14:41:55  ! Malware detected: eval() with base64_decode
                         pub/media/wysiwyg/.cache.php
  2024-09-03T14:42:03  ~ Core file modified after installation/update
                         vendor/magento/module-payment/Model/Method/Cc.php
  2024-09-04T02:15:00  ⊕ Suspicious admin user created recently
```

Cela permet d'identifier :
- **Le vecteur d'attaque initial** (quelle CVE a ete exploitee)
- **La fenetre de compromission** (quand l'infection a commence)
- **La propagation** (quels fichiers ont ete modifies et dans quel ordre)

---

## Scan de la base de donnees

Le module `--db` lit automatiquement les credentials depuis `app/etc/env.php` et se connecte via le client `mysql` en ligne de commande. Aucune librairie Python supplementaire n'est necessaire.

**Tables scannees :**
- `core_config_data` -- configuration du store (URLs, scripts injectes)
- `cms_block` -- blocs CMS (contenu HTML/JS)
- `cms_page` -- pages CMS (contenu + layout XML)
- `email_template` -- templates d'emails
- `admin_user` -- utilisateurs admin crees recemment
- `cron_schedule` -- taches cron suspectes

---

## Categories de detection

### Skimmers de cartes bancaires (CC-001 a CC-007)
- Patterns de numeros de carte dans le code
- Exfiltration par `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `new Image`
- Domaines Magecart connus (typosquatting Google Analytics, jQuery CDN, etc.)
- Interception de formulaires de paiement
- URLs d'exfiltration encodees en base64

### Backdoors PHP (BD-001 a BD-012)
- `eval(base64_decode(...))` et variantes
- Webshells connus : WSO, C99, R57, B374K, FilesMan
- Execution directe de `$_GET`/`$_POST`/`$_REQUEST`
- `preg_replace` avec modificateur `/e`
- Upload de fichiers arbitraires
- Construction dynamique de fonctions (`chr()`, hex)

### Obfuscation (OB-001 a OB-007 + OB-ENT)
- Chaines de decodage imbriquees (base64 > gzinflate > str_rot13...)
- Longues chaines base64 (>500 caracteres)
- Variables variables `${$var}()`
- Analyse d'entropie de Shannon (detecte le code obfusque sans signature connue)
- ionCube / Zend Guard (peut cacher du malware)

### Patterns Magento (MG-001 a MG-008)
- Modification de modeles de paiement core
- Observers malveillants sur les evenements checkout
- Creation d'utilisateurs admin non autorisee
- Modification de `env.php` / `config.php`
- Modules non autorises avec du code suspect

### Menaces serveur (SV-001 a SV-004)
- Redirections `.htaccess` vers des domaines malveillants
- `.htaccess` autorisant l'execution PHP dans les dossiers d'upload
- Malware persistant via cron jobs
- Utilisation de `mail()` pour exfiltration

### Noms de fichiers suspects
- PHP dans `media/`, `static/`, `var/`, `cache/`
- Fichiers caches (`.x.php`)
- Double extensions (`.php.jpg`)
- Fichiers WordPress dans une installation Magento
- Utilitaires dangereux (`adminer.php`, `phpinfo.php`)

### Injections en base de donnees (DBI-001 a DBI-010)
- Scripts JS injectes dans les blocs CMS et pages
- Tags `<script>` chargeant des domaines externes
- Payloads base64 dans le contenu DB
- Iframes injectees
- Code PHP dans les champs de la base
- Utilisateurs admin suspects (emails jetables, noms generiques)
- Cron jobs suspects dans `cron_schedule`

### Permissions (PERM-001 a PERM-005)
- Fichiers et dossiers world-writable
- Bits SUID/SGID sur les scripts
- PHP executable dans les repertoires web
- `env.php` lisible par tous

### Regles YARA integrees
- `magento_skimmer_generic` -- Skimmer de carte generique
- `php_webshell_generic` -- Webshell/backdoor PHP
- `php_backdoor_obfuscated` -- Backdoor PHP obfusquee
- `magento_malware_known` -- Familles de malware Magento connues
- `php_in_image` -- Code PHP cache dans des images
- `suspicious_js_obfuscation` -- JavaScript fortement obfusque
- `magento_config_theft` -- Vol de configuration/credentials

---

## Support YARA

### Regles integrees

AN4SCAN inclut 7 regles YARA precompilees couvrant les menaces les plus courantes. Elles sont activees automatiquement avec `--yara`.

### Regles externes

Vous pouvez charger vos propres regles ou des regles communautaires :

```bash
# Un seul fichier
python3 an4scan.py /var/www/magento2 --yara --yara-rules custom_rules.yar

# Un dossier complet (charge tous les .yar et .yara)
python3 an4scan.py /var/www/magento2 --yara --yara-rules /etc/yara-rules/
```

Compatibles avec les rulesets publics :
- [Sansec](https://sansec.io/) (eComscan signatures)
- [THOR](https://www.nextron-systems.com/thor/) / [signature-base](https://github.com/Neo23x0/signature-base)
- [YARA-Rules](https://github.com/Yara-Rules/rules)

---

## Codes de sortie

| Code | Signification |
|------|---------------|
| `0` | Aucune alerte critique ou haute |
| `1` | Au moins un finding HIGH |
| `2` | Au moins un finding CRITICAL |

Utile pour l'integration CI/CD :

```bash
python3 an4scan.py /var/www/magento2 -s HIGH --json > report.json
if [ $? -eq 2 ]; then
  echo "CRITICAL: malware detecte!"
  # envoyer une alerte...
fi
```

---

## Faux positifs

Certains patterns legitimes peuvent declencher des alertes (ex: `eval()` dans des librairies, base64 dans du code legitime). Strategies pour gerer les faux positifs :

1. **Whitelist** : `--whitelist vendor/legitimate-module app/code/MyModule`
2. **Filtrer par severite** : `-s HIGH` pour ignorer les MEDIUM/LOW
3. **Paths auto-whitelistes** : `vendor/phpunit`, `dev/tests`, `setup/src`, `lib/internal/Magento/Framework/Code/Generator`

---

## Licence

MIT

---

## Contribuer

Les contributions sont les bienvenues. En particulier :

- Nouvelles signatures de malware Magento
- Regles YARA supplementaires
- Mise a jour de la base de CVEs
- Reduction des faux positifs
- Nouveaux patterns de detection dans les logs
- Support d'autres CMS e-commerce (WooCommerce, PrestaShop)
