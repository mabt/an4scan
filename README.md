# AN4SCAN - Magento 2 Malware Scanner

Scanner de s&eacute;curit&eacute; d&eacute;fensif pour les installations Magento 2. D&eacute;tecte les fichiers infect&eacute;s, les backdoors PHP, les skimmers de cartes bancaires (Magecart), le code obfusqu&eacute;, les injections en base de donn&eacute;es et les probl&egrave;mes de permissions.

Inspir&eacute; par des outils comme [eComscan](https://sansec.io/ecomscan), AN4SCAN est un outil open-source et gratuit con&ccedil;u pour &ecirc;tre utilis&eacute; en audit, forensics ou surveillance continue.

---

## Fonctionnalit&eacute;s

| Module | Flag | Description |
|--------|------|-------------|
| **File Scan** | *(toujours actif)* | 60+ signatures regex : skimmers CC, backdoors, webshells, obfuscation, patterns Magento sp&eacute;cifiques |
| **Database Scan** | `--db` | Analyse les tables `core_config_data`, `cms_block`, `cms_page`, `email_template` + v&eacute;rifie les admin users suspects et les cron jobs |
| **Permission Check** | `--permissions` | D&eacute;tecte fichiers/dossiers world-writable, SUID/SGID sur scripts, `env.php` world-readable |
| **Modified Files** | `--mtime` | Compare les dates de modification des fichiers core vs `composer.lock`, d&eacute;tecte les PHP r&eacute;cents dans `pub/media`, `var`, etc. |
| **YARA Scan** | `--yara` | 7 r&egrave;gles YARA int&eacute;gr&eacute;es + support de r&egrave;gles externes (Sansec, THOR, custom) |
| **Integrity Check** | `--integrity` | V&eacute;rifie les overrides de fichiers core dans `app/code/Magento` |
| **Tout activer** | `--all` | Active tous les modules ci-dessus |

---

## Pr&eacute;requis

- **Python 3.8+** (aucune d&eacute;pendance externe pour le scan de base)
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
# Rapport JSON pour int&eacute;gration CI/CD
python3 an4scan.py /var/www/magento2 --json > report.json

# Seulement les alertes critiques et hautes, 8 workers
python3 an4scan.py /var/www/magento2 -s HIGH -w 8

# Scan DB + permissions + fichiers modifi&eacute;s dans les 14 derniers jours
python3 an4scan.py /var/www/magento2 --db --permissions --mtime --mtime-days 14

# Scan YARA avec r&egrave;gles externes
python3 an4scan.py /var/www/magento2 --yara --yara-rules /path/to/rules/

# Exclure des chemins (faux positifs connus)
python3 an4scan.py /var/www/magento2 --whitelist vendor/custom app/code/MyModule

# Sauvegarder le rapport
python3 an4scan.py /var/www/magento2 --all -o rapport.txt

# Mode verbose (affiche les erreurs de scan)
python3 an4scan.py /var/www/magento2 --all -v
```

---

## Options compl&egrave;tes

```
positional arguments:
  path                    Chemin vers la racine Magento 2

options:
  -h, --help              Aide
  -j, --json              Sortie JSON
  -s, --severity          Niveau minimum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  -w, --workers           Nombre de workers parall&egrave;les (d&eacute;faut: 4)
  -v, --verbose           Sortie d&eacute;taill&eacute;e
  -o, --output FILE       Sauvegarder le rapport dans un fichier
  --whitelist PATH...     Chemins &agrave; exclure du scan
  --integrity             V&eacute;rifier l'int&eacute;grit&eacute; des fichiers core
  --db                    Scanner la base de donn&eacute;es
  --permissions           V&eacute;rifier les permissions fichiers
  --mtime                 D&eacute;tecter les fichiers core modifi&eacute;s r&eacute;cemment
  --mtime-days N          Fen&ecirc;tre de temps pour --mtime (d&eacute;faut: 7 jours)
  --yara                  Activer le scan YARA
  --yara-rules PATH       Chemin vers des r&egrave;gles YARA suppl&eacute;mentaires
  --all                   Activer tous les modules
```

---

## Cat&eacute;gories de d&eacute;tection

### Skimmers de cartes bancaires (CC-001 &agrave; CC-007)
- Patterns de num&eacute;ros de carte dans le code
- Exfiltration par `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `new Image`
- Domaines Magecart connus (typosquatting Google Analytics, jQuery CDN, etc.)
- Interception de formulaires de paiement
- URLs d'exfiltration encod&eacute;es en base64

### Backdoors PHP (BD-001 &agrave; BD-012)
- `eval(base64_decode(...))` et variantes
- Webshells connus : WSO, C99, R57, B374K, FilesMan
- Ex&eacute;cution directe de `$_GET`/`$_POST`/`$_REQUEST`
- `preg_replace` avec modificateur `/e`
- Upload de fichiers arbitraires
- Construction dynamique de fonctions (`chr()`, hex)

### Obfuscation (OB-001 &agrave; OB-007 + OB-ENT)
- Cha&icirc;nes de d&eacute;codage imbriqu&eacute;es (base64 > gzinflate > str_rot13...)
- Longues cha&icirc;nes base64 (>500 caract&egrave;res)
- Variables variables `${$var}()`
- Analyse d'entropie de Shannon (d&eacute;tecte le code obfusqu&eacute; sans signature connue)
- ionCube / Zend Guard (peut cacher du malware)

### Patterns Magento (MG-001 &agrave; MG-008)
- Modification de mod&egrave;les de paiement core
- Observers malveillants sur les &eacute;v&eacute;nements checkout
- Cr&eacute;ation d'utilisateurs admin non autoris&eacute;e
- Modification de `env.php` / `config.php`
- Modules non autoris&eacute;s avec du code suspect

### Menaces serveur (SV-001 &agrave; SV-004)
- Redirections `.htaccess` vers des domaines malveillants
- `.htaccess` autorisant l'ex&eacute;cution PHP dans les dossiers d'upload
- Malware persistant via cron jobs
- Utilisation de `mail()` pour exfiltration

### Noms de fichiers suspects
- PHP dans `media/`, `static/`, `var/`, `cache/`
- Fichiers cach&eacute;s (`.x.php`)
- Double extensions (`.php.jpg`)
- Fichiers WordPress dans une installation Magento
- Utilitaires dangereux (`adminer.php`, `phpinfo.php`)

### Injections en base de donn&eacute;es (DBI-001 &agrave; DBI-010)
- Scripts JS inject&eacute;s dans les blocs CMS et pages
- Tags `<script>` chargeant des domaines externes
- Payloads base64 dans le contenu DB
- Iframes inject&eacute;es
- Code PHP dans les champs de la base
- Utilisateurs admin suspects (emails jetables, noms g&eacute;n&eacute;riques)
- Cron jobs suspects dans `cron_schedule`

### Permissions (PERM-001 &agrave; PERM-005)
- Fichiers et dossiers world-writable
- Bits SUID/SGID sur les scripts
- PHP ex&eacute;cutable dans les r&eacute;pertoires web
- `env.php` lisible par tous

### R&egrave;gles YARA int&eacute;gr&eacute;es
- `magento_skimmer_generic` &mdash; Skimmer de carte g&eacute;n&eacute;rique
- `php_webshell_generic` &mdash; Webshell/backdoor PHP
- `php_backdoor_obfuscated` &mdash; Backdoor PHP obfusqu&eacute;e
- `magento_malware_known` &mdash; Familles de malware Magento connues
- `php_in_image` &mdash; Code PHP cach&eacute; dans des images
- `suspicious_js_obfuscation` &mdash; JavaScript fortement obfusqu&eacute;
- `magento_config_theft` &mdash; Vol de configuration/credentials

---

## Codes de sortie

| Code | Signification |
|------|---------------|
| `0` | Aucune alerte critique ou haute |
| `1` | Au moins un finding HIGH |
| `2` | Au moins un finding CRITICAL |

Utile pour l'int&eacute;gration CI/CD :

```bash
python3 an4scan.py /var/www/magento2 -s HIGH --json > report.json
if [ $? -eq 2 ]; then
  echo "CRITICAL: malware d&eacute;tect&eacute;!"
  # envoyer une alerte...
fi
```

---

## Scan de la base de donn&eacute;es

Le module `--db` lit automatiquement les credentials depuis `app/etc/env.php` et se connecte via le client `mysql` en ligne de commande. Aucune librairie Python suppl&eacute;mentaire n'est n&eacute;cessaire.

**Tables scann&eacute;es :**
- `core_config_data` &mdash; configuration du store (URLs, scripts inject&eacute;s)
- `cms_block` &mdash; blocs CMS (contenu HTML/JS)
- `cms_page` &mdash; pages CMS (contenu + layout XML)
- `email_template` &mdash; templates d'emails
- `admin_user` &mdash; utilisateurs admin cr&eacute;&eacute;s r&eacute;cemment
- `cron_schedule` &mdash; t&acirc;ches cron suspectes

---

## Support YARA

### R&egrave;gles int&eacute;gr&eacute;es

AN4SCAN inclut 7 r&egrave;gles YARA pr&eacute;compil&eacute;es couvrant les menaces les plus courantes. Elles sont activ&eacute;es automatiquement avec `--yara`.

### R&egrave;gles externes

Vous pouvez charger vos propres r&egrave;gles ou des r&egrave;gles communautaires :

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

## Faux positifs

Certains patterns l&eacute;gitimes peuvent d&eacute;clencher des alertes (ex: `eval()` dans des librairies, base64 dans du code l&eacute;gitime). Strat&eacute;gies pour g&eacute;rer les faux positifs :

1. **Whitelist** : `--whitelist vendor/legitimate-module app/code/MyModule`
2. **Filtrer par s&eacute;v&eacute;rit&eacute;** : `-s HIGH` pour ignorer les MEDIUM/LOW
3. **Paths auto-whitelist&eacute;s** : `vendor/phpunit`, `dev/tests`, `setup/src`, `lib/internal/Magento/Framework/Code/Generator`

---

## Exemple de sortie

```
╔══════════════════════════════════════════════════════╗
║                  AN4SCAN v2.0                        ║
║          Magento 2 Malware Scanner                   ║
╚══════════════════════════════════════════════════════╝

  Scanning: /var/www/magento2
  Workers:  4
  Modules:  DB, MTIME(7d), PERMS, YARA

  Found 12847 files to scan...
  Progress: 12847/12847 files scanned.

════════════════════════════════════════════════════════════
  SCAN REPORT
════════════════════════════════════════════════════════════
  Path:     /var/www/magento2
  Duration: 8.34s
  Files:    12847 scanned

  SUMMARY
  ────────────────────────────────────
  Total findings:     3
  Affected files:     2

    CRITICAL  : 1
    HIGH      : 2

  ⚠  HIGH RISK - 1 critical finding(s) detected!
  Immediate investigation recommended.
```

---

## Licence

MIT

---

## Contribuer

Les contributions sont les bienvenues. En particulier :

- Nouvelles signatures de malware Magento
- R&egrave;gles YARA suppl&eacute;mentaires
- R&eacute;duction des faux positifs
- Support d'autres CMS e-commerce (WooCommerce, PrestaShop)
