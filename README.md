# AN4SCAN — CMS Malware & Vulnerability Scanner

Single-binary security scanner for **Magento 2**, **WordPress**, and **PrestaShop**. Auto-detects the CMS, then runs targeted checks: backdoors, skimmers, obfuscated code, plugin vulnerabilities, core file integrity, database injections, known CVEs, and exploit attempts in access logs.

No dependencies. Just download and run.

<p align="center">
  <img src="demo.gif" alt="AN4SCAN Demo" width="800">
</p>

## Install

### One-liner (Linux x86_64)

```bash
curl -sL https://github.com/mabt/an4scan/releases/latest/download/an4scan-linux-amd64 -o /usr/local/bin/an4scan && chmod +x /usr/local/bin/an4scan
```

### Other platforms

| Platform | Command |
|----------|---------|
| Linux x86_64 | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-linux-amd64 && chmod +x /usr/local/bin/an4scan` |
| Linux ARM64 | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-linux-arm64 && chmod +x /usr/local/bin/an4scan` |
| macOS Intel | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-darwin-amd64 && chmod +x /usr/local/bin/an4scan` |
| macOS ARM (M1+) | `curl -sLo /usr/local/bin/an4scan https://github.com/mabt/an4scan/releases/latest/download/an4scan-darwin-arm64 && chmod +x /usr/local/bin/an4scan` |

### Build from source

```bash
git clone https://github.com/mabt/an4scan.git
cd an4scan && go build -o an4scan .
```

## Quick Start

```bash
# Scan a site (auto-detects CMS)
an4scan /var/www/html

# Full audit (all modules)
an4scan /var/www/html -all

# Full audit + HTML report
an4scan /var/www/html -all -html report.html
```

## Features

| Module | Flag | What it does |
|--------|------|--------------|
| **File scan** | *(always on)* | 80+ regex signatures: backdoors, skimmers, webshells, obfuscation, CMS-specific patterns |
| **CMS detection** | *(automatic)* | Auto-detect Magento 2, WordPress, PrestaShop — loads CMS-specific signatures |
| **Version + CVEs** | `-version` | Detect version, check against 60+ known CVEs (Magento, WP, PrestaShop) |
| **Plugin scan** | `-plugins` | List plugins/modules, check against known vulnerable versions |
| **Core integrity** | `-integrity` | WordPress: verify checksums via wordpress.org API. Magento/PS: mtime-based |
| **Database scan** | `-db` | Scan CMS tables for injected scripts, suspicious admins, cron jobs |
| **Log analysis** | `-logs` | Parse Apache/Nginx logs for exploit attempts, brute force, SQLi |
| **Permissions** | `-permissions` | World-writable files, SUID/SGID, readable credentials |
| **Modified files** | `-mtime` | Core files modified after install |
| **YARA scan** | `-yara` | 4 built-in rules + auto-load community rulesets (~1700 rules) |
| **Timeline** | *(automatic)* | Reconstructs infection timeline from findings |
| **All modules** | `-all` | Enable everything above |

### Output modes

| Flag | Description |
|------|-------------|
| `-html report.html` | Standalone HTML report (dark theme, no external deps) |
| `-j` / `-json` | JSON output |
| `-q` / `-quiet` | One-line summary |
| `-o FILE` | Write text report to file |
| `-save` | Save scan results for future diffing |
| `-diff auto` | Compare with last saved scan (show new/resolved findings) |

## Usage Examples

### Quick scan (confirmed threats only)

```bash
an4scan /var/www/html
```

Only CRITICAL/HIGH findings shown by default.

### Deep scan (include suspicions)

```bash
an4scan /var/www/html -deep
```

Also reports MEDIUM/LOW/INFO: obfuscation, unusual files, low-confidence matches.

### Full audit

```bash
an4scan /var/www/html -all              # confirmed threats only
an4scan /var/www/html -all -deep        # everything
```

### Plugin vulnerability check

```bash
an4scan /var/www/html -plugins -version
```

Detects installed plugins/modules, checks versions against known CVEs. Supports:
- **WordPress**: plugins, themes, mu-plugins (reads PHP headers)
- **PrestaShop**: modules (reads `$this->version`)
- **Magento**: extensions from `composer.lock` + `app/code/`

### Core file integrity

```bash
an4scan /var/www/html -integrity
```

- **WordPress**: fetches official checksums from `api.wordpress.org`, verifies every core file MD5. Detects unknown PHP files in `wp-admin/` and `wp-includes/`.
- **Magento/PrestaShop**: detects core files modified after last install.

### HTML report

```bash
an4scan /var/www/html -all -html report.html
```

Produces a standalone HTML file with dark theme. Includes all findings, CVEs, plugin vulnerabilities, integrity results, timeline, and suspicious IPs.

### Diff between scans

```bash
# First scan — save results
an4scan /var/www/html -all -save

# Later — compare with last saved scan
an4scan /var/www/html -all -diff auto
```

Shows new findings and resolved findings since the last scan.

### Other examples

```bash
# JSON export for CI/CD
an4scan /var/www/html -all -j > report.json

# DB + permissions + recently modified files (14 days)
an4scan /var/www/html -db -permissions -mtime -mtime-days 14

# Access log analysis with custom path
an4scan /var/www/html -logs -log-path /var/log/nginx/access.log

# YARA scan with custom rules
an4scan /var/www/html -yara -yara-rules /path/to/rules/

# Exclude paths (known false positives)
an4scan /var/www/html -whitelist vendor/custom,app/code/MyModule

# One-line summary only
an4scan /var/www/html -all -q

# Download community YARA rulesets
an4scan -update

# Show installed rulesets
an4scan -status
```

## CMS-Specific Detection

### Magento 2

- 40+ file signatures (skimmers, backdoor patterns, core tampering)
- 27 known CVEs (CosmicSting, template injection, command injection...)
- Extension vulnerability database
- DB scan: `core_config_data`, `cms_block`, `cms_page`, `email_template`, admin users, cron

### WordPress

- 12 WP-specific signatures (WooCommerce skimmers, plugin backdoors, SEO spam, xmlrpc abuse)
- 14 core CVEs + 25 plugin CVEs (Elementor, LiteSpeed Cache, Wordfence, WooCommerce, Contact Form 7...)
- Core integrity via official wordpress.org checksums API
- 7 WP-specific log patterns (wp-login brute force, xmlrpc, REST API enumeration)

### PrestaShop

- 11 PS-specific signatures (module backdoors, Smarty template injection, payment hooks)
- 16 core CVEs + 10 module CVEs (SQL Manager RCE, pk_faq, blockwishlist...)
- 5 PS-specific log patterns (admin brute force, module exploits, SQL Manager)

## Options Reference

```
  path                    CMS root path (auto-detects Magento/WordPress/PrestaShop)

scan modules:
  -all                    Enable all modules
  -deep                   Include suspicions (default: confirmed threats only)
  -db                     Scan database for injected malware
  -version                Detect version and check known CVEs
  -plugins                Scan plugins/modules for known vulnerabilities
  -integrity              Check core file integrity (WP: official checksums)
  -mtime                  Recently modified core files
  -mtime-days N           Time window for -mtime (default: 7)
  -permissions            Check file permissions
  -logs                   Analyze access logs for exploit attempts
  -log-path PATH          Access log file path(s), comma-separated
  -yara                   Enable YARA scanning
  -yara-rules PATH        Additional YARA rules file or directory

output:
  -j, -json               JSON output
  -html FILE              Write HTML report
  -o, -output FILE        Save text report to file
  -q, -quiet              One-line summary only
  -s, -severity LEVEL     Override severity filter (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  -v, -verbose            Show scan errors

diff:
  -save                   Save scan for future diffing (in .an4scan/)
  -diff PATH              Compare with previous scan JSON ("auto" for last saved)

tuning:
  -w, -workers N          Parallel workers (default: 4)
  -whitelist PATHS        Comma-separated paths to exclude from scan

ruleset management:
  -update                 Download/update community YARA rulesets
  -status                 Show installed YARA rulesets
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one HIGH finding |
| `2` | At least one CRITICAL finding |

```bash
an4scan /var/www/html -all -q
if [ $? -eq 2 ]; then
  echo "CRITICAL: malware detected!"
fi
```

## YARA Support

The built-in regex signatures cover most threats. YARA adds binary-level detection for advanced/custom malware.

```bash
# Download community rulesets (~1700 rule files)
an4scan -update

# Scan with YARA
an4scan /var/www/html -yara
```

Bundled rulesets: [Sansec](https://github.com/gwillem/magento-malware-scanner), [Mage Security Council](https://github.com/magesec/magesecurityscanner), [Neo23x0](https://github.com/Neo23x0/signature-base), [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules), [Elastic](https://github.com/elastic/protections-artifacts).

## License

MIT
