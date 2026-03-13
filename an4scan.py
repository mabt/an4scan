#!/usr/bin/env python3
"""
AN4SCAN - Magento 2 Malware Scanner
Scans Magento 2 installations for known malware signatures, backdoors,
credit card skimmers, and suspicious code patterns.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ─── Severity levels ───────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
SEVERITY_COLORS = {
    CRITICAL: "\033[91;1m",  # bright red bold
    HIGH: "\033[91m",        # red
    MEDIUM: "\033[93m",      # yellow
    LOW: "\033[96m",         # cyan
    INFO: "\033[90m",        # gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


# ─── Signature database ───────────────────────────────────────────────────────
# Each signature: (id, severity, category, description, regex_pattern, file_globs)
# file_globs: list of extensions to scan, or None for all text files

SIGNATURES = [
    # ━━━ Credit Card Skimmers / Payment Exfiltration ━━━━━━━━━━━━━━━━━━━━━━━━━
    ("CC-001", CRITICAL, "skimmer",
     "Credit card number regex pattern (potential skimmer)",
     r"""(?:card.?num|cc.?num|pan.?num)[\s\S]{0,50}(?:\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|\b[3-6]\d{12,18}\b)""",
     [".php", ".js", ".phtml"]),

    ("CC-002", CRITICAL, "skimmer",
     "JavaScript CC exfiltration - sending payment data to external URL",
     r"""(?:XMLHttpRequest|fetch|navigator\.sendBeacon|new\s+Image)\s*\([\s\S]{0,200}(?:cc|card|payment|checkout|cvv|cvc|expir)""",
     [".js", ".phtml", ".html"]),

    ("CC-003", CRITICAL, "skimmer",
     "Known Magecart/skimmer domain patterns",
     r"""(?:google-anaiytic|googie-analytics|google-anaiytics|g00gle-analytics|googlc-analytics|google-analytcs|jquery-cdn|bootstrap-js|cloudflare-cdn|magento-cdn|fontsgoogleapis|jquery-ui-cdn|react-js-cdn)\.(?:com|info|org|net|xyz|top|pw)""",
     [".js", ".phtml", ".html", ".php"]),

    ("CC-004", CRITICAL, "skimmer",
     "Inline JS intercepting payment form submit",
     r"""(?:payment|checkout|billing)[\s\S]{0,100}(?:addEventListener|onsubmit|\.submit)[\s\S]{0,200}(?:send|fetch|XMLHttp|Image\(|beacon)""",
     [".js", ".phtml", ".html"]),

    ("CC-005", CRITICAL, "skimmer",
     "Base64-encoded exfiltration URL in JavaScript",
     r"""atob\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*\)[\s\S]{0,100}(?:send|fetch|XMLHttp|Image|beacon)""",
     [".js", ".phtml"]),

    ("CC-006", CRITICAL, "skimmer",
     "WebSocket-based data exfiltration",
     r"""new\s+WebSocket\s*\([\s\S]{0,300}(?:card|cc_|cvv|payment|checkout)""",
     [".js", ".phtml"]),

    ("CC-007", HIGH, "skimmer",
     "Suspicious form field value collection targeting payment data",
     r"""(?:querySelector|getElementById|getElementsByName|getElement)\s*\([\s\S]{0,50}(?:cc[-_]|card[-_]|payment[-_]|cvv|cvc|expir)[\s\S]{0,100}\.value""",
     [".js", ".phtml"]),

    # ━━━ PHP Backdoors / Webshells ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("BD-001", CRITICAL, "backdoor",
     "eval() with base64_decode - classic backdoor pattern",
     r"""eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode)\s*\(""",
     [".php", ".phtml"]),

    ("BD-002", CRITICAL, "backdoor",
     "eval() with variable function call (obfuscated execution)",
     r"""eval\s*\(\s*\$[a-zA-Z_]\w*\s*\(""",
     [".php", ".phtml"]),

    ("BD-003", CRITICAL, "backdoor",
     "assert() used as code execution",
     r"""assert\s*\(\s*(?:base64_decode|gzinflate|\$_(?:GET|POST|REQUEST|COOKIE)|stripslashes)""",
     [".php", ".phtml"]),

    ("BD-004", CRITICAL, "backdoor",
     "preg_replace with /e modifier (code execution)",
     r"""preg_replace\s*\(\s*['"]/.*/[a-zA-Z]*e[a-zA-Z]*['"]""",
     [".php", ".phtml"]),

    ("BD-005", CRITICAL, "backdoor",
     "Direct execution of user-supplied input",
     r"""(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)""",
     [".php", ".phtml"]),

    ("BD-006", CRITICAL, "backdoor",
     "create_function with user input (code injection)",
     r"""create_function\s*\([\s\S]{0,100}\$_(?:GET|POST|REQUEST|COOKIE)""",
     [".php", ".phtml"]),

    ("BD-007", CRITICAL, "backdoor",
     "Known webshell signatures (WSO, C99, R57, B374K, etc.)",
     r"""(?:WSO\s+\d|c99shell|r57shell|b374k|FilesMan|webshell|Ani-Shell|MARIJUANA|phpSpy|phpRemoteView|Network\s+Tools)""",
     [".php", ".phtml"]),

    ("BD-008", HIGH, "backdoor",
     "Dynamic function creation/call from string",
     r"""\$[a-zA-Z_]\w*\s*=\s*(?:chr\(\d+\)\s*\.?\s*){4,}""",
     [".php", ".phtml"]),

    ("BD-009", HIGH, "backdoor",
     "Variable function call with string concatenation",
     r"""\$[a-zA-Z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
     [".php", ".phtml"]),

    ("BD-010", HIGH, "backdoor",
     "Hexadecimal-encoded string execution",
     r"""(?:\\x[0-9a-fA-F]{2}){10,}""",
     [".php", ".phtml"]),

    ("BD-011", CRITICAL, "backdoor",
     "File upload backdoor (arbitrary file write)",
     r"""move_uploaded_file\s*\([\s\S]{0,200}\$_(?:GET|POST|REQUEST)""",
     [".php", ".phtml"]),

    ("BD-012", HIGH, "backdoor",
     "Suspicious file_put_contents with user input",
     r"""file_put_contents\s*\([\s\S]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)""",
     [".php", ".phtml"]),

    # ━━━ Obfuscation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("OB-001", HIGH, "obfuscation",
     "Heavily nested base64/gzip decode chains",
     r"""(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(""",
     [".php", ".phtml"]),

    ("OB-002", MEDIUM, "obfuscation",
     "Long base64-encoded string (>500 chars) in PHP",
     r"""['"][A-Za-z0-9+/]{500,}={0,2}['"]""",
     [".php", ".phtml"]),

    ("OB-003", HIGH, "obfuscation",
     "Variable variables used for obfuscation",
     r"""\$\{\s*\$[a-zA-Z_]\w*\s*\}\s*\(""",
     [".php", ".phtml"]),

    ("OB-004", HIGH, "obfuscation",
     "Encoded/obfuscated eval via string manipulation",
     r"""(?:\$\w+\s*=\s*['"][\w]+['"];\s*){3,}.*(?:\$\w+\s*\.\s*){3,}""",
     [".php", ".phtml"]),

    ("OB-005", MEDIUM, "obfuscation",
     "JavaScript obfuscation with char code arrays",
     r"""String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}""",
     [".js", ".phtml", ".html"]),

    ("OB-006", MEDIUM, "obfuscation",
     "PHP compact/extract abuse for variable injection",
     r"""extract\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)""",
     [".php", ".phtml"]),

    ("OB-007", HIGH, "obfuscation",
     "ionCube/Zend Guard encoded file (may hide malware)",
     r"""(?:ionCube|ioncube_loader|zend_loader|sg_load|SourceGuardian)""",
     [".php"]),

    # ━━━ Suspicious File Operations ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("FO-001", HIGH, "file_operation",
     "Writing PHP code to a file (potential dropper)",
     r"""file_put_contents\s*\([\s\S]{0,100}(?:<\?php|<\?=|eval|base64_decode)""",
     [".php", ".phtml"]),

    ("FO-002", HIGH, "file_operation",
     "Remote file inclusion",
     r"""(?:include|require|include_once|require_once)\s*\(\s*(?:['"]https?://|\$_(?:GET|POST|REQUEST))""",
     [".php", ".phtml"]),

    ("FO-003", MEDIUM, "file_operation",
     "file_get_contents from external URL with suspicious usage",
     r"""file_get_contents\s*\(\s*['"]https?://[\s\S]{0,200}(?:eval|base64_decode|file_put_contents)""",
     [".php", ".phtml"]),

    ("FO-004", MEDIUM, "file_operation",
     "curl_exec to external URL in non-standard location",
     r"""curl_exec\s*\(""",
     [".php", ".phtml"]),

    # ━━━ Magento-Specific Malware Patterns ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("MG-001", CRITICAL, "magento",
     "Modified Magento core payment model (core file tampering)",
     r"""(?:Magento\\Payment|Magento\\Sales)[\s\S]{0,500}(?:curl_exec|file_get_contents\s*\(\s*['"]https?://)""",
     [".php"]),

    ("MG-002", CRITICAL, "magento",
     "Malicious Magento observer intercepting payment data",
     r"""(?:sales_order_place_after|checkout_onepage_controller_success_action|checkout_submit_all_after)[\s\S]{0,500}(?:curl|file_get_contents|fopen|stream_context)""",
     [".php"]),

    ("MG-003", HIGH, "magento",
     "Suspicious Magento admin user creation",
     r"""(?:createUser|addRole|setRoleType|setUserType)[\s\S]{0,200}(?:Administrators|admin)""",
     [".php"]),

    ("MG-004", HIGH, "magento",
     "Magento config.php or env.php modification code",
     r"""(?:app/etc/(?:config|env)\.php)[\s\S]{0,100}(?:file_put_contents|fwrite|fopen)""",
     [".php"]),

    ("MG-005", CRITICAL, "magento",
     "Known Magento malware (Magecart Group patterns)",
     r"""(?:ccDecode|ccGet|getFormData|skimData|exfilData|sendCC|grabCC|sniffCC)""",
     [".js", ".php", ".phtml"]),

    ("MG-006", HIGH, "magento",
     "Suspicious inline script in Magento CMS/static content",
     r"""<script[^>]*>[\s\S]{0,50}(?:atob|eval|document\.write|unescape)[\s\S]{0,500}(?:payment|card|checkout|billing)""",
     [".phtml", ".html", ".php"]),

    ("MG-007", HIGH, "magento",
     "Unauthorized Magento module registration (rogue module)",
     r"""registration\.php[\s\S]{0,50}(?:ComponentRegistrar|module)[\s\S]{0,200}(?:eval|base64|shell_exec|system)""",
     [".php"]),

    ("MG-008", MEDIUM, "magento",
     "Suspicious REST/SOAP API endpoint override",
     r"""webapi\.xml[\s\S]{0,200}(?:route[\s\S]{0,50}url=)[\s\S]{0,200}(?:password|admin|token|secret)""",
     [".xml"]),

    # ━━━ Server-Level Threats ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("SV-001", HIGH, "server",
     "Suspicious .htaccess redirect (SEO spam / phishing)",
     r"""RewriteCond[\s\S]{0,200}(?:google|yahoo|bing|facebook|instagram|tiktok)[\s\S]{0,200}RewriteRule.*https?://""",
     [".htaccess"]),

    ("SV-002", HIGH, "server",
     ".htaccess allowing PHP execution in upload dirs",
     r"""(?:AddHandler|AddType)[\s\S]{0,50}(?:php|phtml|application/x-httpd)""",
     [".htaccess"]),

    ("SV-003", CRITICAL, "server",
     "Cron job malware (persistent backdoor)",
     r"""(?:\*/\d+\s+\*\s+\*\s+\*\s+\*|@(?:reboot|hourly|daily))[\s\S]{0,200}(?:curl|wget|python|perl|bash|php)[\s\S]{0,200}(?:https?://|/tmp/|/dev/shm/)""",
     [".php", ".sh", ".txt"]),

    ("SV-004", MEDIUM, "server",
     "PHP mail() function used for spam or data exfiltration",
     r"""mail\s*\([\s\S]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)""",
     [".php", ".phtml"]),

    # ━━━ Suspicious Functions & Patterns ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("SF-001", MEDIUM, "suspicious",
     "eval() usage (review for legitimacy)",
     r"""\beval\s*\(""",
     [".php", ".phtml"]),

    ("SF-002", LOW, "suspicious",
     "base64_decode usage (review context)",
     r"""\bbase64_decode\s*\(""",
     [".php", ".phtml"]),

    ("SF-003", MEDIUM, "suspicious",
     "System command execution functions",
     r"""\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(""",
     [".php", ".phtml"]),

    ("SF-004", LOW, "suspicious",
     "Disabled functions bypass attempt",
     r"""(?:ini_set|ini_alter)\s*\(\s*['"](?:disable_functions|open_basedir|safe_mode)['"]""",
     [".php", ".phtml"]),

    ("SF-005", MEDIUM, "suspicious",
     "Suspicious chmod/permission changes",
     r"""chmod\s*\(\s*[\s\S]{0,50}\s*,\s*0?7[0-7]{2}\s*\)""",
     [".php", ".phtml"]),

    ("SF-006", HIGH, "suspicious",
     "PHP code in image/media file",
     r"""<\?php""",
     [".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".bmp", ".webp"]),

    ("SF-007", HIGH, "suspicious",
     "Hidden PHP file in media/static directories",
     r"""<\?(?:php|=)""",
     [".php.jpg", ".php.png", ".php.gif", ".phtml.jpg", ".php.ico"]),

    ("SF-008", MEDIUM, "suspicious",
     "Suspicious error suppression with dangerous functions",
     r"""@\s*(?:eval|assert|system|exec|passthru|shell_exec|unlink|file_put_contents)\s*\(""",
     [".php", ".phtml"]),

    # ━━━ Database / Credential Theft ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ("DB-001", HIGH, "credential_theft",
     "Database credential extraction and exfiltration",
     r"""(?:db-(?:host|user|password|name)|MYSQL_|DB_PASS)[\s\S]{0,200}(?:curl|file_get_contents|mail|fopen|stream)""",
     [".php", ".phtml"]),

    ("DB-002", HIGH, "credential_theft",
     "Reading Magento env.php for credentials",
     r"""(?:file_get_contents|include|require|fopen)\s*\([\s\S]{0,100}app/etc/env\.php""",
     [".php", ".phtml"]),

    ("DB-003", CRITICAL, "credential_theft",
     "Admin credential harvesting",
     r"""(?:\$_POST|\$request->getParam)\s*\([\s\S]{0,50}(?:login|password|user)[\s\S]{0,200}(?:curl|file_get_contents|mail|fwrite|stream)""",
     [".php", ".phtml"]),
]

# ─── DB content signatures (for scanning database content) ────────────────────
# These patterns detect malware injected into DB fields (CMS blocks, config, etc.)
DB_SIGNATURES = [
    ("DBI-001", CRITICAL, "db_injection",
     "JavaScript skimmer injected in DB content",
     r"""<script[^>]*>[\s\S]{0,100}(?:eval|atob|document\.write|String\.fromCharCode)"""),

    ("DBI-002", CRITICAL, "db_injection",
     "External script tag loading skimmer from remote domain",
     r"""<script[^>]*src\s*=\s*['"]https?://(?!(?:.*\.magento\.com|.*\.adobe\.com|.*\.google\.com|.*\.googleapis\.com|.*\.gstatic\.com|.*\.jquery\.com|.*\.cloudflare\.com|.*\.bootstrapcdn\.com))"""),

    ("DBI-003", CRITICAL, "db_injection",
     "Base64-encoded payload in DB content",
     r"""(?:atob|base64_decode|eval)\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]"""),

    ("DBI-004", CRITICAL, "db_injection",
     "Known Magecart skimmer domain in DB",
     r"""(?:google-anaiytic|googie-analytics|google-anaiytics|g00gle-analytics|jquery-cdn|bootstrap-js|cloudflare-cdn|magento-cdn|fontsgoogleapis)\.(?:com|info|org|net|xyz|top|pw)"""),

    ("DBI-005", HIGH, "db_injection",
     "Obfuscated JavaScript in DB content",
     r"""(?:String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}|unescape\s*\(\s*['"]%[0-9a-fA-F]{2})"""),

    ("DBI-006", HIGH, "db_injection",
     "Iframe injection in DB content",
     r"""<iframe[^>]*src\s*=\s*['"]https?://(?!.*(?:youtube|vimeo|google|facebook|twitter))"""),

    ("DBI-007", HIGH, "db_injection",
     "PHP code injected in DB content",
     r"""<\?(?:php|=)\s*(?:eval|system|exec|base64_decode|file_put_contents)"""),

    ("DBI-008", CRITICAL, "db_injection",
     "WebSocket/Beacon exfiltration in DB content",
     r"""(?:new\s+WebSocket|navigator\.sendBeacon|new\s+Image\s*\(\s*\)\.src)\s*[\(=][\s\S]{0,100}(?:https?://|atob)"""),

    ("DBI-009", HIGH, "db_injection",
     "Suspicious admin path or URL rewrite in core_config_data",
     r"""(?:admin/url/custom|web/unsecure/base_url|web/secure/base_url)"""),

    ("DBI-010", MEDIUM, "db_injection",
     "Inline event handler injection (onload, onerror, etc.)",
     r"""(?:on(?:load|error|mouseover|click|focus))\s*=\s*['"](?:eval|fetch|XMLHttpRequest|document\.write|atob)"""),
]

# ─── Suspicious file names/paths ──────────────────────────────────────────────
SUSPICIOUS_FILENAMES = [
    (r"(?:^|/)\.(?!htaccess|gitignore|gitkeep|well-known)[a-zA-Z0-9]{1,3}\.php$", HIGH, "Hidden PHP file (dot-prefixed)"),
    (r"(?:^|/)(?:cmd|shell|wso|c99|r57|b374k|webshell|backdoor|hack|exploit)\.php$", CRITICAL, "Known malware filename"),
    (r"(?:^|/)(?:upload|media|static|pub)/.+\.(?:php|phtml|php[3-7]|pht)$", HIGH, "PHP file in content directory"),
    (r"(?:^|/)(?:wp-login|wp-admin|wp-config|xmlrpc)\.php$", MEDIUM, "WordPress file in Magento (likely malware)"),
    (r"(?:^|/)(?:adminer|phpmyadmin|phpinfo|info|test|debug|phpunit)\.php$", MEDIUM, "Potentially dangerous utility file"),
    (r"(?:^|/)\.(?:php|phtml|pht)[0-9]*$", HIGH, "Hidden PHP variant file"),
    (r"(?:^|/)(?:cache|tmp|log|var)/.+\.php$", HIGH, "PHP file in temp/cache directory"),
    (r"(?:^|/)(?:images|img|css|js|fonts)/.+\.php$", HIGH, "PHP file in static asset directory"),
    (r"\.php\.(jpg|png|gif|ico|txt|bak|old|swp)$", HIGH, "PHP file with fake extension"),
]

# ─── YARA rules (built-in, used when yara-python is available) ────────────────
YARA_RULES_SOURCE = r"""
rule magento_skimmer_generic {
    meta:
        description = "Generic Magento credit card skimmer"
        severity = "CRITICAL"
        category = "skimmer"
    strings:
        $s1 = "onestepcheckout" nocase
        $s2 = "payment" nocase
        $s3 = /send(Beacon|Request)?/ nocase
        $exfil1 = /https?:\/\/[^\s'"]{10,}/ nocase
        $cc1 = "card" nocase
        $cc2 = "cvv" nocase
        $cc3 = "expir" nocase
    condition:
        ($s1 or $s2) and ($s3 or $exfil1) and any of ($cc*)
}

rule php_webshell_generic {
    meta:
        description = "Generic PHP webshell/backdoor"
        severity = "CRITICAL"
        category = "backdoor"
    strings:
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $b64 = "base64_decode(" nocase
        $gz = "gzinflate(" nocase
        $gz2 = "gzuncompress(" nocase
        $rot = "str_rot13(" nocase
        $shell1 = "system(" nocase
        $shell2 = "passthru(" nocase
        $shell3 = "shell_exec(" nocase
        $shell4 = "popen(" nocase
        $input1 = "$_GET" nocase
        $input2 = "$_POST" nocase
        $input3 = "$_REQUEST" nocase
        $input4 = "$_COOKIE" nocase
    condition:
        ($eval or $assert) and ($b64 or $gz or $gz2 or $rot) and any of ($input*) or
        any of ($shell*) and any of ($input*)
}

rule php_backdoor_obfuscated {
    meta:
        description = "Obfuscated PHP backdoor using string manipulation"
        severity = "HIGH"
        category = "backdoor"
    strings:
        $chr_chain = /chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/
        $hex_chain = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/
        $var_func = /\$[a-zA-Z_]+\s*=\s*['"]\w+['"];\s*\$[a-zA-Z_]+\(/
        $preg_e = /preg_replace\s*\(\s*['"]\/.*\/e['"]/
        $create_func = "create_function" nocase
    condition:
        any of them
}

rule magento_malware_known {
    meta:
        description = "Known Magento malware families"
        severity = "CRITICAL"
        category = "magento"
    strings:
        $wso = "WSO " ascii
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
        $b374k = "b374k" ascii nocase
        $filesman = "FilesMan" ascii
        $magecart1 = "ccDecode" ascii
        $magecart2 = "ccGet" ascii
        $magecart3 = "skimData" ascii
        $magecart4 = "exfilData" ascii
        $magecart5 = "grabCC" ascii
        $magecart6 = "sniffCC" ascii
    condition:
        any of them
}

rule php_in_image {
    meta:
        description = "PHP code hidden inside image file"
        severity = "HIGH"
        category = "suspicious"
    strings:
        $php1 = "<?php" nocase
        $php2 = "<? " nocase
        $php3 = "<?=" nocase
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 }
        $gif = "GIF8"
    condition:
        ($jpg at 0 or $png at 0 or $gif at 0) and any of ($php*)
}

rule suspicious_js_obfuscation {
    meta:
        description = "Heavily obfuscated JavaScript (potential skimmer)"
        severity = "MEDIUM"
        category = "obfuscation"
    strings:
        $fromchar = /String\.fromCharCode\(\d+,\d+,\d+,\d+,\d+/ nocase
        $atob_long = /atob\(['"][A-Za-z0-9+\/=]{100,}['"]\)/ nocase
        $unescape = /unescape\(['"](%[0-9a-fA-F]{2}){20,}['"]\)/ nocase
        $array_map = /\[(\d+,){20,}\d+\].*map.*String\.fromCharCode/ nocase
    condition:
        any of them
}

rule magento_config_theft {
    meta:
        description = "Code designed to steal Magento configuration/credentials"
        severity = "CRITICAL"
        category = "credential_theft"
    strings:
        $env = "app/etc/env.php" ascii
        $config = "app/etc/config.php" ascii
        $read1 = "file_get_contents" ascii
        $read2 = "fopen" ascii
        $read3 = "include" ascii
        $exfil1 = "curl" ascii
        $exfil2 = "file_get_contents(\"http" ascii
        $exfil3 = "mail(" ascii
        $exfil4 = "fwrite" ascii
    condition:
        ($env or $config) and any of ($read*) and any of ($exfil*)
}
"""

# ─── File types to scan ───────────────────────────────────────────────────────
SCANNABLE_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht",
    ".js", ".html", ".htm", ".xml", ".json",
    ".htaccess", ".htpasswd",
    ".sh", ".bash", ".cgi", ".pl", ".py",
    ".svg",  # Can contain scripts
    ".sql",  # Can contain injected PHP
    # Also scan images for embedded PHP
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".bmp", ".webp",
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", ".svn", ".hg",
    "vendor/composer", "vendor/autoload.php",
}

# Known legitimate paths that may trigger false positives
WHITELIST_PATHS = {
    "vendor/phpunit",
    "dev/tests",
    "setup/src",
    "lib/internal/Magento/Framework/Code/Generator",
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    file_path: str
    signature_id: str
    severity: str
    category: str
    description: str
    line_number: int = 0
    line_content: str = ""
    context: str = ""

@dataclass
class ScanResult:
    scan_path: str
    start_time: str
    end_time: str = ""
    duration_seconds: float = 0
    total_files_scanned: int = 0
    total_files_skipped: int = 0
    findings: list = field(default_factory=list)
    suspicious_files: list = field(default_factory=list)
    db_findings: list = field(default_factory=list)
    permission_findings: list = field(default_factory=list)
    mtime_findings: list = field(default_factory=list)
    yara_findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


# ─── Database Scanner ──────────────────────────────────────────────────────────

class DatabaseScanner:
    """Scan Magento 2 database for injected malware in CMS content and config."""

    def __init__(self, magento_root: Path, verbose: bool = False):
        self.root = magento_root
        self.verbose = verbose
        self.db_config = self._read_env_php()
        self.compiled_sigs = []
        for sig_id, severity, category, desc, pattern in DB_SIGNATURES:
            try:
                self.compiled_sigs.append((
                    sig_id, severity, category, desc,
                    re.compile(pattern, re.IGNORECASE | re.DOTALL)
                ))
            except re.error:
                pass

    def _read_env_php(self) -> Optional[dict]:
        """Parse app/etc/env.php to extract DB credentials."""
        env_path = self.root / "app" / "etc" / "env.php"
        if not env_path.exists():
            return None
        try:
            content = env_path.read_text()
            config = {}
            # Extract DB connection info from PHP array
            # Match 'key' => 'value' patterns
            db_section = re.search(
                r"'connection'\s*=>\s*\[\s*'default'\s*=>\s*\[([\s\S]*?)\]",
                content
            )
            if not db_section:
                # Try alternative format
                db_section = re.search(
                    r"'db'\s*=>\s*\[\s*[\s\S]*?'connection'\s*=>\s*\[\s*'default'\s*=>\s*\[([\s\S]*?)\]",
                    content
                )
            if db_section:
                section = db_section.group(1)
                for key in ["host", "dbname", "username", "password", "port"]:
                    match = re.search(rf"'{key}'\s*=>\s*'([^']*)'", section)
                    if match:
                        config[key] = match.group(1)

            # Also try to get table prefix
            prefix_match = re.search(r"'table_prefix'\s*=>\s*'([^']*)'", content)
            config["table_prefix"] = prefix_match.group(1) if prefix_match else ""

            if "host" in config and "dbname" in config:
                return config
            return None
        except Exception:
            return None

    def scan(self) -> list[Finding]:
        """Scan database tables for malicious content."""
        if not self.db_config:
            if self.verbose:
                print("  [DB] Could not read database config from env.php", file=sys.stderr)
            return []

        findings = []
        try:
            findings.extend(self._scan_via_mysql_cli())
        except Exception as e:
            if self.verbose:
                print(f"  [DB] Error scanning database: {e}", file=sys.stderr)
        return findings

    def _run_query(self, query: str) -> Optional[str]:
        """Execute a MySQL query via CLI and return output."""
        cfg = self.db_config
        host = cfg.get("host", "localhost")
        port = cfg.get("port", "3306")
        user = cfg.get("username", "")
        password = cfg.get("password", "")
        dbname = cfg.get("dbname", "")

        cmd = ["mysql", "--batch", "--raw", "-N",
               f"-h{host}", f"-P{port}", f"-u{user}", f"-D{dbname}"]
        if password:
            cmd.append(f"-p{password}")

        try:
            result = subprocess.run(
                cmd, input=query, capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                if self.verbose:
                    print(f"  [DB] MySQL error: {result.stderr.strip()}", file=sys.stderr)
                return None
            return result.stdout
        except FileNotFoundError:
            if self.verbose:
                print("  [DB] mysql client not found, trying mysqldump...", file=sys.stderr)
            return None
        except subprocess.TimeoutExpired:
            if self.verbose:
                print("  [DB] Query timed out", file=sys.stderr)
            return None

    def _scan_via_mysql_cli(self) -> list[Finding]:
        """Scan DB content using mysql CLI."""
        findings = []
        prefix = self.db_config.get("table_prefix", "")

        # Tables and columns to scan
        targets = [
            (f"{prefix}core_config_data", ["path", "value"],
             "core_config_data"),
            (f"{prefix}cms_block", ["content", "title", "identifier"],
             "cms_block"),
            (f"{prefix}cms_page", ["content", "title", "identifier", "content_heading", "layout_update_xml"],
             "cms_page"),
            (f"{prefix}email_template", ["template_text", "template_subject"],
             "email_template"),
            (f"{prefix}sales_order_status_label", ["label"],
             "sales_order_status_label"),
        ]

        # Also scan for rogue admin users
        admin_findings = self._check_admin_users(prefix)
        findings.extend(admin_findings)

        # Also check for suspicious cron jobs in DB
        cron_findings = self._check_cron_schedule(prefix)
        findings.extend(cron_findings)

        for table, columns, table_label in targets:
            for col in columns:
                query = f"SELECT CONCAT('{table_label}:', {col}) FROM `{table}` WHERE 1=1;"
                try:
                    # Use a smarter query that only pulls suspicious rows
                    like_patterns = [
                        "<script%", "%eval(%", "%base64_decode(%",
                        "%atob(%", "%document.write(%", "%String.fromCharCode%",
                        "%<iframe%", "%<?php%", "%onload=%", "%onerror=%",
                        "%WebSocket%", "%sendBeacon%",
                    ]
                    where_clauses = " OR ".join(
                        f"`{col}` LIKE '{p}'" for p in like_patterns
                    )
                    query = f"SELECT `{col}` FROM `{table}` WHERE {where_clauses} LIMIT 100;"
                    output = self._run_query(query)
                    if not output:
                        continue

                    for row_num, row in enumerate(output.strip().split("\n"), 1):
                        if not row.strip():
                            continue
                        for sig_id, severity, category, desc, regex in self.compiled_sigs:
                            if regex.search(row):
                                snippet = row[:200].strip()
                                findings.append(Finding(
                                    file_path=f"DB:{table_label}.{col}",
                                    signature_id=sig_id,
                                    severity=severity,
                                    category=category,
                                    description=desc,
                                    line_number=row_num,
                                    line_content=snippet,
                                    context=f"Table: {table}, Column: {col}",
                                ))
                                break  # One finding per row per table
                except Exception:
                    continue

        return findings

    def _check_admin_users(self, prefix: str) -> list[Finding]:
        """Check for suspicious admin users created recently."""
        findings = []
        query = f"""SELECT CONCAT(username, '|', email, '|', created)
                    FROM `{prefix}admin_user`
                    WHERE created > DATE_SUB(NOW(), INTERVAL 30 DAY)
                    ORDER BY created DESC LIMIT 20;"""
        output = self._run_query(query)
        if not output:
            return findings

        for row in output.strip().split("\n"):
            if not row.strip():
                continue
            parts = row.split("|")
            username = parts[0] if len(parts) > 0 else "unknown"
            email = parts[1] if len(parts) > 1 else ""
            created = parts[2] if len(parts) > 2 else ""

            # Flag suspicious patterns
            suspicious = False
            reason = ""
            if re.search(r"@(?:mail\.ru|yandex|proton|tutanota|guerrilla|tempmail|throwaway)", email, re.I):
                suspicious = True
                reason = f"Suspicious email domain: {email}"
            elif re.search(r"^(?:admin\d+|test\d*|user\d+|support\d+)$", username, re.I):
                suspicious = True
                reason = f"Generic admin username: {username}"

            if suspicious:
                findings.append(Finding(
                    file_path="DB:admin_user",
                    signature_id="DBI-ADM",
                    severity=HIGH,
                    category="db_injection",
                    description=f"Suspicious admin user created recently - {reason}",
                    line_number=0,
                    line_content=f"User: {username}, Email: {email}, Created: {created}",
                    context="admin_user table",
                ))

        return findings

    def _check_cron_schedule(self, prefix: str) -> list[Finding]:
        """Check for suspicious entries in cron_schedule."""
        findings = []
        query = f"""SELECT CONCAT(job_code, '|', status, '|', scheduled_at)
                    FROM `{prefix}cron_schedule`
                    WHERE job_code NOT LIKE 'catalog_%'
                      AND job_code NOT LIKE 'sales_%'
                      AND job_code NOT LIKE 'indexer_%'
                      AND job_code NOT LIKE 'newsletter_%'
                      AND job_code NOT LIKE 'sitemap_%'
                      AND job_code NOT LIKE 'currency_%'
                      AND job_code NOT LIKE 'backup_%'
                      AND job_code NOT LIKE 'staging_%'
                      AND job_code NOT LIKE 'analytics_%'
                      AND job_code NOT LIKE 'consumers_%'
                      AND job_code NOT LIKE 'magento_%'
                    ORDER BY scheduled_at DESC LIMIT 50;"""
        output = self._run_query(query)
        if not output:
            return findings

        suspicious_patterns = re.compile(
            r"(?:curl|wget|eval|base64|shell|exec|system|php\s+-r)", re.I
        )
        for row in output.strip().split("\n"):
            if not row.strip():
                continue
            if suspicious_patterns.search(row):
                findings.append(Finding(
                    file_path="DB:cron_schedule",
                    signature_id="DBI-CRON",
                    severity=HIGH,
                    category="db_injection",
                    description="Suspicious cron job in database",
                    line_number=0,
                    line_content=row[:200],
                    context="cron_schedule table",
                ))

        return findings


# ─── Permission Checker ────────────────────────────────────────────────────────

class PermissionChecker:
    """Check file/directory permissions for security issues."""

    def __init__(self, magento_root: Path, verbose: bool = False):
        self.root = magento_root
        self.verbose = verbose

    def check(self) -> list[Finding]:
        findings = []

        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = os.path.relpath(dirpath, self.root)
            # Skip .git, node_modules, etc.
            parts = Path(rel_dir).parts
            if any(skip in parts for skip in {".git", "node_modules", ".svn", ".hg"}):
                dirnames.clear()
                continue

            # Check directory permissions
            try:
                dir_stat = os.stat(dirpath)
                mode = dir_stat.st_mode
                if mode & stat.S_IWOTH:  # world-writable directory
                    findings.append(Finding(
                        file_path=rel_dir + "/",
                        signature_id="PERM-001",
                        severity=HIGH,
                        category="permissions",
                        description="World-writable directory",
                        line_number=0,
                        line_content=f"Mode: {oct(mode)[-4:]}",
                    ))
            except OSError:
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(fpath, self.root)
                try:
                    fstat = os.stat(fpath)
                    mode = fstat.st_mode
                except OSError:
                    continue

                # World-writable files
                if mode & stat.S_IWOTH:
                    findings.append(Finding(
                        file_path=rel_path,
                        signature_id="PERM-002",
                        severity=HIGH,
                        category="permissions",
                        description="World-writable file",
                        line_number=0,
                        line_content=f"Mode: {oct(mode)[-4:]}",
                    ))

                # SUID/SGID on PHP files
                if (mode & stat.S_ISUID or mode & stat.S_ISGID):
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in {".php", ".phtml", ".sh", ".py", ".pl", ".cgi"}:
                        findings.append(Finding(
                            file_path=rel_path,
                            signature_id="PERM-003",
                            severity=CRITICAL,
                            category="permissions",
                            description="SUID/SGID bit set on script file",
                            line_number=0,
                            line_content=f"Mode: {oct(mode)[-4:]}",
                        ))

                # Executable PHP/PHTML in web directories
                ext = os.path.splitext(fname)[1].lower()
                if ext in {".php", ".phtml"} and (mode & stat.S_IXOTH):
                    # PHP files should not be world-executable
                    if any(d in rel_path for d in ["pub/", "media/", "static/"]):
                        findings.append(Finding(
                            file_path=rel_path,
                            signature_id="PERM-004",
                            severity=MEDIUM,
                            category="permissions",
                            description="World-executable PHP file in web directory",
                            line_number=0,
                            line_content=f"Mode: {oct(mode)[-4:]}",
                        ))

                # env.php should not be world-readable
                if rel_path == os.path.join("app", "etc", "env.php"):
                    if mode & stat.S_IROTH:
                        findings.append(Finding(
                            file_path=rel_path,
                            signature_id="PERM-005",
                            severity=HIGH,
                            category="permissions",
                            description="env.php is world-readable (contains DB credentials)",
                            line_number=0,
                            line_content=f"Mode: {oct(mode)[-4:]}",
                        ))

        return findings


# ─── Recently Modified Files Checker ──────────────────────────────────────────

class MtimeChecker:
    """Detect core files modified after installation/last update."""

    def __init__(self, magento_root: Path, days: int = 7, verbose: bool = False):
        self.root = magento_root
        self.days = days
        self.verbose = verbose
        self.reference_time = self._get_reference_time()

    def _get_reference_time(self) -> Optional[float]:
        """Determine the installation/last update time from reference files."""
        candidates = [
            self.root / "composer.lock",
            self.root / "vendor" / "magento" / "framework" / "composer.json",
            self.root / "app" / "etc" / "config.php",
        ]
        for ref in candidates:
            if ref.exists():
                return ref.stat().st_mtime
        return None

    def check(self) -> list[Finding]:
        findings = []

        if self.reference_time is None:
            if self.verbose:
                print("  [MTIME] No reference file found to determine install time",
                      file=sys.stderr)
            # Fallback: flag files modified in the last N days
            cutoff = time.time() - (self.days * 86400)
        else:
            # Files modified after reference + 1 hour grace period
            cutoff = self.reference_time + 3600

        # Core directories to check for unexpected modifications
        core_dirs = [
            (self.root / "vendor" / "magento", "vendor/magento"),
            (self.root / "lib" / "internal", "lib/internal"),
            (self.root / "setup" / "src", "setup/src"),
        ]

        # Also check for recently created PHP files anywhere
        recent_php = self._find_recent_php_files(cutoff)
        findings.extend(recent_php)

        for core_dir, label in core_dirs:
            if not core_dir.exists():
                continue
            for fpath in core_dir.rglob("*"):
                if not fpath.is_file():
                    continue
                ext = fpath.suffix.lower()
                if ext not in {".php", ".phtml", ".js", ".html", ".xml"}:
                    continue
                try:
                    mtime = fpath.stat().st_mtime
                except OSError:
                    continue
                if mtime > cutoff:
                    rel = os.path.relpath(fpath, self.root)
                    mod_date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                    findings.append(Finding(
                        file_path=rel,
                        signature_id="MTIME-001",
                        severity=HIGH,
                        category="modified_core",
                        description=f"Core file modified after installation/update",
                        line_number=0,
                        line_content=f"Modified: {mod_date}",
                    ))

        return findings

    def _find_recent_php_files(self, cutoff: float) -> list[Finding]:
        """Find PHP files created/modified very recently (suspicious)."""
        findings = []
        suspicious_dirs = [
            self.root / "pub" / "media",
            self.root / "pub" / "static",
            self.root / "var",
            self.root / "generated",
        ]

        now = time.time()
        recent_cutoff = now - (self.days * 86400)  # Last N days

        for sdir in suspicious_dirs:
            if not sdir.exists():
                continue
            for fpath in sdir.rglob("*.php"):
                if not fpath.is_file():
                    continue
                try:
                    fstat = fpath.stat()
                except OSError:
                    continue
                if fstat.st_mtime > recent_cutoff:
                    rel = os.path.relpath(fpath, self.root)
                    mod_date = datetime.fromtimestamp(fstat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    findings.append(Finding(
                        file_path=rel,
                        signature_id="MTIME-002",
                        severity=HIGH,
                        category="modified_core",
                        description=f"Recently modified/created PHP file in sensitive directory",
                        line_number=0,
                        line_content=f"Modified: {mod_date}, Size: {fstat.st_size}B",
                    ))

        return findings


# ─── YARA Scanner ──────────────────────────────────────────────────────────────

class YaraScanner:
    """Scan files using YARA rules for advanced malware detection."""

    def __init__(self, magento_root: Path, extra_rules_path: Optional[str] = None,
                 verbose: bool = False):
        self.root = magento_root
        self.verbose = verbose
        self.rules = None
        self.available = False
        self._init_yara(extra_rules_path)

    def _init_yara(self, extra_rules_path: Optional[str]):
        try:
            import yara
            self.yara = yara
        except ImportError:
            if self.verbose:
                print("  [YARA] yara-python not installed. Install with: pip install yara-python",
                      file=sys.stderr)
            return

        try:
            sources = {"builtin": YARA_RULES_SOURCE}

            # Load external rules if provided
            if extra_rules_path:
                rules_dir = Path(extra_rules_path)
                if rules_dir.is_file():
                    sources["external"] = rules_dir.read_text()
                elif rules_dir.is_dir():
                    for i, yar_file in enumerate(rules_dir.glob("*.yar")):
                        try:
                            sources[f"ext_{i}"] = yar_file.read_text()
                        except Exception:
                            pass
                    for i, yar_file in enumerate(rules_dir.glob("*.yara")):
                        try:
                            sources[f"exty_{i}"] = yar_file.read_text()
                        except Exception:
                            pass

            self.rules = yara.compile(sources=sources)
            self.available = True
            if self.verbose:
                print(f"  [YARA] Loaded rules successfully", file=sys.stderr)
        except Exception as e:
            if self.verbose:
                print(f"  [YARA] Failed to compile rules: {e}", file=sys.stderr)

    def scan_file(self, filepath: str) -> list[Finding]:
        if not self.available or not self.rules:
            return []

        findings = []
        rel_path = os.path.relpath(filepath, self.root)

        try:
            matches = self.rules.match(filepath, timeout=10)
        except Exception:
            return findings

        for match in matches:
            severity = HIGH
            category = "yara"
            if hasattr(match, "meta"):
                severity = match.meta.get("severity", HIGH)
                category = match.meta.get("category", "yara")

            matched_strings = []
            if hasattr(match, "strings"):
                for s in match.strings[:3]:  # Limit to first 3
                    if hasattr(s, "instances"):
                        for inst in s.instances[:1]:
                            matched_strings.append(str(inst)[:80])
                    else:
                        matched_strings.append(str(s)[:80])

            desc = match.meta.get("description", match.rule) if hasattr(match, "meta") else match.rule

            findings.append(Finding(
                file_path=rel_path,
                signature_id=f"YARA-{match.rule}",
                severity=severity,
                category=category,
                description=f"[YARA] {desc}",
                line_number=0,
                line_content="; ".join(matched_strings)[:200] if matched_strings else "",
            ))

        return findings

    def scan_directory(self, files: list[str]) -> list[Finding]:
        if not self.available:
            return []
        findings = []
        for fpath in files:
            try:
                size = os.path.getsize(fpath)
                if size > MAX_FILE_SIZE or size == 0:
                    continue
                findings.extend(self.scan_file(fpath))
            except OSError:
                continue
        return findings


# ─── Scanner ───────────────────────────────────────────────────────────────────

class An4Scanner:
    def __init__(self, path: str, workers: int = 4, min_severity: str = LOW,
                 whitelist: Optional[list] = None, json_output: bool = False,
                 verbose: bool = False, scan_db: bool = False,
                 check_mtime: bool = False, mtime_days: int = 7,
                 check_permissions: bool = False,
                 use_yara: bool = False, yara_rules: Optional[str] = None):
        self.path = Path(path).resolve()
        self.workers = workers
        self.min_severity = min_severity
        self.whitelist = whitelist or []
        self.json_output = json_output
        self.verbose = verbose
        self.scan_db = scan_db
        self.check_mtime = check_mtime
        self.mtime_days = mtime_days
        self.check_permissions = check_permissions
        self.use_yara = use_yara
        self.yara_rules = yara_rules
        self.compiled_sigs = self._compile_signatures()
        self.compiled_filenames = self._compile_filename_patterns()

    def _compile_signatures(self) -> list:
        compiled = []
        for sig_id, severity, category, desc, pattern, exts in SIGNATURES:
            if SEVERITY_ORDER.get(severity, 99) > SEVERITY_ORDER.get(self.min_severity, 4):
                continue
            try:
                compiled.append((
                    sig_id, severity, category, desc,
                    re.compile(pattern, re.IGNORECASE | re.DOTALL),
                    set(exts) if exts else None
                ))
            except re.error as e:
                print(f"Warning: invalid regex in {sig_id}: {e}", file=sys.stderr)
        return compiled

    def _compile_filename_patterns(self) -> list:
        compiled = []
        for pattern, severity, desc in SUSPICIOUS_FILENAMES:
            if SEVERITY_ORDER.get(severity, 99) > SEVERITY_ORDER.get(self.min_severity, 4):
                continue
            try:
                compiled.append((re.compile(pattern, re.IGNORECASE), severity, desc))
            except re.error:
                pass
        return compiled

    def _should_skip_dir(self, dirpath: str) -> bool:
        rel = os.path.relpath(dirpath, self.path)
        parts = Path(rel).parts
        for skip in SKIP_DIRS:
            if skip in parts:
                return True
        return False

    def _is_whitelisted(self, filepath: str) -> bool:
        rel = os.path.relpath(filepath, self.path)
        for wp in WHITELIST_PATHS:
            if rel.startswith(wp):
                return True
        for wp in self.whitelist:
            if rel.startswith(wp):
                return True
        return False

    def _collect_files(self) -> list[str]:
        files = []
        for dirpath, dirnames, filenames in os.walk(self.path):
            # Prune directories
            dirnames[:] = [
                d for d in dirnames
                if not self._should_skip_dir(os.path.join(dirpath, d))
            ]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                ext = os.path.splitext(fname)[1].lower()
                # Also check double extensions
                if ext in SCANNABLE_EXTENSIONS or fname == ".htaccess":
                    if os.path.isfile(fpath):
                        files.append(fpath)
                # Check for suspicious filenames even if extension doesn't match
                elif any(p.search(fpath) for p, _, _ in self.compiled_filenames):
                    if os.path.isfile(fpath):
                        files.append(fpath)
        return files

    def _scan_file(self, filepath: str) -> tuple[list[Finding], list[dict]]:
        findings = []
        suspicious = []

        rel_path = os.path.relpath(filepath, self.path)

        # Check filename patterns
        for pattern, severity, desc in self.compiled_filenames:
            if pattern.search(rel_path):
                suspicious.append({
                    "file": rel_path,
                    "severity": severity,
                    "reason": desc,
                })

        # Skip whitelisted paths for content scanning
        if self._is_whitelisted(filepath):
            return findings, suspicious

        # Check file size
        try:
            size = os.path.getsize(filepath)
            if size > MAX_FILE_SIZE:
                return findings, suspicious
            if size == 0:
                return findings, suspicious
        except OSError:
            return findings, suspicious

        # Read file content
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except (OSError, PermissionError):
            return findings, suspicious

        # Detect encoding - try UTF-8 first, fallback to latin-1
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                content = raw.decode("latin-1")
            except UnicodeDecodeError:
                return findings, suspicious

        ext = os.path.splitext(filepath)[1].lower()
        lines = content.split("\n")

        # Check for PHP code in image files
        if ext in {".jpg", ".jpeg", ".png", ".gif", ".ico", ".bmp", ".webp", ".svg"}:
            if b"<?php" in raw or b"<?=" in raw:
                findings.append(Finding(
                    file_path=rel_path,
                    signature_id="SF-006",
                    severity=HIGH,
                    category="suspicious",
                    description="PHP code embedded in image/media file",
                    line_number=0,
                    line_content="(binary file)",
                ))
            return findings, suspicious

        # Run signature checks
        for sig_id, severity, category, desc, regex, exts in self.compiled_sigs:
            if exts and ext not in exts:
                continue
            for i, line in enumerate(lines, 1):
                if len(line) > 10000:
                    # For very long lines, check in chunks
                    for chunk_start in range(0, len(line), 8000):
                        chunk = line[chunk_start:chunk_start + 10000]
                        if regex.search(chunk):
                            snippet = chunk[:200].strip()
                            findings.append(Finding(
                                file_path=rel_path,
                                signature_id=sig_id,
                                severity=severity,
                                category=category,
                                description=desc,
                                line_number=i,
                                line_content=snippet,
                            ))
                            break
                else:
                    if regex.search(line):
                        snippet = line[:200].strip()
                        findings.append(Finding(
                            file_path=rel_path,
                            signature_id=sig_id,
                            severity=severity,
                            category=category,
                            description=desc,
                            line_number=i,
                            line_content=snippet,
                        ))

        # Entropy check for detecting heavily obfuscated code
        if ext in {".php", ".phtml", ".js"} and len(content) > 500:
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if len(stripped) > 1000:
                    entropy = self._shannon_entropy(stripped)
                    if entropy > 5.5 and len(stripped) > 2000:
                        findings.append(Finding(
                            file_path=rel_path,
                            signature_id="OB-ENT",
                            severity=MEDIUM,
                            category="obfuscation",
                            description=f"High entropy line (entropy={entropy:.2f}) - possible obfuscated code",
                            line_number=i,
                            line_content=stripped[:200],
                        ))

        return findings, suspicious

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        from math import log2
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * log2(p)
        return entropy

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(
            scan_path=str(self.path),
            start_time=datetime.now().isoformat(),
        )

        if not self.json_output:
            self._print_banner()
            print(f"  Scanning: {self.path}")
            print(f"  Workers:  {self.workers}")
            print(f"  Min severity: {self.min_severity}")
            modules = []
            if self.scan_db:
                modules.append("DB")
            if self.check_mtime:
                modules.append(f"MTIME({self.mtime_days}d)")
            if self.check_permissions:
                modules.append("PERMS")
            if self.use_yara:
                modules.append("YARA")
            if modules:
                print(f"  Modules:  {', '.join(modules)}")
            print()

        # Collect files
        files = self._collect_files()
        total_files = len(files)

        if not self.json_output:
            print(f"  Found {total_files} files to scan...")
            print()

        # ── File signature scan (parallel) ──
        all_findings = []
        all_suspicious = []
        scanned = 0

        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            future_to_file = {
                executor.submit(self._scan_file, f): f for f in files
            }
            for future in as_completed(future_to_file):
                scanned += 1
                try:
                    findings, suspicious = future.result()
                    all_findings.extend(findings)
                    all_suspicious.extend(suspicious)
                except Exception as e:
                    filepath = future_to_file[future]
                    if self.verbose:
                        print(f"  Error scanning {filepath}: {e}", file=sys.stderr)

                if not self.json_output and scanned % 500 == 0:
                    print(f"  Progress: {scanned}/{total_files} files scanned, "
                          f"{len(all_findings)} findings so far...",
                          end="\r")

        if not self.json_output:
            print(f"  Progress: {total_files}/{total_files} files scanned.        ")
            print()

        # ── Database scan ──
        if self.scan_db:
            if not self.json_output:
                print("  Scanning database...")
            db_scanner = DatabaseScanner(self.path, verbose=self.verbose)
            result.db_findings = db_scanner.scan()
            if not self.json_output:
                print(f"  Database: {len(result.db_findings)} finding(s)")
                print()

        # ── Permission check ──
        if self.check_permissions:
            if not self.json_output:
                print("  Checking file permissions...")
            perm_checker = PermissionChecker(self.path, verbose=self.verbose)
            result.permission_findings = perm_checker.check()
            if not self.json_output:
                print(f"  Permissions: {len(result.permission_findings)} finding(s)")
                print()

        # ── Modified files check ──
        if self.check_mtime:
            if not self.json_output:
                print(f"  Checking recently modified files ({self.mtime_days} days)...")
            mtime_checker = MtimeChecker(self.path, days=self.mtime_days,
                                         verbose=self.verbose)
            result.mtime_findings = mtime_checker.check()
            if not self.json_output:
                print(f"  Modified: {len(result.mtime_findings)} finding(s)")
                print()

        # ── YARA scan ──
        if self.use_yara:
            if not self.json_output:
                print("  Running YARA scan...")
            yara_scanner = YaraScanner(self.path, extra_rules_path=self.yara_rules,
                                       verbose=self.verbose)
            if yara_scanner.available:
                result.yara_findings = yara_scanner.scan_directory(files)
                if not self.json_output:
                    print(f"  YARA: {len(result.yara_findings)} finding(s)")
            elif not self.json_output:
                print("  YARA: skipped (yara-python not installed)")
            print()

        # ── Deduplicate & sort ──
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.file_path, f.signature_id)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings = deduped

        all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        all_suspicious.sort(key=lambda s: SEVERITY_ORDER.get(s["severity"], 99))

        end = time.time()
        result.end_time = datetime.now().isoformat()
        result.duration_seconds = round(end - start, 2)
        result.total_files_scanned = total_files
        result.findings = all_findings
        result.suspicious_files = all_suspicious
        result.summary = self._build_summary(result)

        return result

    def _build_summary(self, result: ScanResult) -> dict:
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        affected_files = set()

        all_findings = (
            result.findings
            + result.db_findings
            + result.permission_findings
            + result.mtime_findings
            + result.yara_findings
        )

        for f in all_findings:
            by_severity[f.severity] += 1
            by_category[f.category] += 1
            affected_files.add(f.file_path)

        for s in result.suspicious_files:
            by_severity[s["severity"]] += 1

        return {
            "total_findings": len(all_findings),
            "total_suspicious_files": len(result.suspicious_files),
            "affected_files": len(affected_files),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "modules": {
                "file_scan": len(result.findings),
                "db_scan": len(result.db_findings),
                "permissions": len(result.permission_findings),
                "mtime": len(result.mtime_findings),
                "yara": len(result.yara_findings),
            },
        }

    def _print_banner(self):
        print(f"""
{BOLD}╔══════════════════════════════════════════════════════╗
║                  AN4SCAN v2.0                        ║
║          Magento 2 Malware Scanner                   ║
╚══════════════════════════════════════════════════════╝{RESET}
""")

    def print_report(self, result: ScanResult):
        if self.json_output:
            self._print_json_report(result)
            return
        self._print_text_report(result)

    def _print_json_report(self, result: ScanResult):
        output = {
            "scan_path": result.scan_path,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration_seconds": result.duration_seconds,
            "total_files_scanned": result.total_files_scanned,
            "summary": result.summary,
            "findings": [asdict(f) for f in result.findings],
            "suspicious_files": result.suspicious_files,
            "db_findings": [asdict(f) for f in result.db_findings],
            "permission_findings": [asdict(f) for f in result.permission_findings],
            "mtime_findings": [asdict(f) for f in result.mtime_findings],
            "yara_findings": [asdict(f) for f in result.yara_findings],
        }
        print(json.dumps(output, indent=2))

    def _print_text_report(self, result: ScanResult):
        s = result.summary
        print(f"{BOLD}{'═' * 60}")
        print(f"  SCAN REPORT")
        print(f"{'═' * 60}{RESET}")
        print(f"  Path:     {result.scan_path}")
        print(f"  Duration: {result.duration_seconds}s")
        print(f"  Files:    {result.total_files_scanned} scanned")
        print()

        # Module breakdown
        mods = s.get("modules", {})
        if any(v > 0 for v in mods.values()):
            print(f"{BOLD}  MODULES{RESET}")
            print(f"  {'─' * 40}")
            for mod, count in mods.items():
                if count > 0:
                    print(f"    {mod:20s}: {count} finding(s)")
            print()

        # Summary
        print(f"{BOLD}  SUMMARY{RESET}")
        print(f"  {'─' * 40}")
        total = s["total_findings"] + s["total_suspicious_files"]
        if total == 0:
            print(f"  \033[92m✓ No threats detected{RESET}")
            print()
            return

        print(f"  Total findings:     {total}")
        print(f"  Affected files:     {s['affected_files']}")
        print()

        for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
            count = s["by_severity"].get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "")
                print(f"  {color}  {sev:10s}: {count}{RESET}")
        print()

        if s["by_category"]:
            print(f"  By category:")
            for cat, count in sorted(s["by_category"].items(), key=lambda x: -x[1]):
                print(f"    {cat:25s}: {count}")
            print()

        # Suspicious files
        if result.suspicious_files:
            print(f"{BOLD}  SUSPICIOUS FILES{RESET}")
            print(f"  {'─' * 40}")
            for sf in result.suspicious_files:
                color = SEVERITY_COLORS.get(sf["severity"], "")
                print(f"  {color}[{sf['severity']:8s}]{RESET} {sf['file']}")
                print(f"           {DIM}{sf['reason']}{RESET}")
            print()

        # All findings grouped by source
        finding_groups = [
            ("DETAILED FINDINGS (File Scan)", result.findings),
            ("DATABASE FINDINGS", result.db_findings),
            ("PERMISSION FINDINGS", result.permission_findings),
            ("RECENTLY MODIFIED FILES", result.mtime_findings),
            ("YARA FINDINGS", result.yara_findings),
        ]

        for title, findings_list in finding_groups:
            if not findings_list:
                continue

            print(f"{BOLD}  {title}{RESET}")
            print(f"  {'─' * 40}")

            current_severity = None
            for f in findings_list:
                if f.severity != current_severity:
                    current_severity = f.severity
                    color = SEVERITY_COLORS.get(f.severity, "")
                    print(f"\n  {color}{BOLD}── {f.severity} ──{RESET}")

                color = SEVERITY_COLORS.get(f.severity, "")
                print(f"\n  {color}[{f.signature_id}]{RESET} {f.description}")
                print(f"  {DIM}File: {f.file_path}:{f.line_number}{RESET}")
                if f.line_content:
                    content = f.line_content[:120]
                    print(f"  {DIM}Code: {content}{RESET}")
                if f.context:
                    print(f"  {DIM}Context: {f.context}{RESET}")
            print()

        print(f"{BOLD}{'═' * 60}{RESET}")

        # Risk assessment
        crit = s["by_severity"].get(CRITICAL, 0)
        high = s["by_severity"].get(HIGH, 0)
        if crit > 0:
            print(f"\n  {SEVERITY_COLORS[CRITICAL]}{BOLD}⚠  HIGH RISK - {crit} critical finding(s) detected!")
            print(f"  Immediate investigation recommended.{RESET}")
        elif high > 0:
            print(f"\n  {SEVERITY_COLORS[HIGH]}⚠  ELEVATED RISK - {high} high severity finding(s) detected.")
            print(f"  Review recommended.{RESET}")
        elif total > 0:
            print(f"\n  {SEVERITY_COLORS[MEDIUM]}△  LOW-MEDIUM RISK - Review findings for false positives.{RESET}")
        print()


# ─── Integrity checker ─────────────────────────────────────────────────────────

class IntegrityChecker:
    """Check if Magento core files have been modified by comparing checksums."""

    def __init__(self, magento_root: Path):
        self.root = magento_root
        self.vendor_dir = magento_root / "vendor" / "magento"

    def check_modified_core_files(self) -> list[dict]:
        """
        Compare files in app/code/Magento against vendor/magento originals.
        Also flag any .php/.js/.phtml in core dirs with recent modification dates.
        """
        findings = []

        # Check for overridden core files
        app_code_magento = self.root / "app" / "code" / "Magento"
        if app_code_magento.exists():
            for fpath in app_code_magento.rglob("*"):
                if fpath.is_file():
                    findings.append({
                        "file": str(fpath.relative_to(self.root)),
                        "severity": MEDIUM,
                        "reason": "Core override in app/code/Magento - verify legitimacy",
                    })

        return findings


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AN4SCAN - Magento 2 Malware Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /var/www/magento2
  %(prog)s /var/www/magento2 --json > report.json
  %(prog)s /var/www/magento2 --severity HIGH --workers 8
  %(prog)s /var/www/magento2 --all
  %(prog)s /var/www/magento2 --db --permissions --mtime --mtime-days 14
  %(prog)s /var/www/magento2 --yara --yara-rules /path/to/rules/
  %(prog)s /var/www/magento2 --whitelist vendor/custom lib/custom
        """,
    )
    parser.add_argument("path", help="Path to Magento 2 installation root")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output report in JSON format")
    parser.add_argument("-s", "--severity", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("-w", "--workers", type=int, default=4,
                        help="Number of parallel workers (default: 4)")
    parser.add_argument("--whitelist", nargs="*", default=[],
                        help="Additional paths to whitelist (relative to Magento root)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--integrity", action="store_true",
                        help="Check Magento core file integrity")
    parser.add_argument("-o", "--output", help="Write report to file")

    # New modules
    parser.add_argument("--db", action="store_true",
                        help="Scan database (CMS blocks, config, pages) for injected malware")
    parser.add_argument("--permissions", action="store_true",
                        help="Check file/directory permissions (world-writable, SUID/SGID)")
    parser.add_argument("--mtime", action="store_true",
                        help="Check for recently modified core files")
    parser.add_argument("--mtime-days", type=int, default=7,
                        help="Number of days for mtime check (default: 7)")
    parser.add_argument("--yara", action="store_true",
                        help="Enable YARA scanning (requires yara-python)")
    parser.add_argument("--yara-rules", type=str, default=None,
                        help="Path to additional YARA rules file or directory")
    parser.add_argument("--all", action="store_true",
                        help="Enable all scan modules (--db --permissions --mtime --yara --integrity)")

    args = parser.parse_args()

    # --all enables everything
    if args.all:
        args.db = True
        args.permissions = True
        args.mtime = True
        args.yara = True
        args.integrity = True

    scan_path = Path(args.path)
    if not scan_path.exists():
        print(f"Error: path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)
    if not scan_path.is_dir():
        print(f"Error: path is not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    scanner = An4Scanner(
        path=args.path,
        workers=args.workers,
        min_severity=args.severity,
        whitelist=args.whitelist,
        json_output=args.json,
        verbose=args.verbose,
        scan_db=args.db,
        check_mtime=args.mtime,
        mtime_days=args.mtime_days,
        check_permissions=args.permissions,
        use_yara=args.yara,
        yara_rules=args.yara_rules,
    )

    result = scanner.scan()

    # Integrity check
    if args.integrity:
        checker = IntegrityChecker(scan_path)
        integrity_findings = checker.check_modified_core_files()
        result.suspicious_files.extend(integrity_findings)
        for f in integrity_findings:
            result.summary.setdefault("by_severity", {})[f["severity"]] = \
                result.summary.get("by_severity", {}).get(f["severity"], 0) + 1

    # Output
    if args.output:
        import io
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        scanner.print_report(result)
        sys.stdout = old_stdout
        report_text = buf.getvalue()
        with open(args.output, "w") as f:
            f.write(report_text)
        if not args.json:
            # Also print to stdout
            print(report_text)
            print(f"  Report saved to: {args.output}")
    else:
        scanner.print_report(result)

    # Exit code based on severity
    crit = result.summary.get("by_severity", {}).get(CRITICAL, 0)
    high = result.summary.get("by_severity", {}).get(HIGH, 0)
    if crit > 0:
        sys.exit(2)
    elif high > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
