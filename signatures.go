package main

// ─── File content signatures ────────────────────────────────────────────────

var Signatures = []SignatureDef{
	// ━━━ Credit Card Skimmers / Payment Exfiltration ━━━━━━━━━━━━━━━━━━━━━━━━━
	{"CC-001", CRITICAL, "skimmer",
		"Credit card number regex pattern (potential skimmer)",
		`(?i)(?:card.?num|cc.?num|pan.?num)[\s\S]{0,50}(?:\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|\b[3-6]\d{12,18}\b)`,
		[]string{".php", ".js", ".phtml"}},
	{"CC-002", CRITICAL, "skimmer",
		"JavaScript CC exfiltration - sending payment data to external URL",
		`(?i)(?:XMLHttpRequest|fetch|navigator\.sendBeacon|new\s+Image)\s*\([\s\S]{0,200}(?:cc|card|payment|checkout|cvv|cvc|expir)`,
		[]string{".js", ".phtml", ".html"}},
	{"CC-003", CRITICAL, "skimmer",
		"Known Magecart/skimmer domain patterns",
		`(?i)(?:google-anaiytic|googie-analytics|google-anaiytics|g00gle-analytics|googlc-analytics|google-analytcs|jquery-cdn|bootstrap-js|cloudflare-cdn|magento-cdn|fontsgoogleapis|jquery-ui-cdn|react-js-cdn)\.(?:com|info|org|net|xyz|top|pw)`,
		[]string{".js", ".phtml", ".html", ".php"}},
	{"CC-004", CRITICAL, "skimmer",
		"Inline JS intercepting payment form submit",
		`(?i)(?:payment|checkout|billing)[\s\S]{0,100}(?:addEventListener|onsubmit|\.submit)[\s\S]{0,200}(?:send|fetch|XMLHttp|Image\(|beacon)`,
		[]string{".js", ".phtml", ".html"}},
	{"CC-005", CRITICAL, "skimmer",
		"Base64-encoded exfiltration URL in JavaScript",
		`(?i)atob\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*\)[\s\S]{0,100}(?:send|fetch|XMLHttp|Image|beacon)`,
		[]string{".js", ".phtml"}},
	{"CC-006", CRITICAL, "skimmer",
		"WebSocket-based data exfiltration",
		`(?i)new\s+WebSocket\s*\([\s\S]{0,300}(?:card|cc_|cvv|payment|checkout)`,
		[]string{".js", ".phtml"}},
	{"CC-007", HIGH, "skimmer",
		"Suspicious form field value collection targeting payment data",
		`(?i)(?:querySelector|getElementById|getElementsByName|getElement)\s*\([\s\S]{0,50}(?:cc[-_]|card[-_]|payment[-_]|cvv|cvc|expir)[\s\S]{0,100}\.value`,
		[]string{".js", ".phtml"}},

	// ━━━ PHP Backdoors / Webshells ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"BD-001", CRITICAL, "backdoor",
		"eval() with base64_decode - classic backdoor pattern",
		`(?i)eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode)\s*\(`,
		[]string{".php", ".phtml"}},
	{"BD-002", CRITICAL, "backdoor",
		"eval() with variable function call (obfuscated execution)",
		`(?i)eval\s*\(\s*\$[a-zA-Z_]\w*\s*\(`,
		[]string{".php", ".phtml"}},
	{"BD-003", CRITICAL, "backdoor",
		"assert() used as code execution",
		`(?i)assert\s*\(\s*(?:base64_decode|gzinflate|\$_(?:GET|POST|REQUEST|COOKIE)|stripslashes)`,
		[]string{".php", ".phtml"}},
	{"BD-004", CRITICAL, "backdoor",
		"preg_replace with /e modifier (code execution)",
		`(?i)preg_replace\s*\(\s*['"]/.*/[a-zA-Z]*e[a-zA-Z]*['"]`,
		[]string{".php", ".phtml"}},
	{"BD-005", CRITICAL, "backdoor",
		"Direct execution of user-supplied input",
		`(?i)(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`,
		[]string{".php", ".phtml"}},
	{"BD-006", CRITICAL, "backdoor",
		"create_function with user input (code injection)",
		`(?i)create_function\s*\([\s\S]{0,100}\$_(?:GET|POST|REQUEST|COOKIE)`,
		[]string{".php", ".phtml"}},
	{"BD-007", CRITICAL, "backdoor",
		"Known webshell signatures (WSO, C99, R57, B374K, etc.)",
		`(?i)(?:WSO\s+\d|c99shell|r57shell|b374k|FilesMan|webshell|Ani-Shell|MARIJUANA|phpSpy|phpRemoteView|Network\s+Tools)`,
		[]string{".php", ".phtml"}},
	{"BD-008", HIGH, "backdoor",
		"Dynamic function creation/call from string",
		`(?i)\$[a-zA-Z_]\w*\s*=\s*(?:chr\(\d+\)\s*\.?\s*){4,}`,
		[]string{".php", ".phtml"}},
	{"BD-009", HIGH, "backdoor",
		"Variable function call with string concatenation",
		`(?i)\$[a-zA-Z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)`,
		[]string{".php", ".phtml"}},
	{"BD-010", HIGH, "backdoor",
		"Hexadecimal-encoded string execution",
		`(?i)(?:\\x[0-9a-fA-F]{2}){10,}`,
		[]string{".php", ".phtml"}},
	{"BD-011", CRITICAL, "backdoor",
		"File upload backdoor (arbitrary file write)",
		`(?i)move_uploaded_file\s*\([\s\S]{0,200}\$_(?:GET|POST|REQUEST)`,
		[]string{".php", ".phtml"}},
	{"BD-012", HIGH, "backdoor",
		"Suspicious file_put_contents with user input",
		`(?i)file_put_contents\s*\([\s\S]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)`,
		[]string{".php", ".phtml"}},

	// ━━━ Obfuscation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"OB-001", HIGH, "obfuscation",
		"Heavily nested base64/gzip decode chains",
		`(?i)(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(`,
		[]string{".php", ".phtml"}},
	{"OB-002", MEDIUM, "obfuscation",
		"Long base64-encoded string (>500 chars) in PHP",
		`['"][A-Za-z0-9+/]{500,}={0,2}['"]`,
		[]string{".php", ".phtml"}},
	{"OB-003", HIGH, "obfuscation",
		"Variable variables used for obfuscation",
		`\$\{\s*\$[a-zA-Z_]\w*\s*\}\s*\(`,
		[]string{".php", ".phtml"}},
	{"OB-004", HIGH, "obfuscation",
		"Encoded/obfuscated eval via string manipulation",
		`(?:\$\w+\s*=\s*['"][\w]+['"];\s*){3,}.*(?:\$\w+\s*\.\s*){3,}`,
		[]string{".php", ".phtml"}},
	{"OB-005", MEDIUM, "obfuscation",
		"JavaScript obfuscation with char code arrays",
		`(?i)String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}`,
		[]string{".js", ".phtml", ".html"}},
	{"OB-006", MEDIUM, "obfuscation",
		"PHP compact/extract abuse for variable injection",
		`(?i)extract\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)`,
		[]string{".php", ".phtml"}},
	{"OB-007", MEDIUM, "obfuscation",
		"ionCube/Zend Guard encoded file - verify legitimacy",
		`(?i)(?:ionCube|ioncube_loader|zend_loader|sg_load|SourceGuardian)`,
		[]string{".php"}},

	// ━━━ Suspicious File Operations ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"FO-001", HIGH, "file_operation",
		"Writing PHP code to a file (potential dropper)",
		`(?is)file_put_contents\s*\([\s\S]{0,100}(?:<\?php|<\?=|eval|base64_decode)`,
		[]string{".php", ".phtml"}},
	{"FO-002", HIGH, "file_operation",
		"Remote file inclusion",
		`(?i)(?:include|require|include_once|require_once)\s*\(\s*(?:['"]https?://|\$_(?:GET|POST|REQUEST))`,
		[]string{".php", ".phtml"}},
	{"FO-003", MEDIUM, "file_operation",
		"file_get_contents from external URL with suspicious usage",
		`(?is)file_get_contents\s*\(\s*['"]https?://[\s\S]{0,200}(?:eval|base64_decode|file_put_contents)`,
		[]string{".php", ".phtml"}},

	// ━━━ Magento-Specific Malware Patterns ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"MG-001", CRITICAL, "magento",
		"Modified Magento core payment model (core file tampering)",
		`(?is)(?:Magento\\Payment|Magento\\Sales)[\s\S]{0,500}(?:curl_exec|file_get_contents\s*\(\s*['"]https?://)`,
		[]string{".php"}},
	{"MG-002", CRITICAL, "magento",
		"Malicious Magento observer intercepting payment data",
		`(?is)(?:sales_order_place_after|checkout_onepage_controller_success_action|checkout_submit_all_after)[\s\S]{0,500}(?:curl|file_get_contents|fopen|stream_context)`,
		[]string{".php"}},
	{"MG-003", HIGH, "magento",
		"Suspicious Magento admin user creation",
		`(?is)(?:createUser|addRole|setRoleType|setUserType)[\s\S]{0,200}(?:Administrators|admin)`,
		[]string{".php"}},
	{"MG-004", HIGH, "magento",
		"Magento config.php or env.php modification code",
		`(?is)(?:app/etc/(?:config|env)\.php)[\s\S]{0,100}(?:file_put_contents|fwrite|fopen)`,
		[]string{".php"}},
	{"MG-005", CRITICAL, "magento",
		"Known Magento malware (Magecart Group patterns)",
		`(?i)(?:ccDecode|ccGet|getFormData|skimData|exfilData|sendCC|grabCC|sniffCC)`,
		[]string{".js", ".php", ".phtml"}},
	{"MG-006", HIGH, "magento",
		"Suspicious inline script in Magento CMS/static content",
		`(?is)<script[^>]*>[\s\S]{0,50}(?:atob|eval|document\.write|unescape)[\s\S]{0,500}(?:payment|card|checkout|billing)`,
		[]string{".phtml", ".html", ".php"}},
	{"MG-007", HIGH, "magento",
		"Unauthorized Magento module registration (rogue module)",
		`(?is)registration\.php[\s\S]{0,50}(?:ComponentRegistrar|module)[\s\S]{0,200}(?:eval|base64|shell_exec|system)`,
		[]string{".php"}},
	{"MG-008", MEDIUM, "magento",
		"Suspicious REST/SOAP API endpoint override",
		`(?is)webapi\.xml[\s\S]{0,200}(?:route[\s\S]{0,50}url=)[\s\S]{0,200}(?:password|admin|token|secret)`,
		[]string{".xml"}},

	// ━━━ Server-Level Threats ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"SV-001", HIGH, "server",
		"Suspicious .htaccess redirect (SEO spam / phishing)",
		`(?is)RewriteCond[\s\S]{0,200}(?:google|yahoo|bing|facebook|instagram|tiktok)[\s\S]{0,200}RewriteRule.*https?://`,
		[]string{".htaccess"}},
	{"SV-002", HIGH, "server",
		".htaccess allowing PHP execution in upload dirs",
		`(?i)(?:AddHandler|AddType)[\s\S]{0,50}(?:php|phtml|application/x-httpd)`,
		[]string{".htaccess"}},
	{"SV-003", CRITICAL, "server",
		"Cron job malware (persistent backdoor)",
		`(?is)(?:\*/\d+\s+\*\s+\*\s+\*\s+\*|@(?:reboot|hourly|daily))[\s\S]{0,200}(?:curl|wget|python|perl|bash|php)[\s\S]{0,200}(?:https?://|/tmp/|/dev/shm/)`,
		[]string{".php", ".sh", ".txt"}},
	{"SV-004", MEDIUM, "server",
		"PHP mail() function used for spam or data exfiltration",
		`(?i)mail\s*\([\s\S]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)`,
		[]string{".php", ".phtml"}},

	// ━━━ Suspicious Functions & Patterns ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"SF-001", INFO, "suspicious",
		"eval() usage (review for legitimacy)",
		`(?i)\beval\s*\(`,
		[]string{".php", ".phtml"}},
	{"SF-002", INFO, "suspicious",
		"base64_decode usage (review context)",
		`(?i)\bbase64_decode\s*\(`,
		[]string{".php", ".phtml"}},
	{"SF-003", INFO, "suspicious",
		"System command execution functions",
		`(?i)\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(`,
		[]string{".php", ".phtml"}},
	{"SF-004", LOW, "suspicious",
		"Disabled functions bypass attempt",
		`(?i)(?:ini_set|ini_alter)\s*\(\s*['"](?:disable_functions|open_basedir|safe_mode)['"]`,
		[]string{".php", ".phtml"}},
	{"SF-005", MEDIUM, "suspicious",
		"Suspicious chmod/permission changes",
		`(?i)chmod\s*\(\s*[\s\S]{0,50}\s*,\s*0?7[0-7]{2}\s*\)`,
		[]string{".php", ".phtml"}},
	{"SF-006", HIGH, "suspicious",
		"PHP code in image/media file",
		`<\?php`,
		[]string{".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".bmp", ".webp"}},
	{"SF-007", HIGH, "suspicious",
		"Hidden PHP file in media/static directories",
		`<\?(?:php|=)`,
		[]string{".php.jpg", ".php.png", ".php.gif", ".phtml.jpg", ".php.ico"}},
	{"SF-008", MEDIUM, "suspicious",
		"Suspicious error suppression with dangerous functions",
		`(?i)@\s*(?:eval|assert|system|exec|passthru|shell_exec|unlink|file_put_contents)\s*\(`,
		[]string{".php", ".phtml"}},

	// ━━━ Database / Credential Theft ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	{"DB-001", HIGH, "credential_theft",
		"Database credential extraction and exfiltration",
		`(?is)(?:db-(?:host|user|password|name)|MYSQL_|DB_PASS)[\s\S]{0,200}(?:curl|file_get_contents|mail|fopen|stream)`,
		[]string{".php", ".phtml"}},
	{"DB-002", HIGH, "credential_theft",
		"Reading Magento env.php for credentials",
		`(?i)(?:file_get_contents|include|require|fopen)\s*\([\s\S]{0,100}app/etc/env\.php`,
		[]string{".php", ".phtml"}},
	{"DB-003", CRITICAL, "credential_theft",
		"Admin credential harvesting",
		`(?is)(?:\$_POST|\$request->getParam)\s*\([\s\S]{0,50}(?:login|password|user)[\s\S]{0,200}(?:curl|file_get_contents|mail|fwrite|stream)`,
		[]string{".php", ".phtml"}},
}

// ─── DB content signatures ──────────────────────────────────────────────────

var DBSignatures = []DBSignatureDef{
	{"DBI-001", CRITICAL, "db_injection",
		"JavaScript skimmer injected in DB content",
		`(?is)<script[^>]*>[\s\S]{0,100}(?:eval|atob|document\.write|String\.fromCharCode)`},
	{"DBI-002", CRITICAL, "db_injection",
		"External script tag loading skimmer from remote domain",
		`(?i)<script[^>]*src\s*=\s*['"]https?://(?!(?:.*\.magento\.com|.*\.adobe\.com|.*\.google\.com|.*\.googleapis\.com|.*\.gstatic\.com|.*\.jquery\.com|.*\.cloudflare\.com|.*\.bootstrapcdn\.com))`},
	{"DBI-003", CRITICAL, "db_injection",
		"Base64-encoded payload in DB content",
		`(?i)(?:atob|base64_decode|eval)\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]`},
	{"DBI-004", CRITICAL, "db_injection",
		"Known Magecart skimmer domain in DB",
		`(?i)(?:google-anaiytic|googie-analytics|google-anaiytics|g00gle-analytics|jquery-cdn|bootstrap-js|cloudflare-cdn|magento-cdn|fontsgoogleapis)\.(?:com|info|org|net|xyz|top|pw)`},
	{"DBI-005", HIGH, "db_injection",
		"Obfuscated JavaScript in DB content",
		`(?i)(?:String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}|unescape\s*\(\s*['"]%[0-9a-fA-F]{2})`},
	{"DBI-006", HIGH, "db_injection",
		"Iframe injection in DB content",
		`(?i)<iframe[^>]*src\s*=\s*['"]https?://(?!.*(?:youtube|vimeo|google|facebook|twitter))`},
	{"DBI-007", HIGH, "db_injection",
		"PHP code injected in DB content",
		`(?i)<\?(?:php|=)\s*(?:eval|system|exec|base64_decode|file_put_contents)`},
	{"DBI-008", CRITICAL, "db_injection",
		"WebSocket/Beacon exfiltration in DB content",
		`(?is)(?:new\s+WebSocket|navigator\.sendBeacon|new\s+Image\s*\(\s*\)\.src)\s*[\(=][\s\S]{0,100}(?:https?://|atob)`},
	{"DBI-009", MEDIUM, "db_injection",
		"Suspicious URL rewrite pointing to external domain in core_config_data",
		`(?i)(?:web/(?:un)?secure/base_url|admin/url/custom)\s*[=:]\s*['"]?https?://(?!localhost|127\.0\.0\.1)[\w.-]+\.[a-z]{2,}`},
	{"DBI-010", MEDIUM, "db_injection",
		"Inline event handler injection (onload, onerror, etc.)",
		`(?i)(?:on(?:load|error|mouseover|click|focus))\s*=\s*['"](?:eval|fetch|XMLHttpRequest|document\.write|atob)`},
}

// ─── Suspicious file names/paths ────────────────────────────────────────────

var SuspiciousFilenames = []SuspiciousFilenameDef{
	{`(?i)(?:^|/)\.(?!htaccess|gitignore|gitkeep|well-known)[a-zA-Z0-9]{1,3}\.php$`, HIGH, "Hidden PHP file (dot-prefixed)"},
	{`(?i)(?:^|/)(?:cmd|shell|wso|c99|r57|b374k|webshell|backdoor|hack|exploit)\.php$`, CRITICAL, "Known malware filename"},
	{`(?i)(?:^|/)(?:upload|media|static|pub)/.+\.(?:php|phtml|php[3-7]|pht)$`, HIGH, "PHP file in content directory"},
	{`(?i)(?:^|/)(?:wp-login|wp-admin|wp-config|xmlrpc)\.php$`, MEDIUM, "WordPress file in Magento (likely malware)"},
	{`(?i)(?:^|/)(?:adminer|phpmyadmin|phpinfo|info|test|debug|phpunit)\.php$`, MEDIUM, "Potentially dangerous utility file"},
	{`(?i)(?:^|/)\.(?:php|phtml|pht)[0-9]*$`, HIGH, "Hidden PHP variant file"},
	{`(?i)(?:^|/)(?:cache|tmp|log|var)/.+\.php$`, HIGH, "PHP file in temp/cache directory"},
	{`(?i)(?:^|/)(?:images|img|css|js|fonts)/.+\.php$`, HIGH, "PHP file in static asset directory"},
	{`(?i)\.php\.(jpg|png|gif|ico|txt|bak|old|swp)$`, HIGH, "PHP file with fake extension"},
}

// ─── Access log exploit patterns ────────────────────────────────────────────

var LogExploitPatterns = []LogExploitPatternDef{
	{"LOG-001", CRITICAL, "log_exploit",
		"CosmicSting XXE exploit attempt (CVE-2024-34102)",
		`(?i)(?:POST|GET)\s+\S*rest/V1/guest-carts/\S*estimate-shipping-methods`,
		`(?i)(?:ENTITY|DOCTYPE|SYSTEM|file://)`},
	{"LOG-002", CRITICAL, "log_exploit",
		"Template injection RCE attempt (CVE-2022-24086)",
		`(?i)(?:POST)\s+\S*(?:checkout|sales/order)`,
		`(?i)(?:\{\{|construct|__destruct|unserialize|Phar)`},
	{"LOG-003", CRITICAL, "log_exploit",
		"Admin brute force attack (multiple failed logins)",
		`(?i)POST\s+\S*/admin\S*(?:/dashboard|/auth/login|/admin_html|/index/index)`,
		""},
	{"LOG-004", HIGH, "log_exploit",
		"Suspicious file upload attempt to media/pub directory",
		`(?i)POST\s+\S*(?:media|pub|static|upload)\S*\.(?:php|phtml|pht)`,
		""},
	{"LOG-005", HIGH, "log_exploit",
		"Direct access to suspicious PHP file",
		`(?i)GET\s+\S*(?:media|pub|static|var|generated)/\S*\.php`,
		""},
	{"LOG-006", HIGH, "log_exploit",
		"SQL injection attempt in URL parameters",
		`(?i)(?:GET|POST)\s+\S*(?:UNION\s+SELECT|SELECT\s+.*FROM|OR\s+1=1|AND\s+1=1|SLEEP\s*\(|BENCHMARK\s*\()`,
		""},
	{"LOG-007", HIGH, "log_exploit",
		"Path traversal / directory traversal attempt",
		`(?i)(?:GET|POST)\s+\S*(?:\.\./\.\./|%2e%2e%2f|\.\.\\|%252e%252e)`,
		""},
	{"LOG-008", HIGH, "log_exploit",
		"Webshell/backdoor access attempt",
		`(?i)GET\s+\S*(?:cmd|shell|wso|c99|r57|b374k|backdoor|hack)\S*\.php`,
		""},
	{"LOG-009", MEDIUM, "log_exploit",
		"REST API mass enumeration / scraping",
		`(?i)GET\s+\S*rest/V1/(?:products|customers|orders)\?searchCriteria`,
		""},
	{"LOG-010", HIGH, "log_exploit",
		"Magento XMLRPC / SOAP API abuse attempt",
		`(?i)POST\s+\S*(?:xmlrpc|soap|api/v2_soap)`,
		`(?i)(?:methodCall|system\.listMethods|admin\.login)`},
	{"LOG-011", CRITICAL, "log_exploit",
		"Remote code execution via layout XML (CVE-2024-20720)",
		`(?i)(?:POST|GET)\s+\S*`,
		`(?i)(?:layout_update|<block.*class=|ObjectManager|Interceptor)`},
	{"LOG-012", HIGH, "log_exploit",
		"Unauthorized API token creation attempt",
		`(?i)POST\s+\S*rest/V1/integration/(?:admin|customer)/token`,
		""},
}

// ─── Magento CVE Database ───────────────────────────────────────────────────

var MagentoCVEs = []CVEDef{
	{"2.4.7-p3", "CVE-2025-24434", CRITICAL,
		"Incorrect Authorization - privilege escalation via REST API",
		"APSB25-08 / Upgrade to 2.4.7-p4 or 2.4.8"},
	{"2.4.7-p3", "CVE-2025-24435", HIGH,
		"Incorrect Authorization - unauthorized access to admin features",
		"APSB25-08 / Upgrade to 2.4.7-p4 or 2.4.8"},
	{"2.4.7-p3", "CVE-2025-24436", MEDIUM,
		"Incorrect Authorization - information disclosure",
		"APSB25-08 / Upgrade to 2.4.7-p4 or 2.4.8"},
	{"2.4.7-p2", "CVE-2024-45115", CRITICAL,
		"Incorrect Authorization - admin privilege escalation without auth",
		"APSB24-73 / Upgrade to 2.4.7-p3"},
	{"2.4.7-p2", "CVE-2024-45148", HIGH,
		"Insecure Direct Object Reference (IDOR) - account takeover",
		"APSB24-73 / Upgrade to 2.4.7-p3"},
	{"2.4.7-p2", "CVE-2024-45116", CRITICAL,
		"Stored Cross-Site Scripting (XSS) - arbitrary code execution",
		"APSB24-73 / Upgrade to 2.4.7-p3"},
	{"2.4.7-p2", "CVE-2024-45117", HIGH,
		"Server-Side Request Forgery (SSRF) - internal service access",
		"APSB24-73 / Upgrade to 2.4.7-p3"},
	{"2.4.7-p1", "CVE-2024-39397", CRITICAL,
		"Unrestricted Upload - Remote Code Execution via file upload (Apache)",
		"APSB24-61 / Upgrade to 2.4.7-p2"},
	{"2.4.7-p1", "CVE-2024-39398", HIGH,
		"Brute Force vulnerability on admin login",
		"APSB24-61 / Upgrade to 2.4.7-p2"},
	{"2.4.7-p1", "CVE-2024-39399", HIGH,
		"Server-Side Request Forgery via crafted request",
		"APSB24-61 / Upgrade to 2.4.7-p2"},
	{"2.4.7-p1", "CVE-2024-39401", CRITICAL,
		"OS Command Injection - authenticated RCE",
		"APSB24-61 / Upgrade to 2.4.7-p2"},
	{"2.4.7-p1", "CVE-2024-39402", CRITICAL,
		"OS Command Injection - authenticated RCE (variant)",
		"APSB24-61 / Upgrade to 2.4.7-p2"},
	{"2.4.6-p6", "CVE-2024-34102", CRITICAL,
		"CosmicSting - XXE/SSRF leading to RCE (ACTIVELY EXPLOITED)",
		"APSB24-40 / Upgrade to 2.4.7-p1+ / Apply isolated patch"},
	{"2.4.6-p5", "CVE-2024-20720", CRITICAL,
		"OS Command Injection via crafted layout template (ACTIVELY EXPLOITED)",
		"APSB24-18 / Upgrade to 2.4.6-p4+"},
	{"2.4.6-p4", "CVE-2024-20719", CRITICAL,
		"Stored XSS in admin panel leading to arbitrary code execution",
		"APSB24-18 / Upgrade to 2.4.6-p4+"},
	{"2.4.6-p2", "CVE-2023-38218", HIGH,
		"Insecure Direct Object Reference - customer account information leak",
		"APSB23-50 / Upgrade to 2.4.6-p3+"},
	{"2.4.6-p2", "CVE-2023-38219", HIGH,
		"Stored XSS via customer account",
		"APSB23-50 / Upgrade to 2.4.6-p3+"},
	{"2.4.6-p1", "CVE-2023-26366", CRITICAL,
		"SSRF - Server-Side Request Forgery",
		"APSB23-42 / Upgrade to 2.4.6-p2+"},
	{"2.4.6", "CVE-2023-26359", CRITICAL,
		"Deserialization of Untrusted Data leading to RCE",
		"APSB23-17 / Upgrade to 2.4.6-p1+"},
	{"2.4.5-p2", "CVE-2023-22247", CRITICAL,
		"XML Injection leading to arbitrary file read",
		"APSB23-17 / Upgrade to 2.4.5-p4+"},
	{"2.4.4-p2", "CVE-2022-35698", CRITICAL,
		"Stored XSS leading to arbitrary code execution",
		"APSB22-48 / Upgrade to 2.4.5+"},
	{"2.4.4-p1", "CVE-2022-35689", HIGH,
		"Incorrect Authorization - improper access control",
		"APSB22-38 / Upgrade to 2.4.4-p2+"},
	{"2.4.3-p2", "CVE-2022-24086", CRITICAL,
		"Template injection - Pre-auth RCE (ACTIVELY EXPLOITED IN THE WILD)",
		"APSB22-12 / Upgrade to 2.4.3-p2+ / Apply isolated patch"},
	{"2.4.3-p1", "CVE-2022-24093", CRITICAL,
		"OS Command Injection - authenticated RCE",
		"APSB22-13 / Upgrade to 2.4.3-p2+"},
	{"2.3.7-p3", "CVE-2021-36044", CRITICAL,
		"GraphQL query depth DoS + information disclosure",
		"Upgrade to 2.4.x"},
	{"2.3.7", "CVE-2021-21024", CRITICAL,
		"SQL Injection - blind SQL injection via admin",
		"Upgrade to 2.4.x"},
	{"2.3.5-p1", "CVE-2020-9689", CRITICAL,
		"Arbitrary file write via directory traversal",
		"Upgrade to 2.4.x"},
}

// ─── YARA rules (built-in) ─────────────────────────────────────────────────

var YaraRulesSource = `
rule php_in_image {
    meta:
        description = "PHP code hidden inside image file (binary header check)"
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

rule elf_in_webdir {
    meta:
        description = "ELF binary hidden in web directory (cryptominer, rootkit)"
        severity = "CRITICAL"
        category = "backdoor"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0 and filesize < 10MB
}

rule php_obfuscated_concat_chain {
    meta:
        description = "Heavily obfuscated PHP via long chr()/ord() concatenation chains"
        severity = "HIGH"
        category = "obfuscation"
    strings:
        $chr_long = /(\$\w+=chr\(\d+\)\.){8,}/
        $ord_long = /(chr\(\d+\)\.){15,}/
        $hex_dense = /(\\x[0-9a-fA-F]{2}){20,}/
    condition:
        any of them
}

rule hidden_php_extension {
    meta:
        description = "PHP file disguised with double extension"
        severity = "HIGH"
        category = "suspicious"
    strings:
        $php = "<?php" nocase
    condition:
        $php and (
            filename matches /\.php\.(jpg|png|gif|ico|txt|bak|old)$/i or
            filename matches /\.(jpg|png|gif|ico)\.php$/i
        )
}
`

// ─── YARA rulesets for auto-download ────────────────────────────────────────

var YaraRulesets = []YaraRulesetDef{
	{"sansec-magento",
		"Sansec/ecomscan -- largest Magento malware signature collection",
		"https://github.com/gwillem/magento-malware-scanner/archive/refs/heads/master.tar.gz",
		1, []string{"build/*.yar", "rules/*.yar"}},
	{"magesec",
		"Mage Security Council -- Magento YARA rules (standard + deep)",
		"https://github.com/magesec/magesecurityscanner/archive/refs/heads/master.tar.gz",
		1, []string{"*.yar"}},
	{"signature-base",
		"Neo23x0 YARA rules -- webshells, exploits, malware",
		"https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz",
		1, []string{"yara/*.yar"}},
	{"reversinglabs",
		"ReversingLabs YARA rules -- malware families",
		"https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.tar.gz",
		1, []string{"yara/**/*.yar", "yara/**/*.yara"}},
	{"elastic",
		"Elastic protections -- cross-platform malware YARA",
		"https://github.com/elastic/protections-artifacts/archive/refs/heads/main.tar.gz",
		1, []string{"yara/**/*.yar"}},
}

// ─── Scannable extensions ───────────────────────────────────────────────────

var ScannableExtensions = map[string]bool{
	".php": true, ".phtml": true, ".php3": true, ".php4": true,
	".php5": true, ".php7": true, ".pht": true,
	".js": true, ".html": true, ".htm": true, ".xml": true, ".json": true,
	".htaccess": true, ".htpasswd": true,
	".sh": true, ".bash": true, ".cgi": true, ".pl": true, ".py": true,
	".svg": true, ".sql": true, ".tpl": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".ico": true, ".bmp": true, ".webp": true,
}

var SkipDirs = map[string]bool{
	".git": true, "node_modules": true, ".svn": true, ".hg": true,
}

var WhitelistPaths = []string{
	// Test frameworks
	"vendor/phpunit",
	"dev/tests",
	// Magento core code generators / compilers
	"setup/src",
	"lib/internal/Magento/Framework/Code/Generator",
	"lib/internal/Magento/Framework/Interception",
	"lib/internal/Magento/Framework/ObjectManager",
	// Generated / compiled code
	"generated/code",
	"generated/metadata",
	"var/generation",
	// Vendor libs that legitimately use eval, base64, exec, etc.
	"vendor/magento",
	"vendor/laminas",
	"vendor/symfony",
	"vendor/composer",
	"vendor/monolog",
	"vendor/guzzlehttp",
	"vendor/pelago",
	"vendor/phpcompatibility",
	"vendor/squizlabs",
	"vendor/phpstan",
	"vendor/rector",
	"vendor/php-cs-fixer",
	"vendor/friendsofphp",
	"vendor/colinmollenhour",
	"vendor/tubalmartin",
	"vendor/wikimedia",
	"vendor/webonyx",
	"vendor/braintree",
	"vendor/paypal",
	"vendor/stripe",
	"vendor/amzn",
	"vendor/klarna",
	// Magento static/frontend build tooling
	"lib/web/jquery",
	"lib/web/knockoutjs",
	"lib/web/requirejs",
	"lib/web/mage",
	"lib/web/tiny_mce",
	// Static deployed assets (compiled from vendor)
	"pub/static/frontend",
	"pub/static/adminhtml",
	"pub/static/_requirejs",
}
