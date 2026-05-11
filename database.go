package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type DatabaseScanner struct {
	root     string
	verbose  bool
	dbConfig map[string]string
}

func NewDatabaseScanner(magentoRoot string, verbose bool) *DatabaseScanner {
	ds := &DatabaseScanner{root: magentoRoot, verbose: verbose}
	ds.dbConfig = ds.readEnvPHP()
	return ds
}

func (ds *DatabaseScanner) readEnvPHP() map[string]string {
	envPath := filepath.Join(ds.root, "app", "etc", "env.php")
	data, err := os.ReadFile(envPath)
	if err != nil {
		return nil
	}
	content := string(data)
	config := make(map[string]string)

	// Find default DB connection block
	dbSection := regexp.MustCompile(`(?s)'connection'\s*=>\s*\[\s*'default'\s*=>\s*\[(.*?)\]\s*\]`)
	m := dbSection.FindStringSubmatch(content)
	if m == nil {
		dbSection2 := regexp.MustCompile(`(?s)'db'\s*=>\s*\[[\s\S]*?'connection'\s*=>\s*\[\s*'default'\s*=>\s*\[(.*?)\]`)
		m = dbSection2.FindStringSubmatch(content)
	}
	if m != nil {
		section := m[1]
		for _, key := range []string{"host", "dbname", "username", "password", "port", "unix_socket"} {
			re := regexp.MustCompile(`'` + key + `'\s*=>\s*'([^']*)'`)
			km := re.FindStringSubmatch(section)
			if km != nil {
				config[key] = km[1]
			}
		}
	}

	// Table prefix
	prefixRe := regexp.MustCompile(`'table_prefix'\s*=>\s*'([^']*)'`)
	pm := prefixRe.FindStringSubmatch(content)
	if pm != nil {
		config["table_prefix"] = pm[1]
	} else {
		config["table_prefix"] = ""
	}

	if _, ok := config["dbname"]; !ok {
		return nil
	}
	if _, ok := config["host"]; !ok {
		if _, ok2 := config["unix_socket"]; !ok2 {
			return nil
		}
	}
	return config
}

func (ds *DatabaseScanner) runQuery(query string) string {
	if ds.dbConfig == nil {
		return ""
	}

	args := []string{"--batch", "--raw", "-N",
		"-u" + ds.dbConfig["username"],
		"-D" + ds.dbConfig["dbname"],
	}
	if sock, ok := ds.dbConfig["unix_socket"]; ok && sock != "" {
		args = append(args, "--socket="+sock)
	} else {
		host := ds.dbConfig["host"]
		if host == "" {
			host = "localhost"
		}
		port := ds.dbConfig["port"]
		if port == "" {
			port = "3306"
		}
		args = append(args, "-h"+host, "-P"+port)
	}
	if pw := ds.dbConfig["password"]; pw != "" {
		args = append(args, "-p"+pw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "mysql", args...)
	cmd.Stdin = strings.NewReader(query)
	out, err := cmd.Output()
	if err != nil {
		if ds.verbose {
			fmt.Fprintf(os.Stderr, "  [DB] MySQL error: %v\n", err)
		}
		return ""
	}
	return string(out)
}

func (ds *DatabaseScanner) Scan() []Finding {
	if ds.dbConfig == nil {
		if ds.verbose {
			fmt.Fprintln(os.Stderr, "  [DB] Could not read database config from env.php")
		}
		return nil
	}

	var findings []Finding
	prefix := ds.dbConfig["table_prefix"]

	// Compile DB signatures
	type compiledDBSig struct {
		ID, Severity, Category, Description string
		Regex                               *regexp.Regexp
	}
	var sigs []compiledDBSig
	for _, s := range DBSignatures {
		r, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		sigs = append(sigs, compiledDBSig{s.ID, s.Severity, s.Category, s.Description, r})
	}

	// Tables to scan
	type target struct {
		table, label string
		columns      []string
	}
	targets := []target{
		{prefix + "core_config_data", "core_config_data", []string{"path", "value"}},
		{prefix + "cms_block", "cms_block", []string{"content", "title", "identifier"}},
		{prefix + "cms_page", "cms_page", []string{"content", "title", "identifier", "content_heading", "layout_update_xml"}},
		{prefix + "email_template", "email_template", []string{"template_text", "template_subject"}},
		{prefix + "sales_order_status_label", "sales_order_status_label", []string{"label"}},
	}

	// Check admin users
	findings = append(findings, ds.checkAdminUsers(prefix)...)
	// Check cron schedule
	findings = append(findings, ds.checkCronSchedule(prefix)...)

	likePatterns := []string{
		"<script%", "%eval(%", "%base64_decode(%",
		"%atob(%", "%document.write(%", "%String.fromCharCode%",
		"%<iframe%", "%<?php%", "%onload=%", "%onerror=%",
		"%WebSocket%", "%sendBeacon%",
	}

	for _, t := range targets {
		for _, col := range t.columns {
			var clauses []string
			for _, p := range likePatterns {
				clauses = append(clauses, fmt.Sprintf("`%s` LIKE '%s'", col, p))
			}
			query := fmt.Sprintf("SELECT `%s` FROM `%s` WHERE %s LIMIT 100;",
				col, t.table, strings.Join(clauses, " OR "))

			output := ds.runQuery(query)
			if output == "" {
				continue
			}

			for rowNum, row := range strings.Split(strings.TrimSpace(output), "\n") {
				if strings.TrimSpace(row) == "" {
					continue
				}
				for _, sig := range sigs {
					if sig.Regex.MatchString(row) {
						snippet := row
						if len(snippet) > 200 {
							snippet = snippet[:200]
						}
						findings = append(findings, Finding{
							FilePath:    fmt.Sprintf("DB:%s.%s", t.label, col),
							SignatureID: sig.ID,
							Severity:    sig.Severity,
							Category:    sig.Category,
							Description: sig.Description,
							LineNumber:  rowNum + 1,
							LineContent: strings.TrimSpace(snippet),
							Context:     fmt.Sprintf("Table: %s, Column: %s", t.table, col),
						})
						break
					}
				}
			}
		}
	}

	return findings
}

func (ds *DatabaseScanner) checkAdminUsers(prefix string) []Finding {
	var findings []Finding
	query := fmt.Sprintf(`SELECT CONCAT(username, '|', email, '|', created)
		FROM %sadmin_user
		WHERE created > DATE_SUB(NOW(), INTERVAL 30 DAY)
		ORDER BY created DESC LIMIT 20;`, prefix)

	output := ds.runQuery(query)
	if output == "" {
		return nil
	}

	suspiciousEmail := regexp.MustCompile(`(?i)@(?:mail\.ru|yandex|proton|tutanota|guerrilla|tempmail|throwaway)`)
	suspiciousUser := regexp.MustCompile(`(?i)^(?:admin\d+|test\d*|user\d+|support\d+)$`)

	for _, row := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(row) == "" {
			continue
		}
		parts := strings.SplitN(row, "|", 3)
		username := ""
		email := ""
		created := ""
		if len(parts) > 0 {
			username = parts[0]
		}
		if len(parts) > 1 {
			email = parts[1]
		}
		if len(parts) > 2 {
			created = parts[2]
		}

		suspicious := false
		reason := ""
		if suspiciousEmail.MatchString(email) {
			suspicious = true
			reason = "Suspicious email domain: " + email
		} else if suspiciousUser.MatchString(username) {
			suspicious = true
			reason = "Generic admin username: " + username
		}

		if suspicious {
			findings = append(findings, Finding{
				FilePath:    "DB:admin_user",
				SignatureID: "DBI-ADM",
				Severity:    HIGH,
				Category:    "db_injection",
				Description: "Suspicious admin user created recently - " + reason,
				LineContent: fmt.Sprintf("User: %s, Email: %s, Created: %s", username, email, created),
				Context:     "admin_user table",
			})
		}
	}
	return findings
}

func (ds *DatabaseScanner) checkCronSchedule(prefix string) []Finding {
	var findings []Finding
	query := fmt.Sprintf(`SELECT CONCAT(job_code, '|', status, '|', scheduled_at)
		FROM %scron_schedule
		WHERE job_code NOT LIKE 'catalog_%%'
		  AND job_code NOT LIKE 'sales_%%'
		  AND job_code NOT LIKE 'indexer_%%'
		  AND job_code NOT LIKE 'newsletter_%%'
		  AND job_code NOT LIKE 'sitemap_%%'
		  AND job_code NOT LIKE 'currency_%%'
		  AND job_code NOT LIKE 'backup_%%'
		  AND job_code NOT LIKE 'staging_%%'
		  AND job_code NOT LIKE 'analytics_%%'
		  AND job_code NOT LIKE 'consumers_%%'
		  AND job_code NOT LIKE 'magento_%%'
		ORDER BY scheduled_at DESC LIMIT 50;`, prefix)

	output := ds.runQuery(query)
	if output == "" {
		return nil
	}

	suspPat := regexp.MustCompile(`(?i)(?:curl|wget|eval|base64|shell|exec|system|php\s+-r)`)
	for _, row := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(row) == "" {
			continue
		}
		if suspPat.MatchString(row) {
			snippet := row
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			findings = append(findings, Finding{
				FilePath:    "DB:cron_schedule",
				SignatureID: "DBI-CRON",
				Severity:    HIGH,
				Category:    "db_injection",
				Description: "Suspicious cron job in database",
				LineContent: snippet,
				Context:     "cron_schedule table",
			})
		}
	}
	return findings
}
