package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type ipData struct {
	Count    int
	Patterns map[string]bool
	Paths    map[string]bool
}

func findLogs(root string) []string {
	candidates := []string{
		filepath.Join(root, "var", "log", "access.log"),
		"/var/log/apache2/access.log",
		"/var/log/apache2/other_vhosts_access.log",
		"/var/log/httpd/access_log",
		"/var/log/nginx/access.log",
	}

	// Auto-discover /home/*/logs/apache/ (common hosting layout)
	homeDirs, _ := filepath.Glob("/home/*/logs/apache")
	for _, d := range homeDirs {
		candidates = append(candidates, d)
	}

	var found []string
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, _ := os.ReadDir(c)
			for _, e := range entries {
				name := strings.ToLower(e.Name())
				if !e.IsDir() && (strings.Contains(name, "access") || strings.HasSuffix(name, ".log")) {
					found = append(found, filepath.Join(c, e.Name()))
				}
			}
		} else {
			found = append(found, c)
		}
	}

	// Rotated logs
	for _, log := range append([]string{}, found...) {
		for _, suffix := range []string{".1", ".2"} {
			rotated := log + suffix
			if _, err := os.Stat(rotated); err == nil {
				found = append(found, rotated)
			}
		}
	}

	return found
}

func analyzeLogs(root string, logPaths []string, cmsType CMSType, verbose bool) ([]Finding, []SuspiciousIP) {
	if len(logPaths) == 0 {
		logPaths = findLogs(root)
	}
	if len(logPaths) == 0 {
		if verbose {
			fmt.Fprintln(os.Stderr, "  [LOG] No access logs found")
		}
		return nil, nil
	}

	// Compile patterns - common + CMS-specific
	allPatterns := append([]LogExploitPatternDef{}, LogExploitPatterns...)
	switch cmsType {
	case CMSWordPress:
		allPatterns = append(allPatterns, WordPressLogPatterns...)
	case CMSPrestaShop:
		allPatterns = append(allPatterns, PrestaShopLogPatterns...)
	}

	type compiledLogPat struct {
		ID, Severity, Category, Description string
		URLRegex                            *regexp.Regexp
		BodyRegex                           *regexp.Regexp
	}
	var patterns []compiledLogPat
	for _, p := range allPatterns {
		urlRe, err := regexp.Compile(p.URLPattern)
		if err != nil {
			continue
		}
		var bodyRe *regexp.Regexp
		if p.BodyPattern != "" {
			bodyRe, _ = regexp.Compile(p.BodyPattern)
		}
		patterns = append(patterns, compiledLogPat{
			p.ID, p.Severity, p.Category, p.Description, urlRe, bodyRe,
		})
	}

	var findings []Finding
	ipCounter := make(map[string]*ipData)
	adminBruteforce := make(map[string]int)

	// Track successful (200) access to suspicious paths
	type shellAccess struct {
		IP     string
		Path   string
		Status string
		Date   string
	}
	var successfulShellAccess []shellAccess
	shellPathRe := regexp.MustCompile(`(?i)(?:custom_options|upload|tmp|media)/.*\.(?:php|phtml|pht|php[3-7])`)

	logRe := regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)`)
	adminPostRe := regexp.MustCompile(`(?i)POST\s+\S*/admin\S*(?:/dashboard|/auth/login|/index/index|/admin_html)`)

	for _, logPath := range logPaths {
		f, err := os.Open(logPath)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "  [LOG] Cannot read %s: %v\n", logPath, err)
			}
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			if lineNum > 500000 {
				if verbose {
					fmt.Fprintf(os.Stderr, "  [LOG] Truncated %s at 500K lines\n", logPath)
				}
				break
			}

			line := scanner.Text()
			m := logRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}

			ip := m[1]
			method := m[3]
			path := m[4]
			statusCode := m[5]
			fullRequest := method + " " + path

			// Admin brute force
			if adminPostRe.MatchString(fullRequest) {
				adminBruteforce[ip]++
			}

			// Track successful access to shell/PHP files in upload dirs
			if shellPathRe.MatchString(path) {
				if statusCode == "200" {
					date := m[2]
					successfulShellAccess = append(successfulShellAccess, shellAccess{
						IP: ip, Path: path, Status: statusCode, Date: date,
					})
				}
			}

			// Exploit patterns
			for _, pat := range patterns {
				if pat.ID == "LOG-003" {
					continue // handled by frequency
				}
				if pat.URLRegex.MatchString(fullRequest) {
					if pat.BodyRegex == nil || pat.BodyRegex.MatchString(line) {
						if ipCounter[ip] == nil {
							ipCounter[ip] = &ipData{
								Patterns: make(map[string]bool),
								Paths:    make(map[string]bool),
							}
						}
						ipCounter[ip].Count++
						ipCounter[ip].Patterns[pat.ID] = true
						truncPath := path
						if len(truncPath) > 100 {
							truncPath = truncPath[:100]
						}
						ipCounter[ip].Paths[truncPath] = true

						if ipCounter[ip].Count <= 3 {
							reqSnippet := fullRequest
							if len(reqSnippet) > 150 {
								reqSnippet = reqSnippet[:150]
							}
							findings = append(findings, Finding{
								FilePath:    "LOG:" + filepath.Base(logPath),
								SignatureID: pat.ID,
								Severity:    pat.Severity,
								Category:    pat.Category,
								Description: pat.Description,
								LineNumber:  lineNum,
								LineContent: fmt.Sprintf("IP: %s | %s", ip, reqSnippet),
								Context:     "Status: " + statusCode,
							})
						}
						break
					}
				}
			}
		}
		f.Close()
	}

	// Admin brute force findings
	for ip, count := range adminBruteforce {
		if count >= 10 {
			sev := HIGH
			if count >= 50 {
				sev = CRITICAL
			}
			findings = append(findings, Finding{
				FilePath:    "ACCESS_LOG",
				SignatureID: "LOG-003",
				Severity:    sev,
				Category:    "log_exploit",
				Description: fmt.Sprintf("Admin brute force: %d login attempts from %s", count, ip),
				LineContent: fmt.Sprintf("IP: %s, Attempts: %d", ip, count),
			})
		}
	}

	// Successful shell access = confirmed exploitation
	if len(successfulShellAccess) > 0 {
		// Group by IP
		shellByIP := make(map[string][]shellAccess)
		for _, sa := range successfulShellAccess {
			shellByIP[sa.IP] = append(shellByIP[sa.IP], sa)
		}
		for ip, accesses := range shellByIP {
			sample := accesses[0]
			paths := []string{}
			seen := map[string]bool{}
			for _, a := range accesses {
				if !seen[a.Path] && len(paths) < 5 {
					paths = append(paths, a.Path)
					seen[a.Path] = true
				}
			}
			findings = append(findings, Finding{
				FilePath:    "ACCESS_LOG",
				SignatureID: "LOG-200",
				Severity:    CRITICAL,
				Category:    "log_exploit",
				Description: fmt.Sprintf("CONFIRMED EXPLOITATION: %d successful (HTTP 200) access to PHP shell from %s", len(accesses), ip),
				LineContent: fmt.Sprintf("IP: %s | Paths: %s | Date: %s", ip, strings.Join(paths, ", "), sample.Date),
			})
		}
	} else {
		// No 200 on shells = good news, add as INFO-level finding
		findings = append(findings, Finding{
			FilePath:    "ACCESS_LOG",
			SignatureID: "LOG-200",
			Severity:    INFO,
			Category:    "log_exploit",
			Description: "No successful (HTTP 200) access to PHP files in upload/media directories detected",
			LineContent: "All shell access attempts returned 403/404 — no confirmed exploitation",
		})
	}

	// Build suspicious IP list
	type ipEntry struct {
		IP   string
		Data *ipData
	}
	var ipList []ipEntry
	for ip, data := range ipCounter {
		if data.Count >= 3 {
			ipList = append(ipList, ipEntry{ip, data})
		}
	}
	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].Data.Count > ipList[j].Data.Count
	})

	var suspiciousIPs []SuspiciousIP
	for i, entry := range ipList {
		if i >= 20 {
			break
		}
		var pats []string
		for p := range entry.Data.Patterns {
			pats = append(pats, p)
			if len(pats) >= 5 {
				break
			}
		}
		var paths []string
		for p := range entry.Data.Paths {
			paths = append(paths, p)
			if len(paths) >= 5 {
				break
			}
		}
		suspiciousIPs = append(suspiciousIPs, SuspiciousIP{
			IP: entry.IP, HitCount: entry.Data.Count,
			PatternsMatched: pats, SamplePaths: paths,
		})
	}

	return findings, suspiciousIPs
}
