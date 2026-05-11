package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type compiledSig struct {
	ID, Severity, Category, Description string
	Regex                               *regexp.Regexp
	Extensions                          map[string]bool
}

type compiledFilenameSig struct {
	Regex    *regexp.Regexp
	Severity string
	Reason   string
}

type fileResult struct {
	Findings    []Finding
	Suspicious  []SuspiciousFile
}

// An4Scanner is the main scanner.
type An4Scanner struct {
	Path             string
	Workers          int
	MinSeverity      string
	Whitelist        []string
	JSONOutput       bool
	Verbose          bool
	Quiet            bool
	ScanDB           bool
	CheckMtime       bool
	MtimeDays        int
	CheckPermissions bool
	UseYara          bool
	YaraRulesPath    string
	CheckVersion     bool
	AnalyzeLogs      bool
	CheckPlugins     bool
	CheckIntegrity   bool
	LogPaths         []string
	HTMLOutput       string
	DiffPath         string
	SaveScan         bool
	showProgress     bool
	cms              CMSInfo

	compiledSigs      []compiledSig
	compiledFilenames []compiledFilenameSig
}

func NewScanner(path string) *An4Scanner {
	return &An4Scanner{
		Path:        path,
		Workers:     4,
		MinSeverity: HIGH,
		MtimeDays:   7,
	}
}

func (s *An4Scanner) Init() {
	s.showProgress = !s.JSONOutput && !s.Quiet
	// Detect CMS first
	s.cms = detectCMS(s.Path)
	// Add CMS-specific whitelist paths
	s.Whitelist = append(s.Whitelist, getWhitelistForCMS(s.cms.Type)...)
	s.compileSigs()
	s.compileFilenames()
}

func (s *An4Scanner) compileSigs() {
	// Common signatures (always loaded)
	allSigs := append([]SignatureDef{}, Signatures...)

	// Add CMS-specific signatures
	switch s.cms.Type {
	case CMSWordPress:
		allSigs = append(allSigs, WordPressSignatures...)
	case CMSPrestaShop:
		allSigs = append(allSigs, PrestaShopSignatures...)
	}

	for _, sig := range allSigs {
		if severityOrder[sig.Severity] > severityOrder[s.MinSeverity] {
			continue
		}
		r, err := regexp.Compile(sig.Pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid regex in %s: %v\n", sig.ID, err)
			continue
		}
		var exts map[string]bool
		if sig.Extensions != nil {
			exts = make(map[string]bool)
			for _, e := range sig.Extensions {
				exts[e] = true
			}
		}
		s.compiledSigs = append(s.compiledSigs, compiledSig{
			ID: sig.ID, Severity: sig.Severity, Category: sig.Category,
			Description: sig.Description, Regex: r, Extensions: exts,
		})
	}
}

func (s *An4Scanner) compileFilenames() {
	allPatterns := append([]SuspiciousFilenameDef{}, SuspiciousFilenames...)

	switch s.cms.Type {
	case CMSWordPress:
		allPatterns = append(allPatterns, WordPressSuspiciousFilenames...)
	case CMSPrestaShop:
		allPatterns = append(allPatterns, PrestaShopSuspiciousFilenames...)
	}

	for _, sf := range allPatterns {
		if severityOrder[sf.Severity] > severityOrder[s.MinSeverity] {
			continue
		}
		r, err := regexp.Compile(sf.Pattern)
		if err != nil {
			continue
		}
		s.compiledFilenames = append(s.compiledFilenames, compiledFilenameSig{
			Regex: r, Severity: sf.Severity, Reason: sf.Reason,
		})
	}
}

func (s *An4Scanner) shouldSkipDir(name string) bool {
	return SkipDirs[name]
}

func (s *An4Scanner) isWhitelisted(relPath string) bool {
	for _, wp := range WhitelistPaths {
		if strings.HasPrefix(relPath, wp) {
			return true
		}
	}
	for _, wp := range s.Whitelist {
		if strings.HasPrefix(relPath, wp) {
			return true
		}
	}
	return false
}

func (s *An4Scanner) collectFiles() []string {
	var files []string
	filepath.WalkDir(s.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if s.shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ScannableExtensions[ext] || d.Name() == ".htaccess" {
			files = append(files, path)
		} else {
			rel, _ := filepath.Rel(s.Path, path)
			for _, p := range s.compiledFilenames {
				if p.Regex.MatchString(rel) {
					files = append(files, path)
					break
				}
			}
		}
		return nil
	})
	return files
}

var imageExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".ico": true, ".bmp": true, ".webp": true, ".svg": true,
}

func (s *An4Scanner) scanFile(path string) ([]Finding, []SuspiciousFile) {
	var findings []Finding
	var suspicious []SuspiciousFile

	rel, _ := filepath.Rel(s.Path, path)

	// Check filename patterns
	for _, p := range s.compiledFilenames {
		if p.Regex.MatchString(rel) {
			suspicious = append(suspicious, SuspiciousFile{
				File: rel, Severity: p.Severity, Reason: p.Reason,
			})
		}
	}

	// Skip whitelisted
	if s.isWhitelisted(rel) {
		return findings, suspicious
	}

	// Check size
	info, err := os.Stat(path)
	if err != nil || info.Size() > MaxFileSize || info.Size() == 0 {
		return findings, suspicious
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return findings, suspicious
	}

	ext := strings.ToLower(filepath.Ext(path))

	// PHP in image check
	if imageExts[ext] {
		if bytes.Contains(data, []byte("<?php")) || bytes.Contains(data, []byte("<?=")) {
			findings = append(findings, Finding{
				FilePath: rel, SignatureID: "SF-006", Severity: HIGH,
				Category: "suspicious", Description: "PHP code embedded in image/media file",
				LineContent: "(binary file)",
			})
		}
		return findings, suspicious
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Signature checks
	for _, sig := range s.compiledSigs {
		if sig.Extensions != nil && !sig.Extensions[ext] {
			continue
		}
		for i, line := range lines {
			if len(line) > 10000 {
				for chunkStart := 0; chunkStart < len(line); chunkStart += 8000 {
					end := chunkStart + 10000
					if end > len(line) {
						end = len(line)
					}
					chunk := line[chunkStart:end]
					if sig.Regex.MatchString(chunk) {
						snippet := chunk
						if len(snippet) > 200 {
							snippet = snippet[:200]
						}
						findings = append(findings, Finding{
							FilePath: rel, SignatureID: sig.ID,
							Severity: sig.Severity, Category: sig.Category,
							Description: sig.Description,
							LineNumber: i + 1, LineContent: strings.TrimSpace(snippet),
						})
						break
					}
				}
			} else if sig.Regex.MatchString(line) {
				snippet := line
				if len(snippet) > 200 {
					snippet = snippet[:200]
				}
				findings = append(findings, Finding{
					FilePath: rel, SignatureID: sig.ID,
					Severity: sig.Severity, Category: sig.Category,
					Description: sig.Description,
					LineNumber: i + 1, LineContent: strings.TrimSpace(snippet),
				})
			}
		}
	}

	// Entropy check
	if (ext == ".php" || ext == ".phtml" || ext == ".js") && len(content) > 500 {
		for i, line := range lines {
			stripped := strings.TrimSpace(line)
			if len(stripped) > 1000 {
				entropy := shannonEntropy(stripped)
				if entropy > 5.5 && len(stripped) > 2000 {
					snippet := stripped
					if len(snippet) > 200 {
						snippet = snippet[:200]
					}
					findings = append(findings, Finding{
						FilePath: rel, SignatureID: "OB-ENT",
						Severity: MEDIUM, Category: "obfuscation",
						Description: fmt.Sprintf("High entropy line (entropy=%.2f) - possible obfuscated code", entropy),
						LineNumber: i + 1, LineContent: snippet,
					})
				}
			}
		}
	}

	return findings, suspicious
}

func shannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range data {
		freq[c]++
	}
	length := float64(len([]rune(data)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func (s *An4Scanner) Scan() *ScanResult {
	start := time.Now()
	result := &ScanResult{
		ScanPath:  s.Path,
		StartTime: start.Format(time.RFC3339),
	}

	result.CMSInfo = s.cms

	if s.showProgress {
		s.printBanner()
		fmt.Printf("  Scanning: %s\n", s.Path)
		if s.cms.Type != CMSUnknown {
			fmt.Printf("  CMS:      %s %s", s.cms.Name, s.cms.Version)
			if s.cms.Edition != "" {
				fmt.Printf(" (%s)", s.cms.Edition)
			}
			fmt.Println()
			if s.cms.EOL != "" {
				fmt.Printf("  %s⚠ %s%s\n", severityColors[CRITICAL], s.cms.EOL, Reset)
			}
		} else {
			fmt.Println("  CMS:      Unknown (using generic signatures)")
		}
		fmt.Printf("  Workers:  %d\n", s.Workers)
		fmt.Printf("  Min severity: %s\n", s.MinSeverity)
		var modules []string
		if s.ScanDB {
			modules = append(modules, "DB")
		}
		if s.CheckMtime {
			modules = append(modules, fmt.Sprintf("MTIME(%dd)", s.MtimeDays))
		}
		if s.CheckPermissions {
			modules = append(modules, "PERMS")
		}
		if s.UseYara {
			modules = append(modules, "YARA")
		}
		if s.CheckVersion {
			modules = append(modules, "VERSION/CVE")
		}
		if s.AnalyzeLogs {
			modules = append(modules, "LOGS")
		}
		if s.CheckPlugins {
			modules = append(modules, "PLUGINS")
		}
		if s.CheckIntegrity {
			modules = append(modules, "INTEGRITY")
		}
		if len(modules) > 0 {
			fmt.Printf("  Modules:  %s\n", strings.Join(modules, ", "))
		}
		fmt.Println()
	}

	// Collect files
	files := s.collectFiles()
	totalFiles := len(files)

	if s.showProgress {
		fmt.Printf("  Found %d files to scan...\n\n", totalFiles)
	}

	// Parallel file scan
	var allFindings []Finding
	var allSuspicious []SuspiciousFile
	var mu sync.Mutex
	var scanned int64

	fileCh := make(chan string, 256)
	var wg sync.WaitGroup

	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileCh {
				findings, suspicious := s.scanFile(path)
				n := atomic.AddInt64(&scanned, 1)
				if s.showProgress && n%500 == 0 {
					fmt.Fprintf(os.Stderr, "\r  Progress: %d/%d files scanned, findings so far...", n, totalFiles)
				}
				if len(findings) > 0 || len(suspicious) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					allSuspicious = append(allSuspicious, suspicious...)
					mu.Unlock()
				}
			}
		}()
	}

	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)
	wg.Wait()

	if s.showProgress {
		fmt.Fprintf(os.Stderr, "\r  Progress: %d/%d files scanned.        \n\n", totalFiles, totalFiles)
	}

	// Database scan
	if s.ScanDB {
		if s.showProgress {
			fmt.Println("  Scanning database...")
		}
		dbScanner := NewDatabaseScanner(s.Path, s.Verbose)
		result.DBFindings = dbScanner.Scan()
		if s.showProgress {
			fmt.Printf("  Database: %d finding(s)\n\n", len(result.DBFindings))
		}
	}

	// Permission check
	if s.CheckPermissions {
		if s.showProgress {
			fmt.Println("  Checking file permissions...")
		}
		result.PermissionFindings = checkPermissions(s.Path, s.Verbose)
		if s.showProgress {
			fmt.Printf("  Permissions: %d finding(s)\n\n", len(result.PermissionFindings))
		}
	}

	// Mtime check
	if s.CheckMtime {
		if s.showProgress {
			fmt.Printf("  Checking recently modified files (%d days)...\n", s.MtimeDays)
		}
		result.MtimeFindings = checkMtime(s.Path, s.MtimeDays, s.Verbose)
		if s.showProgress {
			fmt.Printf("  Modified: %d finding(s)\n\n", len(result.MtimeFindings))
		}
	}

	// YARA scan
	if s.UseYara {
		if s.showProgress {
			fmt.Println("  Running YARA scan...")
		}
		yaraFindings, available := yaraScanner(s.Path, s.YaraRulesPath, files, s.Verbose)
		if available {
			result.YaraFindings = yaraFindings
			if s.showProgress {
				fmt.Printf("  YARA: %d finding(s)\n", len(result.YaraFindings))
			}
		} else if s.showProgress {
			fmt.Println("  YARA: skipped (yara binary not found)")
		}
		if s.showProgress {
			fmt.Println()
		}
	}

	// Version detection + CVE check
	if s.CheckVersion {
		if s.showProgress {
			fmt.Println("  Checking known CVEs...")
		}
		version := s.cms.Version
		if version != "" {
			result.CVEFindings = checkCVEsForCMS(s.cms)
			if s.showProgress {
				critCVEs := 0
				for _, f := range result.CVEFindings {
					if f.Severity == CRITICAL {
						critCVEs++
					}
				}
				fmt.Printf("  CVEs: %d known vulnerabilities (%d critical)\n", len(result.CVEFindings), critCVEs)
			}
		} else if s.showProgress {
			fmt.Println("  CVEs: skipped (version not detected)")
		}
		if s.showProgress {
			fmt.Println()
		}
	}

	// Plugin / module scan
	if s.CheckPlugins {
		if s.showProgress {
			fmt.Println("  Detecting installed plugins/modules...")
		}
		result.Plugins = detectPlugins(s.Path, s.cms.Type, s.Verbose)
		if s.showProgress {
			fmt.Printf("  Plugins/modules: %d detected\n", len(result.Plugins))
		}
		result.PluginFindings = checkPluginVulns(result.Plugins, s.cms.Type)
		if s.showProgress {
			fmt.Printf("  Plugin vulnerabilities: %d\n\n", len(result.PluginFindings))
		}
	}

	// Core file integrity check
	if s.CheckIntegrity {
		if s.showProgress {
			fmt.Println("  Checking core file integrity...")
		}
		intResult, intFindings := checkIntegrity(s.Path, s.cms, s.Verbose)
		result.IntegrityResult = intResult
		result.IntegrityFindings = intFindings
		if s.showProgress {
			fmt.Printf("  Integrity: %d files checked, %d modified, %d unknown\n\n",
				intResult.Checked, len(intResult.Modified), len(intResult.Unknown))
		}
	}

	// Log analysis
	if s.AnalyzeLogs {
		if s.showProgress {
			fmt.Println("  Analyzing access logs...")
		}
		logFindings, suspiciousIPs := analyzeLogs(s.Path, s.LogPaths, s.cms.Type, s.Verbose)
		result.LogFindings = logFindings
		result.SuspiciousIPs = suspiciousIPs
		if s.showProgress {
			fmt.Printf("  Log findings: %d\n", len(logFindings))
			if len(suspiciousIPs) > 0 {
				fmt.Printf("  Suspicious IPs: %d\n", len(suspiciousIPs))
			}
			fmt.Println()
		}
	}

	// Timeline
	hasTemporalData := len(result.MtimeFindings) > 0 || len(result.LogFindings) > 0 ||
		len(allFindings) > 0 || len(result.DBFindings) > 0
	if hasTemporalData && (s.CheckMtime || s.AnalyzeLogs) {
		if s.showProgress {
			fmt.Println("  Building infection timeline...")
		}
		result.Findings = allFindings // need this set before timeline
		result.Timeline = buildTimeline(s.Path, result)
		if s.showProgress {
			fmt.Printf("  Timeline events: %d\n\n", len(result.Timeline))
		}
	}

	// Deduplicate & sort
	seen := make(map[string]bool)
	var deduped []Finding
	for _, f := range allFindings {
		key := f.FilePath + "|" + f.SignatureID
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}
	sortFindings(deduped)
	sortSuspicious(allSuspicious)

	end := time.Now()
	result.EndTime = end.Format(time.RFC3339)
	result.DurationSeconds = end.Sub(start).Seconds()
	result.TotalFilesScanned = totalFiles
	result.Findings = deduped
	result.SuspiciousFiles = allSuspicious
	result.Summary = buildSummary(result)

	return result
}

func (s *An4Scanner) printBanner() {
	fmt.Printf("\n%s╔══════════════════════════════════════════════════════╗\n", Bold)
	fmt.Println("║                  AN4SCAN v4.0 (Go)                  ║")
	fmt.Println("║          CMS Malware & Vulnerability Scanner        ║")
	fmt.Printf("╚══════════════════════════════════════════════════════╝%s\n\n", Reset)
}

func sortFindings(f []Finding) {
	for i := 0; i < len(f); i++ {
		for j := i + 1; j < len(f); j++ {
			if severityOrder[f[i].Severity] > severityOrder[f[j].Severity] {
				f[i], f[j] = f[j], f[i]
			}
		}
	}
}

func sortSuspicious(s []SuspiciousFile) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if severityOrder[s[i].Severity] > severityOrder[s[j].Severity] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func buildSummary(result *ScanResult) ScanSummary {
	bySeverity := make(map[string]int)
	byCategory := make(map[string]int)
	affected := make(map[string]bool)

	allFindings := append([]Finding{}, result.Findings...)
	allFindings = append(allFindings, result.DBFindings...)
	allFindings = append(allFindings, result.PermissionFindings...)
	allFindings = append(allFindings, result.MtimeFindings...)
	allFindings = append(allFindings, result.YaraFindings...)
	allFindings = append(allFindings, result.LogFindings...)
	allFindings = append(allFindings, result.CVEFindings...)
	allFindings = append(allFindings, result.IntegrityFindings...)

	for _, f := range allFindings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
		affected[f.FilePath] = true
	}
	for _, sf := range result.SuspiciousFiles {
		bySeverity[sf.Severity]++
	}
	for _, pf := range result.PluginFindings {
		bySeverity[pf.Severity]++
		byCategory["plugin_vuln"]++
		affected["plugin:"+pf.Plugin] = true
	}

	return ScanSummary{
		TotalFindings:        len(allFindings),
		TotalSuspiciousFiles: len(result.SuspiciousFiles),
		AffectedFiles:        len(affected),
		BySeverity:           bySeverity,
		ByCategory:           byCategory,
		Modules: map[string]int{
			"file_scan":    len(result.Findings),
			"db_scan":      len(result.DBFindings),
			"permissions":  len(result.PermissionFindings),
			"mtime":        len(result.MtimeFindings),
			"yara":         len(result.YaraFindings),
			"log_analysis": len(result.LogFindings),
			"cve":          len(result.CVEFindings),
			"integrity":    len(result.IntegrityFindings),
			"plugins":      len(result.PluginFindings),
		},
	}
}
