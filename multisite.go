package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CMSSite represents a detected CMS installation.
type CMSSite struct {
	Path string
	CMS  CMSInfo
}

// MultiSiteResult holds results from scanning multiple sites.
type MultiSiteResult struct {
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Duration  float64       `json:"duration_seconds"`
	Sites     []SiteResult  `json:"sites"`
	Summary   MultiSummary  `json:"summary"`
}

type SiteResult struct {
	Path       string      `json:"path"`
	CMS        CMSInfo     `json:"cms"`
	ScanResult *ScanResult `json:"scan_result"`
}

type MultiSummary struct {
	TotalSites    int            `json:"total_sites"`
	ByCMS         map[string]int `json:"by_cms"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	CriticalSites []string      `json:"critical_sites"`
}

// discoverSites finds all CMS installations under root.
// Max depth of 3 to avoid scanning too deep.
func discoverSites(root string, maxDepth int) []CMSSite {
	var sites []CMSSite

	// First check if root itself is a CMS
	cms := detectCMS(root)
	if cms.Type != CMSUnknown {
		return []CMSSite{{Path: root, CMS: cms}}
	}

	// Walk subdirectories looking for CMS markers
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}

		// Skip hidden dirs and known non-CMS dirs
		name := d.Name()
		if strings.HasPrefix(name, ".") || SkipDirs[name] ||
			name == "vendor" || name == "lib" || name == "var" ||
			name == "generated" || name == "pub" || name == "wp-includes" ||
			name == "wp-admin" || name == "wp-content" || name == "classes" ||
			name == "controllers" || name == "cache" || name == "tmp" {
			return filepath.SkipDir
		}

		// Depth check
		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
		if depth > maxDepth {
			return filepath.SkipDir
		}

		// Try detecting CMS at this path
		cms := detectCMS(path)
		if cms.Type != CMSUnknown {
			sites = append(sites, CMSSite{Path: path, CMS: cms})
			return filepath.SkipDir // Don't scan inside a detected CMS
		}

		return nil
	})

	return sites
}

// runMultiSiteScan scans all detected sites.
func runMultiSiteScan(sites []CMSSite, scanner *An4Scanner) *MultiSiteResult {
	start := time.Now()
	result := &MultiSiteResult{
		StartTime: start.Format(time.RFC3339),
	}

	showProgress := !scanner.JSONOutput && !scanner.Quiet

	if showProgress {
		fmt.Printf("\n%s╔══════════════════════════════════════════════════════╗%s\n", Bold, Reset)
		fmt.Printf("%s║                  AN4SCAN v4.0 (Go)                  ║%s\n", Bold, Reset)
		fmt.Printf("%s║          CMS Malware & Vulnerability Scanner        ║%s\n", Bold, Reset)
		fmt.Printf("%s╚══════════════════════════════════════════════════════╝%s\n\n", Bold, Reset)
		fmt.Printf("  Detected %d site(s):\n", len(sites))
		for i, s := range sites {
			ver := s.CMS.Version
			if ver == "" {
				ver = "?"
			}
			fmt.Printf("    %d. %s — %s %s\n", i+1, s.Path, s.CMS.Name, ver)
		}
		fmt.Printf("\n%s%s%s\n\n", Bold, strings.Repeat("═", 60), Reset)
	}

	for i, site := range sites {
		if showProgress {
			fmt.Printf("%s  [%d/%d] Scanning %s (%s %s)%s\n",
				Bold, i+1, len(sites), site.Path, site.CMS.Name, site.CMS.Version, Reset)
			fmt.Printf("  %s\n\n", strings.Repeat("─", 50))
		}

		// Create a scanner for this site
		s := NewScanner(site.Path)
		s.Workers = scanner.Workers
		s.MinSeverity = scanner.MinSeverity
		s.Whitelist = scanner.Whitelist
		s.JSONOutput = scanner.JSONOutput
		s.Verbose = scanner.Verbose
		s.Quiet = scanner.Quiet
		s.ScanDB = scanner.ScanDB
		s.CheckMtime = scanner.CheckMtime
		s.MtimeDays = scanner.MtimeDays
		s.CheckPermissions = scanner.CheckPermissions
		s.UseYara = scanner.UseYara
		s.YaraRulesPath = scanner.YaraRulesPath
		s.CheckVersion = scanner.CheckVersion
		s.AnalyzeLogs = scanner.AnalyzeLogs
		s.CheckPlugins = scanner.CheckPlugins
		s.CheckIntegrity = scanner.CheckIntegrity
		s.LogPaths = scanner.LogPaths
		s.Init()

		scanResult := s.Scan()
		result.Sites = append(result.Sites, SiteResult{
			Path: site.Path, CMS: site.CMS, ScanResult: scanResult,
		})

		// Per-site quick summary
		if showProgress {
			sr := scanResult.Summary
			total := sr.TotalFindings + sr.TotalSuspiciousFiles
			crit := sr.BySeverity[CRITICAL]
			high := sr.BySeverity[HIGH]
			if total == 0 {
				fmt.Printf("  \033[92m✓ Clean%s\n\n", Reset)
			} else if crit > 0 {
				fmt.Printf("  %s⚠ %d finding(s): %d critical, %d high%s\n\n",
					severityColors[CRITICAL], total, crit, high, Reset)
			} else if high > 0 {
				fmt.Printf("  %s⚠ %d finding(s): %d high%s\n\n",
					severityColors[HIGH], total, high, Reset)
			} else {
				fmt.Printf("  %s△ %d finding(s)%s\n\n", severityColors[MEDIUM], total, Reset)
			}
		}
	}

	end := time.Now()
	result.EndTime = end.Format(time.RFC3339)
	result.Duration = end.Sub(start).Seconds()
	result.Summary = buildMultiSummary(result)

	return result
}

func buildMultiSummary(result *MultiSiteResult) MultiSummary {
	summary := MultiSummary{
		TotalSites: len(result.Sites),
		ByCMS:      make(map[string]int),
		BySeverity: make(map[string]int),
	}

	for _, site := range result.Sites {
		summary.ByCMS[string(site.CMS.Type)]++

		sr := site.ScanResult.Summary
		total := sr.TotalFindings + sr.TotalSuspiciousFiles
		summary.TotalFindings += total

		for sev, count := range sr.BySeverity {
			summary.BySeverity[sev] += count
		}
		// Add plugin findings
		for _, pf := range site.ScanResult.PluginFindings {
			summary.BySeverity[pf.Severity]++
			summary.TotalFindings++
		}

		if sr.BySeverity[CRITICAL] > 0 {
			summary.CriticalSites = append(summary.CriticalSites, site.Path)
		}
	}

	return summary
}

func printMultiSiteReport(result *MultiSiteResult, jsonOutput bool) {
	if jsonOutput {
		printMultiSiteJSON(result)
		return
	}

	fmt.Printf("\n%s%s%s\n", Bold, strings.Repeat("═", 60), Reset)
	fmt.Printf("%s  MULTI-SITE SUMMARY%s\n", Bold, Reset)
	fmt.Printf("%s%s\n", strings.Repeat("═", 60), Reset)
	fmt.Printf("  Sites scanned: %d\n", result.Summary.TotalSites)
	fmt.Printf("  Duration:      %.2fs\n", result.Duration)
	fmt.Println()

	// By CMS
	fmt.Printf("  By CMS:\n")
	for cms, count := range result.Summary.ByCMS {
		fmt.Printf("    %-15s: %d\n", cms, count)
	}
	fmt.Println()

	// By severity
	total := result.Summary.TotalFindings
	if total == 0 {
		fmt.Printf("  \033[92m✓ All sites clean%s\n\n", Reset)
		return
	}

	fmt.Printf("  Total findings: %d\n", total)
	for _, sev := range []string{CRITICAL, HIGH, MEDIUM, LOW, INFO} {
		if count := result.Summary.BySeverity[sev]; count > 0 {
			fmt.Printf("  %s  %-10s: %d%s\n", severityColors[sev], sev, count, Reset)
		}
	}
	fmt.Println()

	// Per-site table
	fmt.Printf("%s  PER-SITE RESULTS%s\n", Bold, Reset)
	fmt.Printf("  %s\n", strings.Repeat("─", 55))

	for _, site := range result.Sites {
		sr := site.ScanResult.Summary
		siteTotal := sr.TotalFindings + sr.TotalSuspiciousFiles + len(site.ScanResult.PluginFindings)
		crit := sr.BySeverity[CRITICAL]
		high := sr.BySeverity[HIGH]

		status := "\033[92m✓ Clean" + Reset
		if crit > 0 {
			status = fmt.Sprintf("%s⚠ %d critical, %d high%s", severityColors[CRITICAL], crit, high, Reset)
		} else if high > 0 {
			status = fmt.Sprintf("%s⚠ %d high%s", severityColors[HIGH], high, Reset)
		} else if siteTotal > 0 {
			status = fmt.Sprintf("%s△ %d finding(s)%s", severityColors[MEDIUM], siteTotal, Reset)
		}

		ver := site.CMS.Version
		if ver == "" {
			ver = "?"
		}
		cmsLabel := fmt.Sprintf("%s %s", site.CMS.Name, ver)

		fmt.Printf("  %-30s %-25s %s\n", site.Path, cmsLabel, status)
	}
	fmt.Println()

	// Critical sites
	if len(result.Summary.CriticalSites) > 0 {
		fmt.Printf("  %s%s⚠ SITES WITH CRITICAL FINDINGS:%s\n", Bold, severityColors[CRITICAL], Reset)
		for _, s := range result.Summary.CriticalSites {
			fmt.Printf("    %s%s%s\n", severityColors[CRITICAL], s, Reset)
		}
		fmt.Println()
	}
}

func printMultiSiteJSON(result *MultiSiteResult) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
}

func writeMultiSiteHTML(result *MultiSiteResult, outputPath string) error {
	// For multi-site, write individual HTML reports per site
	// plus a summary index
	for _, site := range result.Sites {
		if site.ScanResult != nil {
			siteName := filepath.Base(site.Path)
			siteHTML := strings.TrimSuffix(outputPath, ".html") + "-" + siteName + ".html"
			writeHTMLReport(site.ScanResult, siteHTML)
		}
	}
	return nil
}
