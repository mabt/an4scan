package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func printReport(result *ScanResult, jsonOutput, quiet bool) {
	if jsonOutput {
		printJSONReport(result)
		return
	}
	if quiet {
		printQuietSummary(result)
		return
	}
	printTextReport(result)
}

func printQuietSummary(result *ScanResult) {
	s := result.Summary
	total := s.TotalFindings + s.TotalSuspiciousFiles
	crit := s.BySeverity[CRITICAL]
	high := s.BySeverity[HIGH]
	med := s.BySeverity[MEDIUM]

	if total == 0 {
		fmt.Printf("\033[92m✓ No threats detected (%d files scanned)%s\n", result.TotalFilesScanned, Reset)
	} else if crit > 0 {
		fmt.Printf("%s⚠ %d finding(s): %d critical, %d high, %d medium (%d files)%s\n",
			severityColors[CRITICAL], total, crit, high, med, result.TotalFilesScanned, Reset)
	} else if high > 0 {
		fmt.Printf("%s⚠ %d finding(s): %d high, %d medium (%d files)%s\n",
			severityColors[HIGH], total, high, med, result.TotalFilesScanned, Reset)
	} else {
		fmt.Printf("%s△ %d finding(s): %d medium or lower (%d files)%s\n",
			severityColors[MEDIUM], total, med, result.TotalFilesScanned, Reset)
	}
}

func printJSONReport(result *ScanResult) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))
}

func printTextReport(result *ScanResult) {
	s := result.Summary

	fmt.Printf("%s%s\n", Bold, strings.Repeat("═", 60))
	fmt.Println("  SCAN REPORT")
	fmt.Printf("%s%s\n", strings.Repeat("═", 60), Reset)
	fmt.Printf("  Path:     %s\n", result.ScanPath)
	cms := result.CMSInfo
	if cms.Type != CMSUnknown {
		fmt.Printf("  CMS:      %s %s", cms.Name, cms.Version)
		if cms.Edition != "" {
			fmt.Printf(" (%s)", cms.Edition)
		}
		fmt.Println()
		if cms.EOL != "" {
			fmt.Printf("  %s⚠ %s%s\n", severityColors[CRITICAL], cms.EOL, Reset)
		}
	}
	fmt.Printf("  Duration: %.2fs\n", result.DurationSeconds)
	fmt.Printf("  Files:    %d scanned\n\n", result.TotalFilesScanned)

	// Module breakdown
	if hasModuleFindings(s.Modules) {
		fmt.Printf("%s  MODULES%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		for mod, count := range s.Modules {
			if count > 0 {
				fmt.Printf("    %-20s: %d finding(s)\n", mod, count)
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("%s  SUMMARY%s\n", Bold, Reset)
	fmt.Printf("  %s\n", strings.Repeat("─", 40))
	total := s.TotalFindings + s.TotalSuspiciousFiles
	if total == 0 {
		fmt.Printf("  \033[92m✓ No threats detected%s\n\n", Reset)
		return
	}

	fmt.Printf("  Total findings:     %d\n", total)
	fmt.Printf("  Affected files:     %d\n\n", s.AffectedFiles)

	for _, sev := range []string{CRITICAL, HIGH, MEDIUM, LOW, INFO} {
		count := s.BySeverity[sev]
		if count > 0 {
			fmt.Printf("  %s  %-10s: %d%s\n", severityColors[sev], sev, count, Reset)
		}
	}
	fmt.Println()

	if len(s.ByCategory) > 0 {
		fmt.Println("  By category:")
		type catCount struct {
			Cat   string
			Count int
		}
		var cats []catCount
		for cat, count := range s.ByCategory {
			cats = append(cats, catCount{cat, count})
		}
		sort.Slice(cats, func(i, j int) bool { return cats[i].Count > cats[j].Count })
		for _, cc := range cats {
			fmt.Printf("    %-25s: %d\n", cc.Cat, cc.Count)
		}
		fmt.Println()
	}

	// Suspicious files (grouped by reason)
	if len(result.SuspiciousFiles) > 0 {
		fmt.Printf("%s  SUSPICIOUS FILES%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		printGroupedSuspicious(result.SuspiciousFiles)
		fmt.Println()
	}

	// CMS version info (detailed, when --version is used)
	if len(result.CVEFindings) > 0 && cms.Version != "" {
		fmt.Printf("%s  %s VERSION DETAILS%s\n", Bold, strings.ToUpper(string(cms.Type)), Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		fmt.Printf("    CMS:      %s\n", cms.Name)
		fmt.Printf("    Version:  %s\n", cms.Version)
		if cms.Edition != "" {
			fmt.Printf("    Edition:  %s\n", cms.Edition)
		}
		fmt.Printf("    Source:   %s\n", cms.Source)
		if cms.EOL != "" {
			fmt.Printf("    %s⚠ %s%s\n", severityColors[CRITICAL], cms.EOL, Reset)
		}
		fmt.Println()
	}

	// CVE findings
	if len(result.CVEFindings) > 0 {
		fmt.Printf("%s  KNOWN VULNERABILITIES (CVEs)%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		for _, f := range result.CVEFindings {
			color := severityColors[f.Severity]
			fmt.Printf("  %s[%-8s] %s%s\n", color, f.Severity, f.SignatureID, Reset)
			fmt.Printf("           %s\n", f.Description)
			fmt.Printf("           %s%s%s\n", Dim, f.LineContent, Reset)
		}
		fmt.Println()
	}

	// Plugin vulnerabilities
	if len(result.PluginFindings) > 0 {
		fmt.Printf("%s  VULNERABLE PLUGINS / MODULES%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		for _, pf := range result.PluginFindings {
			color := severityColors[pf.Severity]
			fmt.Printf("  %s[%-8s] %s%s v%s — %s\n", color, pf.Severity, Reset, pf.Plugin, pf.Version, pf.CVEID)
			fmt.Printf("           %s\n", pf.Description)
			fmt.Printf("           %sFix: %s%s\n", Dim, pf.Fix, Reset)
		}
		fmt.Println()
	}

	// Installed plugins summary
	if len(result.Plugins) > 0 {
		fmt.Printf("%s  INSTALLED PLUGINS / MODULES (%d)%s\n", Bold, len(result.Plugins), Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		for _, p := range result.Plugins {
			ver := p.Version
			if ver == "" {
				ver = "?"
			}
			fmt.Printf("    %s%-35s%s v%-12s %s\n", Dim, p.Name, Reset, ver, p.Type)
		}
		fmt.Println()
	}

	// Integrity results
	if result.IntegrityResult.Checked > 0 {
		ir := result.IntegrityResult
		fmt.Printf("%s  CORE FILE INTEGRITY%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		fmt.Printf("    Checked: %d files\n", ir.Checked)
		if len(ir.Modified) > 0 {
			fmt.Printf("    %sModified: %d files%s\n", severityColors[HIGH], len(ir.Modified), Reset)
		}
		if len(ir.Unknown) > 0 {
			fmt.Printf("    %sUnknown:  %d files%s\n", severityColors[MEDIUM], len(ir.Unknown), Reset)
		}
		if len(ir.Missing) > 0 {
			fmt.Printf("    Missing:  %d files\n", len(ir.Missing))
		}
		if len(ir.Modified) == 0 && len(ir.Unknown) == 0 {
			fmt.Printf("    \033[92m✓ All core files match expected checksums%s\n", Reset)
		}
		fmt.Println()
	}

	// Suspicious IPs
	if len(result.SuspiciousIPs) > 0 {
		fmt.Printf("%s  TOP SUSPICIOUS IPs (from access logs)%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		limit := 10
		if len(result.SuspiciousIPs) < limit {
			limit = len(result.SuspiciousIPs)
		}
		for _, ip := range result.SuspiciousIPs[:limit] {
			fmt.Printf("    %s%-18s%s %d hits | Patterns: %s\n",
				severityColors[HIGH], ip.IP, Reset, ip.HitCount,
				strings.Join(ip.PatternsMatched, ", "))
		}
		fmt.Println()
	}

	// Detailed findings by group
	groups := []struct {
		Title    string
		Findings []Finding
	}{
		{"DETAILED FINDINGS (File Scan)", result.Findings},
		{"DATABASE FINDINGS", result.DBFindings},
		{"PERMISSION FINDINGS", result.PermissionFindings},
		{"RECENTLY MODIFIED FILES", result.MtimeFindings},
		{"INTEGRITY FINDINGS", result.IntegrityFindings},
		{"YARA FINDINGS", result.YaraFindings},
		{"ACCESS LOG FINDINGS", result.LogFindings},
	}

	for _, g := range groups {
		if len(g.Findings) == 0 {
			continue
		}
		fmt.Printf("%s  %s%s\n", Bold, g.Title, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		printGroupedFindings(g.Findings)
		fmt.Println()
	}

	// Timeline (grouped by day)
	if len(result.Timeline) > 0 {
		fmt.Printf("%s  INFECTION TIMELINE%s\n", Bold, Reset)
		fmt.Printf("  %s\n", strings.Repeat("─", 40))
		printGroupedTimeline(result.Timeline)
		fmt.Println()
	}

	fmt.Printf("%s%s%s\n", Bold, strings.Repeat("═", 60), Reset)

	// Risk assessment
	crit := s.BySeverity[CRITICAL]
	high := s.BySeverity[HIGH]
	if crit > 0 {
		fmt.Printf("\n  %s%s⚠  HIGH RISK - %d critical finding(s) detected!\n", severityColors[CRITICAL], Bold, crit)
		fmt.Printf("  Immediate investigation recommended.%s\n", Reset)
	} else if high > 0 {
		fmt.Printf("\n  %s⚠  ELEVATED RISK - %d high severity finding(s) detected.\n", severityColors[HIGH], high)
		fmt.Printf("  Review recommended.%s\n", Reset)
	} else if total > 0 {
		fmt.Printf("\n  %s△  LOW-MEDIUM RISK - Review findings for false positives.%s\n", severityColors[MEDIUM], Reset)
	}
	fmt.Println()
}

func hasModuleFindings(modules map[string]int) bool {
	for _, v := range modules {
		if v > 0 {
			return true
		}
	}
	return false
}

// printGroupedTimeline groups timeline events by day, collapsing repetitive entries.
func printGroupedTimeline(events []TimelineEvent) {
	typeIcons := map[string]string{
		"reference": "·", "file_modified": "~", "malware_file": "!",
		"exploit_attempt": "→", "suspicious_admin": "⊕",
	}

	// Group events by day + type + description
	type dayGroup struct {
		Day     string
		Type    string
		Icon    string
		Severity string
		Desc    string
		Files   []string
		Count   int
		FirstTS string
	}

	var groups []dayGroup
	var current *dayGroup

	for _, e := range events {
		day := ""
		if len(e.Timestamp) >= 10 {
			day = e.Timestamp[:10]
		}

		// Same day + same type + same description → merge
		if current != nil && current.Day == day && current.Type == e.Type && current.Desc == e.Description {
			current.Count++
			if len(current.Files) < 3 && e.File != "" {
				current.Files = append(current.Files, e.File)
			}
			continue
		}

		// New group
		icon := typeIcons[e.Type]
		if icon == "" {
			icon = "?"
		}
		groups = append(groups, dayGroup{
			Day: day, Type: e.Type, Icon: icon, Severity: e.Severity,
			Desc: e.Description, Count: 1, FirstTS: e.Timestamp,
		})
		current = &groups[len(groups)-1]
		if e.File != "" {
			current.Files = append(current.Files, e.File)
		}
	}

	for _, g := range groups {
		color := severityColors[g.Severity]
		ts := g.Day
		if len(g.FirstTS) >= 16 {
			ts = g.FirstTS[:16]
		}

		if g.Count == 1 {
			fmt.Printf("  %s%s%s  %s%s%s %s\n", Dim, ts, Reset, color, g.Icon, Reset, g.Desc)
			if len(g.Files) > 0 {
				fmt.Printf("  %s%s%s%s\n", Dim, strings.Repeat(" ", 19), g.Files[0], Reset)
			}
		} else {
			desc := g.Desc
			if len(desc) > 60 {
				desc = desc[:60]
			}
			fmt.Printf("  %s%s%s  %s%s%s %s (%d)\n", Dim, g.Day, Reset, color, g.Icon, Reset, desc, g.Count)
			for _, f := range g.Files {
				fmt.Printf("  %s%s%s%s\n", Dim, strings.Repeat(" ", 19), f, Reset)
			}
			if g.Count > len(g.Files) {
				fmt.Printf("  %s%s... and %d more%s\n", Dim, strings.Repeat(" ", 19), g.Count-len(g.Files), Reset)
			}
		}
	}
}

// printGroupedFindings groups findings by signature ID + description and shows count + sample files.
func printGroupedFindings(findings []Finding) {
	type group struct {
		SignatureID string
		Severity    string
		Description string
		Sample      Finding
		Files       []string
		Count       int
	}

	order := []string{}
	groups := map[string]*group{}

	for _, f := range findings {
		key := f.SignatureID + "|" + f.Description
		if g, ok := groups[key]; ok {
			g.Count++
			if len(g.Files) < 3 {
				g.Files = append(g.Files, fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber))
			}
		} else {
			order = append(order, key)
			groups[key] = &group{
				SignatureID: f.SignatureID,
				Severity:    f.Severity,
				Description: f.Description,
				Sample:      f,
				Files:       []string{fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)},
				Count:       1,
			}
		}
	}

	currentSev := ""
	for _, key := range order {
		g := groups[key]
		if g.Severity != currentSev {
			currentSev = g.Severity
			color := severityColors[g.Severity]
			fmt.Printf("\n  %s%s── %s ──%s\n", color, Bold, g.Severity, Reset)
		}
		color := severityColors[g.Severity]

		if g.Count == 1 {
			fmt.Printf("\n  %s[%s]%s %s\n", color, g.SignatureID, Reset, g.Description)
			fmt.Printf("  %sFile: %s%s\n", Dim, g.Files[0], Reset)
			if g.Sample.LineContent != "" {
				content := g.Sample.LineContent
				if len(content) > 120 {
					content = content[:120]
				}
				fmt.Printf("  %sCode: %s%s\n", Dim, content, Reset)
			}
		} else {
			fmt.Printf("\n  %s[%s]%s %s %s(%d files)%s\n", color, g.SignatureID, Reset, g.Description, Dim, g.Count, Reset)
			for _, file := range g.Files {
				fmt.Printf("  %s  %s%s\n", Dim, file, Reset)
			}
			if g.Count > len(g.Files) {
				fmt.Printf("  %s  ... and %d more%s\n", Dim, g.Count-len(g.Files), Reset)
			}
			if g.Sample.LineContent != "" {
				content := g.Sample.LineContent
				if len(content) > 120 {
					content = content[:120]
				}
				fmt.Printf("  %sCode: %s%s\n", Dim, content, Reset)
			}
		}
	}
}

// printGroupedSuspicious groups suspicious files by reason.
func printGroupedSuspicious(files []SuspiciousFile) {
	type group struct {
		Severity string
		Reason   string
		Files    []string
		Count    int
	}

	order := []string{}
	groups := map[string]*group{}

	for _, sf := range files {
		key := sf.Severity + "|" + sf.Reason
		if g, ok := groups[key]; ok {
			g.Count++
			if len(g.Files) < 3 {
				g.Files = append(g.Files, sf.File)
			}
		} else {
			order = append(order, key)
			groups[key] = &group{
				Severity: sf.Severity, Reason: sf.Reason,
				Files: []string{sf.File}, Count: 1,
			}
		}
	}

	for _, key := range order {
		g := groups[key]
		color := severityColors[g.Severity]
		if g.Count == 1 {
			fmt.Printf("  %s[%-8s]%s %s\n", color, g.Severity, Reset, g.Files[0])
			fmt.Printf("           %s%s%s\n", Dim, g.Reason, Reset)
		} else {
			fmt.Printf("  %s[%-8s]%s %s %s(%d files)%s\n", color, g.Severity, Reset, g.Reason, Dim, g.Count, Reset)
			for _, f := range g.Files {
				fmt.Printf("           %s%s%s\n", Dim, f, Reset)
			}
			if g.Count > len(g.Files) {
				fmt.Printf("           %s... and %d more%s\n", Dim, g.Count-len(g.Files), Reset)
			}
		}
	}
}
