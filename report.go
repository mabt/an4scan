package main

import (
	"encoding/json"
	"fmt"
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
	cms := result.CMSInfo
	total := s.TotalFindings + s.TotalSuspiciousFiles

	// Header: one compact block
	fmt.Printf("\n  %s%s%s  ", Bold, result.ScanPath, Reset)
	if cms.Type != CMSUnknown {
		fmt.Printf("%s %s", cms.Name, cms.Version)
	}
	fmt.Printf("  %s(%d files, %.1fs)%s\n", Dim, result.TotalFilesScanned, result.DurationSeconds, Reset)
	if cms.EOL != "" {
		fmt.Printf("  %s⚠ %s%s\n", severityColors[CRITICAL], cms.EOL, Reset)
	}

	if total == 0 {
		fmt.Printf("  \033[92m✓ No threats detected%s\n\n", Reset)
		return
	}

	// Severity summary on one line
	fmt.Print("  ")
	for _, sev := range []string{CRITICAL, HIGH, MEDIUM, LOW, INFO} {
		if count := s.BySeverity[sev]; count > 0 {
			fmt.Printf("%s%d %s%s  ", severityColors[sev], count, sev, Reset)
		}
	}
	fmt.Println()

	// Suspicious files (grouped)
	if len(result.SuspiciousFiles) > 0 {
		fmt.Printf("\n%s  SUSPICIOUS FILES%s\n", Bold, Reset)
		printGroupedSuspicious(result.SuspiciousFiles)
	}

	// CVE findings (compact)
	if len(result.CVEFindings) > 0 {
		fmt.Printf("\n%s  CVEs%s\n", Bold, Reset)
		for _, f := range result.CVEFindings {
			color := severityColors[f.Severity]
			fmt.Printf("  %s%-8s%s %s — %s\n", color, f.Severity, Reset, f.SignatureID, f.Description)
		}
	}

	// Plugin vulnerabilities (compact)
	if len(result.PluginFindings) > 0 {
		fmt.Printf("\n%s  VULNERABLE PLUGINS%s\n", Bold, Reset)
		for _, pf := range result.PluginFindings {
			color := severityColors[pf.Severity]
			fmt.Printf("  %s%-8s%s %s v%s — %s %s(%s)%s\n", color, pf.Severity, Reset, pf.Plugin, pf.Version, pf.CVEID, Dim, pf.Fix, Reset)
		}
	}

	// Integrity (one line)
	if result.IntegrityResult.Checked > 0 {
		ir := result.IntegrityResult
		if len(ir.Modified) > 0 || len(ir.Unknown) > 0 {
			fmt.Printf("\n%s  INTEGRITY%s  %d checked, %s%d modified%s, %s%d unknown%s\n",
				Bold, Reset, ir.Checked,
				severityColors[HIGH], len(ir.Modified), Reset,
				severityColors[MEDIUM], len(ir.Unknown), Reset)
		}
	}

	// Suspicious IPs (compact)
	if len(result.SuspiciousIPs) > 0 {
		fmt.Printf("\n%s  SUSPICIOUS IPs%s\n", Bold, Reset)
		limit := 5
		if len(result.SuspiciousIPs) < limit {
			limit = len(result.SuspiciousIPs)
		}
		for _, ip := range result.SuspiciousIPs[:limit] {
			fmt.Printf("  %-18s %d hits  %s%s%s\n", ip.IP, ip.HitCount, Dim, strings.Join(ip.PatternsMatched, ", "), Reset)
		}
		if len(result.SuspiciousIPs) > limit {
			fmt.Printf("  %s... and %d more%s\n", Dim, len(result.SuspiciousIPs)-limit, Reset)
		}
	}

	// All findings combined
	allFindings := append([]Finding{}, result.Findings...)
	allFindings = append(allFindings, result.DBFindings...)
	allFindings = append(allFindings, result.PermissionFindings...)
	allFindings = append(allFindings, result.MtimeFindings...)
	allFindings = append(allFindings, result.IntegrityFindings...)
	allFindings = append(allFindings, result.YaraFindings...)
	allFindings = append(allFindings, result.LogFindings...)

	if len(allFindings) > 0 {
		fmt.Printf("\n%s  FINDINGS%s\n", Bold, Reset)
		printGroupedFindings(allFindings)
	}

	// Timeline (grouped by day)
	if len(result.Timeline) > 0 {
		fmt.Printf("\n%s  TIMELINE%s\n", Bold, Reset)
		printGroupedTimeline(result.Timeline)
	}

	// Risk assessment
	crit := s.BySeverity[CRITICAL]
	high := s.BySeverity[HIGH]
	if crit > 0 {
		fmt.Printf("\n  %s%s⚠ %d critical — immediate action needed%s\n\n", severityColors[CRITICAL], Bold, crit, Reset)
	} else if high > 0 {
		fmt.Printf("\n  %s⚠ %d high — review recommended%s\n\n", severityColors[HIGH], high, Reset)
	} else {
		fmt.Println()
	}
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
