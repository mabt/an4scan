package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiffResult represents the difference between two scans.
type DiffResult struct {
	PreviousScan string           `json:"previous_scan"`
	CurrentScan  string           `json:"current_scan"`
	NewFindings  []Finding        `json:"new_findings"`
	Resolved     []Finding        `json:"resolved"`
	NewPluginVulns []PluginFinding `json:"new_plugin_vulns"`
	ResolvedPluginVulns []PluginFinding `json:"resolved_plugin_vulns"`
	Summary      DiffSummary      `json:"summary"`
}

type DiffSummary struct {
	NewCount      int `json:"new_count"`
	ResolvedCount int `json:"resolved_count"`
	UnchangedCount int `json:"unchanged_count"`
}

// diffScans compares current scan result with a previous JSON report.
func diffScans(current *ScanResult, previousPath string) (*DiffResult, error) {
	data, err := os.ReadFile(previousPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read previous scan: %w", err)
	}

	var previous ScanResult
	if err := json.Unmarshal(data, &previous); err != nil {
		return nil, fmt.Errorf("invalid previous scan JSON: %w", err)
	}

	diff := &DiffResult{
		PreviousScan: previous.StartTime,
		CurrentScan:  current.StartTime,
	}

	// Build fingerprint sets for all findings
	prevSet := buildFindingSet(&previous)
	currSet := buildFindingSet(current)

	// New findings (in current but not in previous)
	for key, f := range currSet {
		if _, exists := prevSet[key]; !exists {
			diff.NewFindings = append(diff.NewFindings, f)
		}
	}

	// Resolved findings (in previous but not in current)
	for key, f := range prevSet {
		if _, exists := currSet[key]; !exists {
			diff.Resolved = append(diff.Resolved, f)
		}
	}

	// Plugin vuln diff
	prevPlugins := buildPluginFindingSet(previous.PluginFindings)
	currPlugins := buildPluginFindingSet(current.PluginFindings)

	for key, pf := range currPlugins {
		if _, exists := prevPlugins[key]; !exists {
			diff.NewPluginVulns = append(diff.NewPluginVulns, pf)
		}
	}
	for key, pf := range prevPlugins {
		if _, exists := currPlugins[key]; !exists {
			diff.ResolvedPluginVulns = append(diff.ResolvedPluginVulns, pf)
		}
	}

	unchanged := len(currSet) - len(diff.NewFindings)
	if unchanged < 0 {
		unchanged = 0
	}
	diff.Summary = DiffSummary{
		NewCount:      len(diff.NewFindings) + len(diff.NewPluginVulns),
		ResolvedCount: len(diff.Resolved) + len(diff.ResolvedPluginVulns),
		UnchangedCount: unchanged,
	}

	return diff, nil
}

func buildFindingSet(result *ScanResult) map[string]Finding {
	set := make(map[string]Finding)
	allFindings := append([]Finding{}, result.Findings...)
	allFindings = append(allFindings, result.DBFindings...)
	allFindings = append(allFindings, result.PermissionFindings...)
	allFindings = append(allFindings, result.YaraFindings...)
	allFindings = append(allFindings, result.CVEFindings...)
	allFindings = append(allFindings, result.IntegrityFindings...)

	for _, f := range allFindings {
		key := f.FilePath + "|" + f.SignatureID
		set[key] = f
	}
	return set
}

func buildPluginFindingSet(findings []PluginFinding) map[string]PluginFinding {
	set := make(map[string]PluginFinding)
	for _, f := range findings {
		key := f.Plugin + "|" + f.CVEID
		set[key] = f
	}
	return set
}

// saveScanResult saves the scan result as JSON for future diffing.
func saveScanResult(result *ScanResult, root string) (string, error) {
	dir := filepath.Join(root, ".an4scan")
	os.MkdirAll(dir, 0755)

	// Use timestamp-based filename
	ts := strings.ReplaceAll(result.StartTime[:19], ":", "-")
	filename := fmt.Sprintf("scan-%s.json", ts)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}

	// Also save as "latest.json" symlink/copy
	latestPath := filepath.Join(dir, "latest.json")
	os.Remove(latestPath)
	os.WriteFile(latestPath, data, 0644)

	return path, nil
}

// findPreviousScan finds the most recent previous scan JSON.
func findPreviousScan(root string) string {
	latestPath := filepath.Join(root, ".an4scan", "latest.json")
	if _, err := os.Stat(latestPath); err == nil {
		return latestPath
	}
	return ""
}

// printDiffReport prints the diff to stdout.
func printDiffReport(diff *DiffResult) {
	fmt.Printf("\n%s  SCAN DIFF%s\n", Bold, Reset)
	fmt.Printf("  %s\n", strings.Repeat("─", 50))
	fmt.Printf("  Previous: %s\n", diff.PreviousScan)
	fmt.Printf("  Current:  %s\n", diff.CurrentScan)
	fmt.Println()

	newTotal := diff.Summary.NewCount
	resolvedTotal := diff.Summary.ResolvedCount

	if newTotal == 0 && resolvedTotal == 0 {
		fmt.Printf("  \033[92m✓ No changes since last scan%s\n\n", Reset)
		return
	}

	if newTotal > 0 {
		fmt.Printf("  %s+ %d NEW finding(s)%s\n", severityColors[CRITICAL], newTotal, Reset)
	}
	if resolvedTotal > 0 {
		fmt.Printf("  \033[92m- %d RESOLVED finding(s)%s\n", resolvedTotal, Reset)
	}
	fmt.Printf("  = %d unchanged\n", diff.Summary.UnchangedCount)
	fmt.Println()

	if len(diff.NewFindings) > 0 {
		fmt.Printf("  %s%sNEW FINDINGS:%s\n", Bold, severityColors[CRITICAL], Reset)
		for _, f := range diff.NewFindings {
			color := severityColors[f.Severity]
			fmt.Printf("    %s[%s]%s %s — %s\n", color, f.SignatureID, Reset, f.FilePath, f.Description)
		}
		fmt.Println()
	}

	if len(diff.NewPluginVulns) > 0 {
		fmt.Printf("  %s%sNEW PLUGIN VULNERABILITIES:%s\n", Bold, severityColors[CRITICAL], Reset)
		for _, pf := range diff.NewPluginVulns {
			color := severityColors[pf.Severity]
			fmt.Printf("    %s[%s]%s %s v%s — %s\n", color, pf.CVEID, Reset, pf.Plugin, pf.Version, pf.Description)
		}
		fmt.Println()
	}

	if len(diff.Resolved) > 0 {
		fmt.Printf("  \033[92m%sRESOLVED:%s\n", Bold, Reset)
		for _, f := range diff.Resolved {
			fmt.Printf("    \033[92m[%s]%s %s — %s\n", f.SignatureID, Reset, f.FilePath, f.Description)
		}
		fmt.Println()
	}

	if len(diff.ResolvedPluginVulns) > 0 {
		fmt.Printf("  \033[92m%sRESOLVED PLUGIN VULNS:%s\n", Bold, Reset)
		for _, pf := range diff.ResolvedPluginVulns {
			fmt.Printf("    \033[92m[%s]%s %s v%s\n", pf.CVEID, Reset, pf.Plugin, pf.Version)
		}
		fmt.Println()
	}
}
