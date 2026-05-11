package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var yaraRulesDir = filepath.Join(os.Getenv("HOME"), ".an4scan", "rules")

// ─── YARA Rule Updater ──────────────────────────────────────────────────────

func yaraUpdate(verbose bool) {
	os.MkdirAll(yaraRulesDir, 0755)

	meta := make(map[string]map[string]interface{})
	metaPath := filepath.Join(yaraRulesDir, "meta.json")
	if data, err := os.ReadFile(metaPath); err == nil {
		json.Unmarshal(data, &meta)
	}

	for _, rs := range YaraRulesets {
		fmt.Printf("  [%s] Downloading %s...\n", rs.Name, rs.Description)
		count, err := downloadRuleset(rs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%s] Error: %v\n", rs.Name, err)
			continue
		}
		fmt.Printf("  [%s] %d rule file(s) installed\n", rs.Name, count)
		meta[rs.Name] = map[string]interface{}{
			"updated": time.Now().Format(time.RFC3339),
			"count":   count,
		}
	}

	data, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(metaPath, data, 0644)
}

func downloadRuleset(rs YaraRulesetDef) (int, error) {
	dest := filepath.Join(yaraRulesDir, rs.Name)
	os.RemoveAll(dest)
	os.MkdirAll(dest, 0755)

	client := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequest("GET", rs.URL, nil)
	req.Header.Set("User-Agent", "an4scan/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	count := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Strip leading path components
		parts := strings.Split(hdr.Name, "/")
		if len(parts) <= rs.Strip {
			continue
		}
		rel := filepath.Join(parts[rs.Strip:]...)

		// Check if matches any glob
		matched := false
		for _, g := range rs.Globs {
			if matchGlob(rel, g) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		outPath := filepath.Join(dest, rel)
		os.MkdirAll(filepath.Dir(outPath), 0755)
		f, err := os.Create(outPath)
		if err != nil {
			continue
		}
		io.Copy(f, tr)
		f.Close()
		count++
	}

	return count, nil
}

// matchGlob handles patterns like "yara/**/*.yar"
func matchGlob(path, pattern string) bool {
	// Simple case: no **
	if !strings.Contains(pattern, "**") {
		m, _ := filepath.Match(pattern, path)
		return m
	}

	// Split on **
	parts := strings.SplitN(pattern, "**", 2)
	prefix := strings.TrimRight(parts[0], "/")
	suffix := strings.TrimLeft(parts[1], "/")

	// Check prefix
	if prefix != "" && !strings.HasPrefix(path, prefix+"/") && path != prefix {
		return false
	}

	// Check suffix (extension match)
	if suffix != "" {
		// suffix might be "*.yar" or "*.yara"
		m, _ := filepath.Match(suffix, filepath.Base(path))
		return m
	}
	return true
}

func getAllRuleFiles() []string {
	if _, err := os.Stat(yaraRulesDir); err != nil {
		return nil
	}
	var files []string
	filepath.WalkDir(yaraRulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yar" || ext == ".yara" {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func yaraShowStatus() {
	metaPath := filepath.Join(yaraRulesDir, "meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		fmt.Println("  No rulesets downloaded yet. Run: an4scan --update")
		return
	}
	var meta map[string]map[string]interface{}
	json.Unmarshal(data, &meta)

	fmt.Printf("  Rules directory: %s\n\n", yaraRulesDir)
	for name, info := range meta {
		updated := ""
		if u, ok := info["updated"].(string); ok && len(u) >= 19 {
			updated = u[:19]
		}
		count := 0
		if c, ok := info["count"].(float64); ok {
			count = int(c)
		}
		fmt.Printf("  %-20s  %4d files  (updated: %s)\n", name, count, updated)
	}
	total := len(getAllRuleFiles())
	fmt.Printf("\n  Total: %d rule file(s)\n", total)
}

// ─── YARA Scanner ───────────────────────────────────────────────────────────

func yaraScanner(root, extraRulesPath string, files []string, verbose bool) ([]Finding, bool) {
	// Check if yara binary is available
	yaraBin, err := exec.LookPath("yara")
	if err != nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "  [YARA] yara binary not found in PATH")
		}
		return nil, false
	}

	// Collect rule files
	var ruleFiles []string

	// Built-in rules
	builtinPath := filepath.Join(os.TempDir(), "an4scan-builtin.yar")
	os.WriteFile(builtinPath, []byte(YaraRulesSource), 0644)
	defer os.Remove(builtinPath)
	ruleFiles = append(ruleFiles, builtinPath)

	// Extra rules
	if extraRulesPath != "" {
		info, err := os.Stat(extraRulesPath)
		if err == nil {
			if info.IsDir() {
				filepath.WalkDir(extraRulesPath, func(path string, d os.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return nil
					}
					ext := strings.ToLower(filepath.Ext(d.Name()))
					if ext == ".yar" || ext == ".yara" {
						ruleFiles = append(ruleFiles, path)
					}
					return nil
				})
			} else {
				ruleFiles = append(ruleFiles, extraRulesPath)
			}
		}
	}

	// Community rulesets
	ruleFiles = append(ruleFiles, getAllRuleFiles()...)

	if verbose {
		fmt.Fprintf(os.Stderr, "  [YARA] Using %d rule file(s)\n", len(ruleFiles))
	}

	var findings []Finding
	loaded := 0
	failed := 0

	// Scan files with each rule file
	for _, ruleFile := range ruleFiles {
		// Test if rule file compiles
		cmd := exec.Command(yaraBin, "-w", "-C", ruleFile)
		if err := cmd.Run(); err != nil {
			failed++
			continue
		}
		loaded++

		// Scan each file
		for _, target := range files {
			info, err := os.Stat(target)
			if err != nil || info.Size() > MaxFileSize || info.Size() == 0 {
				continue
			}

			cmd := exec.Command(yaraBin, "-w", "-s", ruleFile, target)
			out, err := cmd.Output()
			if err != nil || len(out) == 0 {
				continue
			}

			rel, _ := filepath.Rel(root, target)
			// Parse YARA output: "rulename filepath"
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				parts := strings.Fields(line)
				if len(parts) >= 2 && !strings.HasPrefix(line, "0x") {
					ruleName := parts[0]
					findings = append(findings, Finding{
						FilePath:    rel,
						SignatureID: "YARA-" + ruleName,
						Severity:    HIGH,
						Category:    "yara",
						Description: "[YARA] " + ruleName,
					})
				}
			}
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "  [YARA] Loaded %d ruleset(s), %d failed\n", loaded, failed)
	}

	return findings, true
}
