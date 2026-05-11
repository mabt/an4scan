package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func getReferenceTime(root string) (time.Time, bool) {
	candidates := []string{
		filepath.Join(root, "composer.lock"),
		filepath.Join(root, "vendor", "magento", "framework", "composer.json"),
		filepath.Join(root, "app", "etc", "config.php"),
	}
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err == nil {
			return info.ModTime(), true
		}
	}
	return time.Time{}, false
}

func checkMtime(root string, days int, verbose bool) []Finding {
	var findings []Finding

	// Check for core overrides in app/code/Magento
	appCodeMagento := filepath.Join(root, "app", "code", "Magento")
	if info, err := os.Stat(appCodeMagento); err == nil && info.IsDir() {
		filepath.WalkDir(appCodeMagento, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			findings = append(findings, Finding{
				FilePath:    rel,
				SignatureID: "INTEG-001",
				Severity:    MEDIUM,
				Category:    "integrity",
				Description: "Core override in app/code/Magento - verify legitimacy",
			})
			return nil
		})
	}

	var cutoff time.Time
	refTime, hasRef := getReferenceTime(root)
	if hasRef {
		cutoff = refTime.Add(time.Hour) // 1 hour grace period
	} else {
		if verbose {
			fmt.Fprintln(os.Stderr, "  [MTIME] No reference file found to determine install time")
		}
		cutoff = time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	}

	// Core directories to check
	coreDirs := []string{
		filepath.Join(root, "vendor", "magento"),
		filepath.Join(root, "lib", "internal"),
		filepath.Join(root, "setup", "src"),
	}

	coreExts := map[string]bool{".php": true, ".phtml": true, ".js": true, ".html": true, ".xml": true}

	for _, coreDir := range coreDirs {
		if _, err := os.Stat(coreDir); err != nil {
			continue
		}
		filepath.WalkDir(coreDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if !coreExts[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.ModTime().After(cutoff) {
				rel, _ := filepath.Rel(root, path)
				findings = append(findings, Finding{
					FilePath:    rel,
					SignatureID: "MTIME-001",
					Severity:    HIGH,
					Category:    "modified_core",
					Description: "Core file modified after installation/update",
					LineContent: "Modified: " + info.ModTime().Format("2006-01-02 15:04:05"),
				})
			}
			return nil
		})
	}

	// Recently created PHP files in sensitive dirs
	suspiciousDirs := []string{
		filepath.Join(root, "pub", "media"),
		filepath.Join(root, "pub", "static"),
		filepath.Join(root, "var"),
		filepath.Join(root, "generated"),
	}

	recentCutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	for _, sdir := range suspiciousDirs {
		if _, err := os.Stat(sdir); err != nil {
			continue
		}
		filepath.WalkDir(sdir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.ToLower(filepath.Ext(d.Name())) != ".php" {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.ModTime().After(recentCutoff) {
				rel, _ := filepath.Rel(root, path)
				findings = append(findings, Finding{
					FilePath:    rel,
					SignatureID: "MTIME-002",
					Severity:    HIGH,
					Category:    "modified_core",
					Description: "Recently modified/created PHP file in sensitive directory",
					LineContent: fmt.Sprintf("Modified: %s, Size: %dB",
						info.ModTime().Format("2006-01-02 15:04:05"), info.Size()),
				})
			}
			return nil
		})
	}

	return findings
}
