package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func checkPermissions(magentoRoot string, verbose bool) []Finding {
	var findings []Finding

	filepath.WalkDir(magentoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(magentoRoot, path)

		if d.IsDir() {
			if SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			if mode&0002 != 0 { // world-writable directory
				findings = append(findings, Finding{
					FilePath:    rel + "/",
					SignatureID: "PERM-001",
					Severity:    HIGH,
					Category:    "permissions",
					Description: "World-writable directory",
					LineContent: fmt.Sprintf("Mode: %04o", mode.Perm()),
				})
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()

		// World-writable files
		if mode&0002 != 0 {
			findings = append(findings, Finding{
				FilePath:    rel,
				SignatureID: "PERM-002",
				Severity:    HIGH,
				Category:    "permissions",
				Description: "World-writable file",
				LineContent: fmt.Sprintf("Mode: %04o", mode.Perm()),
			})
		}

		// SUID/SGID on script files
		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			ext := strings.ToLower(filepath.Ext(d.Name()))
			scriptExts := map[string]bool{".php": true, ".phtml": true, ".sh": true, ".py": true, ".pl": true, ".cgi": true}
			if scriptExts[ext] {
				findings = append(findings, Finding{
					FilePath:    rel,
					SignatureID: "PERM-003",
					Severity:    CRITICAL,
					Category:    "permissions",
					Description: "SUID/SGID bit set on script file",
					LineContent: fmt.Sprintf("Mode: %04o", mode.Perm()),
				})
			}
		}

		// World-executable PHP in web dirs
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if (ext == ".php" || ext == ".phtml") && mode&0001 != 0 {
			if strings.Contains(rel, "pub/") || strings.Contains(rel, "media/") || strings.Contains(rel, "static/") {
				findings = append(findings, Finding{
					FilePath:    rel,
					SignatureID: "PERM-004",
					Severity:    MEDIUM,
					Category:    "permissions",
					Description: "World-executable PHP file in web directory",
					LineContent: fmt.Sprintf("Mode: %04o", mode.Perm()),
				})
			}
		}

		// env.php world-readable
		if rel == filepath.Join("app", "etc", "env.php") {
			if mode&0004 != 0 {
				findings = append(findings, Finding{
					FilePath:    rel,
					SignatureID: "PERM-005",
					Severity:    HIGH,
					Category:    "permissions",
					Description: "env.php is world-readable (contains DB credentials)",
					LineContent: fmt.Sprintf("Mode: %04o", mode.Perm()),
				})
			}
		}

		return nil
	})

	return findings
}
