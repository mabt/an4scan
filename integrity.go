package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// IntegrityResult holds the result of a core file integrity check.
type IntegrityResult struct {
	Checked  int       `json:"checked"`
	Modified []ModFile `json:"modified"`
	Unknown  []string  `json:"unknown"`
	Missing  []string  `json:"missing"`
}

// ModFile represents a modified core file.
type ModFile struct {
	Path         string `json:"path"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash   string `json:"actual_hash"`
}

// checkIntegrity runs core file integrity checks based on CMS type.
func checkIntegrity(root string, cms CMSInfo, verbose bool) (IntegrityResult, []Finding) {
	switch cms.Type {
	case CMSWordPress:
		return checkWPIntegrity(root, cms.Version, verbose)
	case CMSPrestaShop:
		return checkPSIntegrity(root, verbose)
	case CMSMagento:
		return checkMagentoIntegrity(root, verbose)
	default:
		return IntegrityResult{}, nil
	}
}

// ─── WordPress Integrity (uses official checksums API) ──────────────────────

func checkWPIntegrity(root, version string, verbose bool) (IntegrityResult, []Finding) {
	result := IntegrityResult{}
	var findings []Finding

	if version == "" {
		if verbose {
			fmt.Fprintln(os.Stderr, "  [INTEGRITY] WordPress version not detected, skipping checksum verification")
		}
		return result, nil
	}

	// Fetch checksums from WordPress.org API
	checksums, err := fetchWPChecksums(version)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  [INTEGRITY] Failed to fetch WP checksums: %v\n", err)
		}
		// Fallback to basic checks
		return checkBasicIntegrity(root, []string{
			"wp-includes", "wp-admin",
		}, verbose)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "  [INTEGRITY] Checking %d core files against WordPress.org checksums\n", len(checksums))
	}

	for relPath, expectedHash := range checksums {
		result.Checked++
		fullPath := filepath.Join(root, relPath)

		actualHash, err := hashFileMD5(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Only flag critical missing files
				if strings.HasPrefix(relPath, "wp-admin/") || strings.HasPrefix(relPath, "wp-includes/") {
					result.Missing = append(result.Missing, relPath)
				}
			}
			continue
		}

		if actualHash != expectedHash {
			result.Modified = append(result.Modified, ModFile{
				Path: relPath, ExpectedHash: expectedHash, ActualHash: actualHash,
			})

			sev := MEDIUM
			desc := "Core file modified (hash mismatch)"
			if strings.HasPrefix(relPath, "wp-admin/") || strings.HasPrefix(relPath, "wp-includes/") {
				sev = HIGH
				desc = "Critical core file modified (hash mismatch with WordPress.org)"
			}
			if strings.Contains(relPath, "wp-login.php") || strings.Contains(relPath, "user.php") {
				sev = CRITICAL
				desc = "Authentication-critical file modified (possible backdoor)"
			}

			findings = append(findings, Finding{
				FilePath:    relPath,
				SignatureID: "INTEG-WP",
				Severity:    sev,
				Category:    "integrity",
				Description: desc,
				LineContent: fmt.Sprintf("Expected: %s, Got: %s", expectedHash[:12], actualHash[:12]),
			})
		}
	}

	// Check for extra PHP files in wp-admin and wp-includes
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		dirPath := filepath.Join(root, dir)
		filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if _, known := checksums[rel]; !known {
				if strings.HasSuffix(rel, ".php") {
					result.Unknown = append(result.Unknown, rel)
					findings = append(findings, Finding{
						FilePath:    rel,
						SignatureID: "INTEG-EXTRA",
						Severity:    HIGH,
						Category:    "integrity",
						Description: "Unknown PHP file in core directory (not in WordPress.org checksums)",
					})
				}
			}
			return nil
		})
	}

	return result, findings
}

func fetchWPChecksums(version string) (map[string]string, error) {
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=en_US", version)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Checksums map[string]string `json:"checksums"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid API response: %w", err)
	}

	if len(result.Checksums) == 0 {
		return nil, fmt.Errorf("no checksums returned for version %s", version)
	}

	return result.Checksums, nil
}

// ─── PrestaShop Integrity ───────────────────────────────────────────────────

func checkPSIntegrity(root string, verbose bool) (IntegrityResult, []Finding) {
	// PrestaShop doesn't have a public checksums API
	// We do basic integrity checks: look for modified/extra files in core dirs
	return checkBasicIntegrity(root, []string{
		"classes",
		"controllers",
		"Core",
		"Adapter",
		filepath.Join("src", "Core"),
		filepath.Join("src", "Adapter"),
	}, verbose)
}

// ─── Magento Integrity ──────────────────────────────────────────────────────

func checkMagentoIntegrity(root string, verbose bool) (IntegrityResult, []Finding) {
	// Magento doesn't have a public checksums API
	// Check for modifications in vendor/magento using composer integrity
	result := IntegrityResult{}
	var findings []Finding

	// Check if vendor/magento files match composer.lock expectations
	// Use basic method: look for recently modified files and extra PHP files
	vendorMagento := filepath.Join(root, "vendor", "magento")
	if _, err := os.Stat(vendorMagento); err != nil {
		return result, findings
	}

	// Get reference time from composer.lock
	refTime := time.Time{}
	lockInfo, err := os.Stat(filepath.Join(root, "composer.lock"))
	if err == nil {
		refTime = lockInfo.ModTime().Add(time.Hour)
	}

	filepath.WalkDir(vendorMagento, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".php" && ext != ".phtml" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		result.Checked++

		if !refTime.IsZero() && info.ModTime().After(refTime) {
			rel, _ := filepath.Rel(root, path)
			result.Modified = append(result.Modified, ModFile{Path: rel})
			findings = append(findings, Finding{
				FilePath:    rel,
				SignatureID: "INTEG-MG",
				Severity:    HIGH,
				Category:    "integrity",
				Description: "Magento core vendor file modified after last composer install",
				LineContent: "Modified: " + info.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
		return nil
	})

	// Check app/code/Magento (should not exist unless deliberately overriding)
	appMagento := filepath.Join(root, "app", "code", "Magento")
	if _, err := os.Stat(appMagento); err == nil {
		filepath.WalkDir(appMagento, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			result.Unknown = append(result.Unknown, rel)
			findings = append(findings, Finding{
				FilePath:    rel,
				SignatureID: "INTEG-OVERRIDE",
				Severity:    MEDIUM,
				Category:    "integrity",
				Description: "Core override in app/code/Magento (verify legitimacy)",
			})
			return nil
		})
	}

	return result, findings
}

// ─── Basic Integrity Check (fallback) ───────────────────────────────────────

func checkBasicIntegrity(root string, coreDirs []string, verbose bool) (IntegrityResult, []Finding) {
	result := IntegrityResult{}
	var findings []Finding

	// Get reference time from any reliable marker
	var refTime time.Time
	for _, marker := range []string{"composer.lock", "index.php", "config/settings.inc.php"} {
		info, err := os.Stat(filepath.Join(root, marker))
		if err == nil {
			refTime = info.ModTime().Add(time.Hour)
			break
		}
	}

	for _, dir := range coreDirs {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); err != nil {
			continue
		}
		filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext != ".php" {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}
			result.Checked++

			if !refTime.IsZero() && info.ModTime().After(refTime) {
				rel, _ := filepath.Rel(root, path)
				result.Modified = append(result.Modified, ModFile{Path: rel})
				findings = append(findings, Finding{
					FilePath:    rel,
					SignatureID: "INTEG-CORE",
					Severity:    HIGH,
					Category:    "integrity",
					Description: "Core file modified after installation",
					LineContent: "Modified: " + info.ModTime().Format("2006-01-02 15:04:05"),
				})
			}
			return nil
		})
	}

	return result, findings
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func hashFileMD5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
