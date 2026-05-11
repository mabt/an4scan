package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type CMSType string

const (
	CMSMagento    CMSType = "magento"
	CMSWordPress  CMSType = "wordpress"
	CMSPrestaShop CMSType = "prestashop"
	CMSUnknown    CMSType = "unknown"
)

type CMSInfo struct {
	Type    CMSType `json:"type"`
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Edition string  `json:"edition,omitempty"`
	Source  string  `json:"source"`
	EOL     string  `json:"eol,omitempty"`
}

// detectCMS identifies the CMS type and version from the given root directory.
func detectCMS(root string) CMSInfo {
	// Try each CMS in order of specificity
	if info := detectMagento(root); info.Type != CMSUnknown {
		return info
	}
	if info := detectPrestaShop(root); info.Type != CMSUnknown {
		return info
	}
	if info := detectWordPress(root); info.Type != CMSUnknown {
		return info
	}
	return CMSInfo{Type: CMSUnknown, Name: "Unknown CMS"}
}

// ─── Magento Detection ──────────────────────────────────────────────────────

func detectMagento(root string) CMSInfo {
	info := CMSInfo{Type: CMSUnknown}

	// Check for Magento markers
	markers := []string{
		filepath.Join(root, "bin", "magento"),
		filepath.Join(root, "app", "etc", "env.php"),
		filepath.Join(root, "app", "etc", "config.php"),
	}
	found := false
	for _, m := range markers {
		if _, err := os.Stat(m); err == nil {
			found = true
			break
		}
	}
	if !found {
		return info
	}

	info.Type = CMSMagento
	info.Name = "Magento 2"
	info.Edition = "Community (Open Source)"

	// Version from composer.lock
	lockPath := filepath.Join(root, "composer.lock")
	if data, err := os.ReadFile(lockPath); err == nil {
		var lock struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		}
		if json.Unmarshal(data, &lock) == nil {
			for _, pkg := range lock.Packages {
				switch pkg.Name {
				case "magento/magento2-base":
					info.Version = strings.TrimLeft(pkg.Version, "v")
					info.Source = "composer.lock (magento2-base)"
				case "magento/product-community-edition":
					if info.Version == "" {
						info.Version = strings.TrimLeft(pkg.Version, "v")
					}
					info.Edition = "Community (Open Source)"
					if info.Source == "" {
						info.Source = "composer.lock"
					}
				case "magento/product-enterprise-edition":
					if info.Version == "" {
						info.Version = strings.TrimLeft(pkg.Version, "v")
					}
					info.Edition = "Enterprise (Commerce)"
					if info.Source == "" {
						info.Source = "composer.lock"
					}
				}
			}
		}
	}

	// Fallback: composer.json
	if info.Version == "" {
		jsonPath := filepath.Join(root, "composer.json")
		if data, err := os.ReadFile(jsonPath); err == nil {
			var cj map[string]interface{}
			if json.Unmarshal(data, &cj) == nil {
				for _, reqKey := range []string{"require", "require-dev"} {
					if reqs, ok := cj[reqKey].(map[string]interface{}); ok {
						for _, pkg := range []string{
							"magento/product-community-edition",
							"magento/product-enterprise-edition",
						} {
							if v, ok := reqs[pkg].(string); ok {
								info.Version = strings.TrimLeft(v, "^~>=v ")
								info.Source = "composer.json"
								break
							}
						}
					}
				}
			}
		}
	}

	// Fallback: framework version
	if info.Version == "" {
		fwPath := filepath.Join(root, "vendor", "magento", "framework", "composer.json")
		if data, err := os.ReadFile(fwPath); err == nil {
			var fw struct{ Version string `json:"version"` }
			if json.Unmarshal(data, &fw) == nil && fw.Version != "" {
				mapping := map[string]string{
					"103.": "2.4.7", "102.": "2.4.6", "101.": "2.4.5",
					"100.": "2.4.4", "99.": "2.4.3", "98.": "2.4.2",
				}
				for prefix, ver := range mapping {
					if strings.HasPrefix(fw.Version, prefix) {
						info.Version = "~" + ver
						info.Source = "framework composer.json"
						break
					}
				}
			}
		}
	}

	// Edition from config.php
	if info.Edition == "Community (Open Source)" {
		configPath := filepath.Join(root, "app", "etc", "config.php")
		if data, err := os.ReadFile(configPath); err == nil {
			if strings.Contains(string(data), "Magento_Enterprise") || strings.Contains(string(data), "Magento_AdminGws") {
				info.Edition = "Enterprise (Commerce)"
			}
		}
	}

	info.EOL = checkMagentoEOL(info.Version)
	return info
}

func checkMagentoEOL(version string) string {
	if version == "" {
		return ""
	}
	v := strings.TrimLeft(version, "~")
	eol := map[string]string{
		"2.3":   "Magento 2.3.x reached EOL in September 2022.",
		"2.4.0": "Magento 2.4.0 has reached EOL.",
		"2.4.1": "Magento 2.4.1 has reached EOL.",
		"2.4.2": "Magento 2.4.2 has reached EOL.",
		"2.4.3": "Magento 2.4.3 line has reached EOL.",
		"2.4.4": "Magento 2.4.4 line has reached EOL in November 2024.",
		"2.4.5": "Magento 2.4.5 line reaches EOL in August 2025.",
	}
	for prefix, msg := range eol {
		if strings.HasPrefix(v, prefix) {
			return msg
		}
	}
	if strings.HasPrefix(v, "2.2") || strings.HasPrefix(v, "2.1") || strings.HasPrefix(v, "2.0") {
		return "Magento " + v + " is severely outdated and EOL."
	}
	return ""
}

// ─── WordPress Detection ────────────────────────────────────────────────────

func detectWordPress(root string) CMSInfo {
	info := CMSInfo{Type: CMSUnknown}

	wpConfig := filepath.Join(root, "wp-config.php")
	if _, err := os.Stat(wpConfig); err != nil {
		// Also check one level up (wp-config.php can be above webroot)
		wpConfig = filepath.Join(root, "..", "wp-config.php")
		if _, err := os.Stat(wpConfig); err != nil {
			return info
		}
	}

	info.Type = CMSWordPress
	info.Name = "WordPress"

	// Version from wp-includes/version.php
	versionFile := filepath.Join(root, "wp-includes", "version.php")
	if data, err := os.ReadFile(versionFile); err == nil {
		re := regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
		if m := re.FindStringSubmatch(string(data)); m != nil {
			info.Version = m[1]
			info.Source = "wp-includes/version.php"
		}
	}

	// Fallback: readme.html
	if info.Version == "" {
		readmePath := filepath.Join(root, "readme.html")
		if data, err := os.ReadFile(readmePath); err == nil {
			re := regexp.MustCompile(`(?i)Version\s+(\d+\.\d+(?:\.\d+)?)`)
			if m := re.FindStringSubmatch(string(data)); m != nil {
				info.Version = m[1]
				info.Source = "readme.html"
			}
		}
	}

	info.EOL = checkWordPressEOL(info.Version)
	return info
}

func checkWordPressEOL(version string) string {
	if version == "" {
		return ""
	}
	// WordPress doesn't have formal EOL, but old versions are unsupported
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		major := parts[0] + "." + parts[1]
		oldVersions := map[string]bool{
			"4.0": true, "4.1": true, "4.2": true, "4.3": true, "4.4": true,
			"4.5": true, "4.6": true, "4.7": true, "4.8": true, "4.9": true,
			"5.0": true, "5.1": true, "5.2": true, "5.3": true, "5.4": true,
			"5.5": true, "5.6": true, "5.7": true, "5.8": true, "5.9": true,
		}
		if oldVersions[major] {
			return "WordPress " + version + " is outdated. Upgrade to latest version."
		}
	}
	return ""
}

// ─── PrestaShop Detection ───────────────────────────────────────────────────

func detectPrestaShop(root string) CMSInfo {
	info := CMSInfo{Type: CMSUnknown}

	// PrestaShop markers
	markers := []string{
		filepath.Join(root, "config", "settings.inc.php"),
		filepath.Join(root, "classes", "PrestaShopAutoload.php"),
	}
	found := false
	for _, m := range markers {
		if _, err := os.Stat(m); err == nil {
			found = true
			break
		}
	}
	if !found {
		return info
	}

	info.Type = CMSPrestaShop
	info.Name = "PrestaShop"

	// Version from config/settings.inc.php
	settingsPath := filepath.Join(root, "config", "settings.inc.php")
	if data, err := os.ReadFile(settingsPath); err == nil {
		re := regexp.MustCompile(`define\s*\(\s*'_PS_VERSION_'\s*,\s*'([^']+)'`)
		if m := re.FindStringSubmatch(string(data)); m != nil {
			info.Version = m[1]
			info.Source = "config/settings.inc.php"
		}
	}

	// Fallback: app/AppKernel.php (PS 1.7+)
	if info.Version == "" {
		kernelPath := filepath.Join(root, "app", "AppKernel.php")
		if data, err := os.ReadFile(kernelPath); err == nil {
			re := regexp.MustCompile(`const\s+VERSION\s*=\s*'([^']+)'`)
			if m := re.FindStringSubmatch(string(data)); m != nil {
				info.Version = m[1]
				info.Source = "app/AppKernel.php"
			}
		}
	}

	// Fallback: composer.json
	if info.Version == "" {
		cjPath := filepath.Join(root, "composer.json")
		if data, err := os.ReadFile(cjPath); err == nil {
			var cj struct{ Version string `json:"version"` }
			if json.Unmarshal(data, &cj) == nil && cj.Version != "" {
				info.Version = cj.Version
				info.Source = "composer.json"
			}
		}
	}

	info.EOL = checkPrestaShopEOL(info.Version)
	return info
}

func checkPrestaShopEOL(version string) string {
	if version == "" {
		return ""
	}
	v := version
	if strings.HasPrefix(v, "1.6") {
		return "PrestaShop 1.6 has reached EOL in June 2019."
	}
	if strings.HasPrefix(v, "1.5") || strings.HasPrefix(v, "1.4") {
		return "PrestaShop " + v + " is severely outdated and EOL."
	}
	if strings.HasPrefix(v, "1.7") {
		return "PrestaShop 1.7 has reached EOL. Upgrade to 8.x."
	}
	return ""
}

// ─── CMS-Specific Whitelists ────────────────────────────────────────────────

var wordPressWhitelist = []string{
	"wp-includes/",
	"wp-admin/",
	"wp-content/themes/twentytwenty",
	"wp-content/themes/twentytwentyone",
	"wp-content/themes/twentytwentytwo",
	"wp-content/themes/twentytwentythree",
	"wp-content/themes/twentytwentyfour",
	"wp-content/themes/twentytwentyfive",
	"wp-content/plugins/akismet",
	"wp-content/plugins/woocommerce",
	"wp-content/plugins/wordpress-seo",
	"wp-content/plugins/jetpack",
	"wp-content/plugins/contact-form-7",
	"vendor/",
}

var prestaShopWhitelist = []string{
	"classes/",
	"controllers/",
	"Core/",
	"Adapter/",
	"vendor/",
	"tools/",
	"js/jquery",
	"js/tiny_mce",
	"modules/ps_",
	"themes/classic",
	"themes/core.js",
}

func getWhitelistForCMS(cms CMSType) []string {
	switch cms {
	case CMSMagento:
		return WhitelistPaths
	case CMSWordPress:
		return wordPressWhitelist
	case CMSPrestaShop:
		return prestaShopWhitelist
	default:
		return nil
	}
}
