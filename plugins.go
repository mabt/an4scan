package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PluginInfo represents an installed plugin/module/extension.
type PluginInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // plugin, theme, module, extension
	Path    string `json:"path"`
	Active  bool   `json:"active"`
}

// PluginFinding represents a vulnerability found in a plugin.
type PluginFinding struct {
	Plugin      string `json:"plugin"`
	Version     string `json:"version"`
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fix         string `json:"fix"`
}

// detectPlugins discovers installed plugins/modules based on CMS type.
func detectPlugins(root string, cmsType CMSType, verbose bool) []PluginInfo {
	switch cmsType {
	case CMSWordPress:
		return detectWPPlugins(root, verbose)
	case CMSPrestaShop:
		return detectPSModules(root, verbose)
	case CMSMagento:
		return detectMagentoExtensions(root, verbose)
	default:
		return nil
	}
}

// checkPluginVulns checks detected plugins against known vulnerable versions.
func checkPluginVulns(plugins []PluginInfo, cmsType CMSType) []PluginFinding {
	var findings []PluginFinding

	var db []pluginCVE
	switch cmsType {
	case CMSWordPress:
		db = wpPluginCVEs
	case CMSPrestaShop:
		db = psModuleCVEs
	case CMSMagento:
		db = magentoExtCVEs
	}

	for _, plugin := range plugins {
		slug := strings.ToLower(plugin.Name)
		for _, cve := range db {
			if strings.ToLower(cve.Slug) == slug {
				if plugin.Version != "" && versionLessOrEqual(
					parseVersionTuple(plugin.Version),
					parseVersionTuple(cve.AffectedUpTo),
				) {
					findings = append(findings, PluginFinding{
						Plugin:      plugin.Name,
						Version:     plugin.Version,
						CVEID:       cve.CVEID,
						Severity:    cve.Severity,
						Description: cve.Description,
						Fix:         cve.Fix,
					})
				}
			}
		}
	}
	return findings
}

// ─── WordPress Plugin Detection ─────────────────────────────────────────────

func detectWPPlugins(root string, verbose bool) []PluginInfo {
	var plugins []PluginInfo

	// Detect plugins
	pluginsDir := filepath.Join(root, "wp-content", "plugins")
	if entries, err := os.ReadDir(pluginsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			pluginDir := filepath.Join(pluginsDir, name)
			version := extractWPPluginVersion(pluginDir, name)
			plugins = append(plugins, PluginInfo{
				Name: name, Version: version, Type: "plugin",
				Path: filepath.Join("wp-content", "plugins", name), Active: true,
			})
		}
	}

	// Detect themes
	themesDir := filepath.Join(root, "wp-content", "themes")
	if entries, err := os.ReadDir(themesDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			themeDir := filepath.Join(themesDir, name)
			version := extractWPThemeVersion(themeDir)
			plugins = append(plugins, PluginInfo{
				Name: name, Version: version, Type: "theme",
				Path: filepath.Join("wp-content", "themes", name),
			})
		}
	}

	// Detect mu-plugins
	muDir := filepath.Join(root, "wp-content", "mu-plugins")
	if entries, err := os.ReadDir(muDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.HasSuffix(e.Name(), ".php") {
				plugins = append(plugins, PluginInfo{
					Name: strings.TrimSuffix(e.Name(), ".php"), Type: "mu-plugin",
					Path: filepath.Join("wp-content", "mu-plugins", e.Name()), Active: true,
				})
			}
		}
	}

	return plugins
}

var wpPluginVersionRe = regexp.MustCompile(`(?i)Version:\s*([0-9][0-9a-zA-Z._-]*)`)

func extractWPPluginVersion(pluginDir, name string) string {
	// Check main plugin file (name.php)
	mainFile := filepath.Join(pluginDir, name+".php")
	if v := extractWPHeaderVersion(mainFile); v != "" {
		return v
	}
	// Check all PHP files in root of plugin dir
	entries, _ := os.ReadDir(pluginDir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".php") {
			if v := extractWPHeaderVersion(filepath.Join(pluginDir, e.Name())); v != "" {
				return v
			}
		}
	}
	return ""
}

func extractWPHeaderVersion(phpFile string) string {
	data, err := os.ReadFile(phpFile)
	if err != nil {
		return ""
	}
	// Only scan first 8KB (plugin header is always at top)
	content := string(data)
	if len(content) > 8192 {
		content = content[:8192]
	}
	m := wpPluginVersionRe.FindStringSubmatch(content)
	if m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var wpThemeVersionRe = regexp.MustCompile(`(?i)Version:\s*([0-9][0-9a-zA-Z._-]*)`)

func extractWPThemeVersion(themeDir string) string {
	styleCSS := filepath.Join(themeDir, "style.css")
	data, err := os.ReadFile(styleCSS)
	if err != nil {
		return ""
	}
	content := string(data)
	if len(content) > 4096 {
		content = content[:4096]
	}
	m := wpThemeVersionRe.FindStringSubmatch(content)
	if m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ─── PrestaShop Module Detection ────────────────────────────────────────────

func detectPSModules(root string, verbose bool) []PluginInfo {
	var plugins []PluginInfo

	modulesDir := filepath.Join(root, "modules")
	if entries, err := os.ReadDir(modulesDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			moduleDir := filepath.Join(modulesDir, name)
			version := extractPSModuleVersion(moduleDir, name)
			plugins = append(plugins, PluginInfo{
				Name: name, Version: version, Type: "module",
				Path: filepath.Join("modules", name), Active: true,
			})
		}
	}

	// Detect themes
	themesDir := filepath.Join(root, "themes")
	if entries, err := os.ReadDir(themesDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "core.js" {
				continue
			}
			name := e.Name()
			plugins = append(plugins, PluginInfo{
				Name: name, Type: "theme",
				Path: filepath.Join("themes", name),
			})
		}
	}

	return plugins
}

var psVersionRe = regexp.MustCompile(`(?i)(?:\$this->version\s*=\s*['"]([^'"]+)|'version'\s*=>\s*'([^']+))`)

func extractPSModuleVersion(moduleDir, name string) string {
	mainFile := filepath.Join(moduleDir, name+".php")
	data, err := os.ReadFile(mainFile)
	if err != nil {
		return ""
	}
	content := string(data)
	m := psVersionRe.FindStringSubmatch(content)
	if m != nil {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}

	// Try config.xml
	configXML := filepath.Join(moduleDir, "config.xml")
	if data, err := os.ReadFile(configXML); err == nil {
		re := regexp.MustCompile(`<version>([^<]+)</version>`)
		if m := re.FindStringSubmatch(string(data)); m != nil {
			return m[1]
		}
	}

	return ""
}

// ─── Magento Extension Detection ────────────────────────────────────────────

func detectMagentoExtensions(root string, verbose bool) []PluginInfo {
	var plugins []PluginInfo

	// Method 1: composer.lock (most reliable)
	lockPath := filepath.Join(root, "composer.lock")
	if data, err := os.ReadFile(lockPath); err == nil {
		var lock struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			} `json:"packages"`
		}
		if json.Unmarshal(data, &lock) == nil {
			for _, pkg := range lock.Packages {
				// Skip core magento packages
				if strings.HasPrefix(pkg.Name, "magento/") ||
					strings.HasPrefix(pkg.Name, "php") ||
					strings.HasPrefix(pkg.Name, "ext-") ||
					pkg.Type == "metapackage" {
					continue
				}
				if pkg.Type == "magento2-module" || pkg.Type == "magento2-theme" ||
					pkg.Type == "magento2-language" || pkg.Type == "magento2-library" {
					pType := strings.TrimPrefix(pkg.Type, "magento2-")
					plugins = append(plugins, PluginInfo{
						Name: pkg.Name, Version: strings.TrimLeft(pkg.Version, "v"),
						Type: pType, Path: "vendor/" + pkg.Name, Active: true,
					})
				}
			}
		}
	}

	// Method 2: app/code (local modules)
	appCode := filepath.Join(root, "app", "code")
	if entries, err := os.ReadDir(appCode); err == nil {
		for _, vendor := range entries {
			if !vendor.IsDir() || vendor.Name() == "Magento" {
				continue
			}
			vendorDir := filepath.Join(appCode, vendor.Name())
			modules, _ := os.ReadDir(vendorDir)
			for _, mod := range modules {
				if !mod.IsDir() {
					continue
				}
				name := vendor.Name() + "/" + mod.Name()
				modPath := filepath.Join(appCode, vendor.Name(), mod.Name())
				version := extractMagentoModuleVersion(modPath)
				plugins = append(plugins, PluginInfo{
					Name: name, Version: version, Type: "module",
					Path: filepath.Join("app", "code", vendor.Name(), mod.Name()),
					Active: true,
				})
			}
		}
	}

	return plugins
}

func extractMagentoModuleVersion(modDir string) string {
	cjPath := filepath.Join(modDir, "composer.json")
	if data, err := os.ReadFile(cjPath); err == nil {
		var cj struct{ Version string `json:"version"` }
		if json.Unmarshal(data, &cj) == nil && cj.Version != "" {
			return cj.Version
		}
	}
	// Try etc/module.xml
	moduleXML := filepath.Join(modDir, "etc", "module.xml")
	if data, err := os.ReadFile(moduleXML); err == nil {
		re := regexp.MustCompile(`setup_version="([^"]+)"`)
		if m := re.FindStringSubmatch(string(data)); m != nil {
			return m[1]
		}
	}
	return ""
}

// ─── Known Plugin/Module CVE Databases ──────────────────────────────────────

type pluginCVE struct {
	Slug        string
	AffectedUpTo string
	CVEID       string
	Severity    string
	Description string
	Fix         string
}

// WordPress plugin CVEs (most exploited in the wild)
var wpPluginCVEs = []pluginCVE{
	// Elementor
	{"elementor", "3.18.0", "CVE-2024-24934", CRITICAL,
		"Arbitrary file upload via template import", "Upgrade to 3.18.1+"},
	{"elementor", "3.12.1", "CVE-2023-32243", CRITICAL,
		"Remote Code Execution (ACTIVELY EXPLOITED)", "Upgrade to 3.12.2+"},
	// WPForms
	{"wpforms-lite", "1.8.4.1", "CVE-2023-47684", HIGH,
		"Stored XSS via form fields", "Upgrade to 1.8.5+"},
	// Contact Form 7
	{"contact-form-7", "5.3.1", "CVE-2020-35489", CRITICAL,
		"Unrestricted file upload to RCE", "Upgrade to 5.3.2+"},
	// WooCommerce
	{"woocommerce", "8.6.0", "CVE-2024-30219", HIGH,
		"Stored XSS in product attributes", "Upgrade to 8.6.1+"},
	{"woocommerce", "6.2.0", "CVE-2023-28121", CRITICAL,
		"Authentication bypass to admin (ACTIVELY EXPLOITED)", "Upgrade to 6.2.1+"},
	{"woocommerce", "5.5.0", "CVE-2021-32789", CRITICAL,
		"SQL Injection via tax rate CSV import", "Upgrade to 5.5.1+"},
	// Yoast SEO
	{"wordpress-seo", "21.6", "CVE-2024-4041", MEDIUM,
		"Reflected XSS via search", "Upgrade to 21.7+"},
	// All in One SEO
	{"all-in-one-seo-pack", "4.2.5.1", "CVE-2023-0585", HIGH,
		"Stored XSS (contributor+)", "Upgrade to 4.2.6+"},
	{"all-in-one-seo-pack", "4.1.5.2", "CVE-2021-25036", CRITICAL,
		"Privilege escalation + SQL injection (ACTIVELY EXPLOITED)", "Upgrade to 4.1.5.3+"},
	// WP File Manager
	{"wp-file-manager", "6.8", "CVE-2020-25213", CRITICAL,
		"Unauthenticated RCE via file upload (ACTIVELY EXPLOITED)", "Upgrade to 6.9+"},
	// Wordfence
	{"wordfence", "7.10.6", "CVE-2024-1071", CRITICAL,
		"Unauthenticated SQL Injection", "Upgrade to 7.10.7+"},
	// Really Simple SSL
	{"really-simple-ssl", "9.0.0", "CVE-2023-49583", CRITICAL,
		"Authentication bypass to admin (ACTIVELY EXPLOITED)", "Upgrade to 9.0.1+"},
	// UpdraftPlus
	{"updraftplus", "1.22.2", "CVE-2022-0633", HIGH,
		"Arbitrary backup download (subscriber+)", "Upgrade to 1.22.3+"},
	// LiteSpeed Cache
	{"litespeed-cache", "6.3.0.1", "CVE-2024-28000", CRITICAL,
		"Unauthenticated privilege escalation (ACTIVELY EXPLOITED)", "Upgrade to 6.4+"},
	{"litespeed-cache", "5.7.0.1", "CVE-2024-3246", HIGH,
		"Stored XSS via admin settings", "Upgrade to 5.7.1+"},
	// Jetpack
	{"jetpack", "12.1.0", "CVE-2023-47774", CRITICAL,
		"Arbitrary file manipulation", "Upgrade to 12.1.1+"},
	// WP SMTP
	{"wp-mail-smtp", "3.3.0", "CVE-2022-2523", MEDIUM,
		"Sensitive data exposure via log file", "Upgrade to 3.4+"},
	// Advanced Custom Fields
	{"advanced-custom-fields", "6.1.5", "CVE-2023-30777", HIGH,
		"Reflected XSS (ACTIVELY EXPLOITED)", "Upgrade to 6.1.6+"},
	// BackupBuddy / Jetstash
	{"developer", "8.7.4.1", "CVE-2022-31474", CRITICAL,
		"Arbitrary file read/download (ACTIVELY EXPLOITED)", "Upgrade to 8.7.5+"},
	// Gravity Forms
	{"gravityforms", "2.7.3", "CVE-2023-28782", HIGH,
		"PHP Object Injection", "Upgrade to 2.7.4+"},
	// Ultimate Member
	{"developer", "2.6.6", "CVE-2023-3460", CRITICAL,
		"Unauthenticated privilege escalation (ACTIVELY EXPLOITED)", "Upgrade to 2.6.7+"},
	// Royal Elementor Addons
	{"developer", "1.3.78", "CVE-2023-5360", CRITICAL,
		"Unauthenticated file upload to RCE (ACTIVELY EXPLOITED)", "Upgrade to 1.3.79+"},
	// TagDiv Composer
	{"developer", "4.1", "CVE-2023-3169", HIGH,
		"Unauthenticated stored XSS (ACTIVELY EXPLOITED)", "Upgrade to 4.2+"},
}

// PrestaShop module CVEs
var psModuleCVEs = []pluginCVE{
	// blockwishlist
	{"blockwishlist", "2.1.0", "CVE-2023-43663", CRITICAL,
		"SQL Injection (unauthenticated)", "Upgrade to 2.1.1+ or remove"},
	// pk_faq
	{"pk_faq", "99.99.99", "CVE-2024-36680", CRITICAL,
		"SQL Injection (ACTIVELY EXPLOITED)", "Remove module immediately"},
	// ps_facetedsearch
	{"ps_facetedsearch", "3.4.1", "CVE-2022-31101", HIGH,
		"SQL Injection via search filters", "Upgrade to 3.4.2+"},
	// contactform
	{"contactform", "4.3.0", "CVE-2022-31110", MEDIUM,
		"CSRF + Stored XSS", "Upgrade to 4.4.0+"},
	// ps_emailsubscription
	{"ps_emailsubscription", "2.6.1", "CVE-2022-22897", HIGH,
		"SQL Injection", "Upgrade to 2.7.0+"},
	// productcomments
	{"productcomments", "5.0.1", "CVE-2022-35934", HIGH,
		"SQL Injection", "Upgrade to 5.0.2+"},
	// gamification
	{"gamification", "2.3.0", "CVE-2022-22895", CRITICAL,
		"Remote Code Execution", "Remove or upgrade"},
	// ps_linklist
	{"ps_linklist", "3.2.0", "CVE-2021-36748", CRITICAL,
		"Blind SQL Injection (ACTIVELY EXPLOITED)", "Upgrade to 3.2.1+"},
	// autoupgrade
	{"autoupgrade", "4.14.0", "CVE-2022-35937", HIGH,
		"Arbitrary file deletion", "Upgrade to 4.15.0+"},
	// wishlist
	{"wishlist", "2.0.0", "CVE-2022-36418", HIGH,
		"SQL Injection (authenticated)", "Upgrade to 2.1.0+"},
}

// Magento extension CVEs
var magentoExtCVEs = []pluginCVE{
	// Mageplaza
	{"mageplaza/magento-2-seo-extension", "99.99.99", "CVE-2024-21633", HIGH,
		"Stored XSS in SEO meta fields", "Check vendor for patch"},
	// Amasty
	{"amasty/module-shop-by-brand", "2.12.0", "CVE-2024-24409", CRITICAL,
		"SQL Injection (unauthenticated)", "Upgrade to 2.12.1+"},
	// Mageworx
	{"mageworx/module-optionfeatures", "99.99.99", "CVE-2023-28431", HIGH,
		"Stored XSS via product options", "Check vendor for patch"},
	// TempUI/Jetstash (common compromised extensions)
	{"temando/module-shipping-m2", "99.99.99", "CVE-2022-23931", CRITICAL,
		"Abandoned extension with known RCE (remove immediately)", "Remove extension"},
	// Fooman
	{"fooman/emailattachments-m2", "1.0.11", "CVE-2022-29903", MEDIUM,
		"Path traversal in email attachment", "Upgrade to 1.1.0+"},
}
