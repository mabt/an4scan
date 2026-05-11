package main

import (
	"strconv"
	"strings"
)

func parseVersionTuple(version string) [4]int {
	v := strings.TrimLeft(version, "~v")
	parts := strings.SplitN(v, "-", 2)
	base := parts[0]
	patch := 0
	if len(parts) > 1 && strings.HasPrefix(parts[1], "p") {
		patch, _ = strconv.Atoi(parts[1][1:])
	}
	baseParts := strings.Split(base, ".")
	var result [4]int
	for i := 0; i < 3 && i < len(baseParts); i++ {
		result[i], _ = strconv.Atoi(baseParts[i])
	}
	result[3] = patch
	return result
}

func versionLessOrEqual(a, b [4]int) bool {
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true // equal
}

func checkCVEs(version string, cveDB []CVEDef, label string) []Finding {
	if version == "" {
		return nil
	}
	var findings []Finding
	current := parseVersionTuple(version)

	for _, cve := range cveDB {
		affected := parseVersionTuple(cve.AffectedUpTo)
		if versionLessOrEqual(current, affected) {
			findings = append(findings, Finding{
				FilePath:    label + "_VERSION",
				SignatureID: cve.CVEID,
				Severity:    cve.Severity,
				Category:    "cve",
				Description: cve.Description,
				LineContent: "Affected: <= " + cve.AffectedUpTo + " | Fix: " + cve.Patch,
				Context:     "Detected version: " + version,
			})
		}
	}

	sortFindings(findings)
	return findings
}

func checkCVEsForCMS(cms CMSInfo) []Finding {
	switch cms.Type {
	case CMSMagento:
		return checkCVEs(cms.Version, MagentoCVEs, "MAGENTO")
	case CMSWordPress:
		return checkCVEs(cms.Version, WordPressCVEs, "WORDPRESS")
	case CMSPrestaShop:
		return checkCVEs(cms.Version, PrestaShopCVEs, "PRESTASHOP")
	default:
		return nil
	}
}

