package main

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

func writeHTMLReport(result *ScanResult, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := func(s string, args ...interface{}) {
		fmt.Fprintf(f, s+"\n", args...)
	}

	cms := result.CMSInfo
	s := result.Summary
	total := s.TotalFindings + s.TotalSuspiciousFiles

	riskClass := "ok"
	riskLabel := "No threats detected"
	if s.BySeverity[CRITICAL] > 0 {
		riskClass = "critical"
		riskLabel = fmt.Sprintf("HIGH RISK - %d critical finding(s)", s.BySeverity[CRITICAL])
	} else if s.BySeverity[HIGH] > 0 {
		riskClass = "high"
		riskLabel = fmt.Sprintf("ELEVATED RISK - %d high severity finding(s)", s.BySeverity[HIGH])
	} else if total > 0 {
		riskClass = "medium"
		riskLabel = fmt.Sprintf("LOW-MEDIUM RISK - %d finding(s)", total)
	}

	w(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AN4SCAN Report - %s</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
.container { max-width: 1100px; margin: 0 auto; }
h1 { color: #58a6ff; margin-bottom: 5px; }
h2 { color: #c9d1d9; border-bottom: 1px solid #30363d; padding-bottom: 8px; margin: 30px 0 15px; }
h3 { color: #8b949e; margin: 20px 0 10px; }
.header { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
.meta { color: #8b949e; font-size: 0.9em; }
.meta span { margin-right: 20px; }
.risk-banner { padding: 12px 20px; border-radius: 6px; font-weight: bold; margin: 15px 0; font-size: 1.1em; }
.risk-banner.critical { background: #3d1117; border: 1px solid #f85149; color: #f85149; }
.risk-banner.high { background: #3d1117; border: 1px solid #f85149; color: #ffa198; }
.risk-banner.medium { background: #2d1b00; border: 1px solid #d29922; color: #e3b341; }
.risk-banner.ok { background: #0d2818; border: 1px solid #3fb950; color: #3fb950; }
.stats { display: flex; gap: 15px; flex-wrap: wrap; margin: 15px 0; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px 18px; min-width: 120px; }
.stat .num { font-size: 1.8em; font-weight: bold; }
.stat .label { color: #8b949e; font-size: 0.85em; }
.stat .num.critical { color: #f85149; }
.stat .num.high { color: #ffa198; }
.stat .num.medium { color: #e3b341; }
.stat .num.ok { color: #3fb950; }
table { width: 100%%; border-collapse: collapse; margin: 10px 0; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }
th { background: #161b22; color: #8b949e; font-weight: 600; font-size: 0.85em; text-transform: uppercase; }
tr:hover { background: #161b22; }
.sev { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; display: inline-block; min-width: 70px; text-align: center; }
.sev.CRITICAL { background: #3d1117; color: #f85149; }
.sev.HIGH { background: #3d1117; color: #ffa198; }
.sev.MEDIUM { background: #2d1b00; color: #e3b341; }
.sev.LOW { background: #0d2230; color: #58a6ff; }
.sev.INFO { background: #21262d; color: #8b949e; }
.code { font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.85em; color: #8b949e; background: #0d1117; padding: 2px 6px; border-radius: 3px; word-break: break-all; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 15px 0; }
.plugin-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
.plugin-card { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; }
.plugin-card .name { font-weight: bold; color: #58a6ff; }
.plugin-card .ver { color: #8b949e; font-size: 0.9em; }
.timeline-item { display: flex; gap: 12px; padding: 6px 0; border-left: 2px solid #30363d; margin-left: 10px; padding-left: 15px; }
.timeline-item .ts { color: #8b949e; font-size: 0.85em; min-width: 160px; }
.footer { text-align: center; color: #484f58; margin-top: 40px; padding: 20px; font-size: 0.85em; }
</style>
</head>
<body>
<div class="container">`)

	// Header
	w(`<div class="header">`)
	w(`<h1>AN4SCAN Security Report</h1>`)
	w(`<div class="meta">`)
	w(`<span>Path: %s</span>`, html.EscapeString(result.ScanPath))
	if cms.Type != CMSUnknown {
		w(`<span>CMS: %s %s`, html.EscapeString(cms.Name), html.EscapeString(cms.Version))
		if cms.Edition != "" {
			w(` (%s)`, html.EscapeString(cms.Edition))
		}
		w(`</span>`)
	}
	w(`<span>Scanned: %s</span>`, result.StartTime[:19])
	w(`<span>Duration: %.2fs</span>`, result.DurationSeconds)
	w(`<span>Files: %d</span>`, result.TotalFilesScanned)
	w(`</div>`)
	if cms.EOL != "" {
		w(`<div class="risk-banner critical" style="margin-top:10px">⚠ %s</div>`, html.EscapeString(cms.EOL))
	}
	w(`</div>`)

	// Risk banner
	w(`<div class="risk-banner %s">%s</div>`, riskClass, riskLabel)

	// Stats
	w(`<div class="stats">`)
	critN := s.BySeverity[CRITICAL]
	highN := s.BySeverity[HIGH]
	medN := s.BySeverity[MEDIUM]
	numClass := "ok"
	if critN > 0 {
		numClass = "critical"
	} else if highN > 0 {
		numClass = "high"
	} else if total > 0 {
		numClass = "medium"
	}
	w(`<div class="stat"><div class="num %s">%d</div><div class="label">Total Findings</div></div>`, numClass, total)
	w(`<div class="stat"><div class="num critical">%d</div><div class="label">Critical</div></div>`, critN)
	w(`<div class="stat"><div class="num high">%d</div><div class="label">High</div></div>`, highN)
	w(`<div class="stat"><div class="num medium">%d</div><div class="label">Medium</div></div>`, medN)
	w(`<div class="stat"><div class="num">%d</div><div class="label">Files Scanned</div></div>`, result.TotalFilesScanned)
	w(`</div>`)

	// CVE Findings
	if len(result.CVEFindings) > 0 {
		w(`<h2>Known Vulnerabilities (CVEs)</h2>`)
		w(`<table><tr><th>Severity</th><th>CVE</th><th>Description</th><th>Fix</th></tr>`)
		for _, f := range result.CVEFindings {
			w(`<tr><td><span class="sev %s">%s</span></td><td>%s</td><td>%s</td><td class="code">%s</td></tr>`,
				f.Severity, f.Severity, html.EscapeString(f.SignatureID),
				html.EscapeString(f.Description), html.EscapeString(f.LineContent))
		}
		w(`</table>`)
	}

	// Plugin vulnerabilities
	if len(result.PluginFindings) > 0 {
		w(`<h2>Vulnerable Plugins / Modules</h2>`)
		w(`<table><tr><th>Severity</th><th>Plugin</th><th>Version</th><th>CVE</th><th>Description</th><th>Fix</th></tr>`)
		for _, pf := range result.PluginFindings {
			w(`<tr><td><span class="sev %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="code">%s</td></tr>`,
				pf.Severity, pf.Severity, html.EscapeString(pf.Plugin),
				html.EscapeString(pf.Version), html.EscapeString(pf.CVEID),
				html.EscapeString(pf.Description), html.EscapeString(pf.Fix))
		}
		w(`</table>`)
	}

	// Installed plugins list
	if len(result.Plugins) > 0 {
		w(`<h2>Installed Plugins / Modules (%d)</h2>`, len(result.Plugins))
		w(`<div class="plugin-grid">`)
		for _, p := range result.Plugins {
			ver := p.Version
			if ver == "" {
				ver = "unknown"
			}
			w(`<div class="plugin-card"><span class="name">%s</span> <span class="ver">v%s</span> <span class="code">%s</span></div>`,
				html.EscapeString(p.Name), html.EscapeString(ver), p.Type)
		}
		w(`</div>`)
	}

	// Integrity
	if result.IntegrityResult.Checked > 0 {
		ir := result.IntegrityResult
		w(`<h2>Core File Integrity</h2>`)
		w(`<div class="section">`)
		w(`<p>Checked %d core files`, ir.Checked)
		if len(ir.Modified) > 0 {
			w(` — <strong style="color:#f85149">%d modified</strong>`, len(ir.Modified))
		}
		if len(ir.Unknown) > 0 {
			w(` — <strong style="color:#e3b341">%d unknown</strong>`, len(ir.Unknown))
		}
		w(`</p></div>`)
	}

	// File scan findings
	writeHTMLFindingsTable(w, "File Scan Findings", result.Findings)
	writeHTMLFindingsTable(w, "Database Findings", result.DBFindings)
	writeHTMLFindingsTable(w, "Permission Findings", result.PermissionFindings)
	writeHTMLFindingsTable(w, "Integrity Findings", result.IntegrityFindings)
	writeHTMLFindingsTable(w, "YARA Findings", result.YaraFindings)
	writeHTMLFindingsTable(w, "Access Log Findings", result.LogFindings)

	// Suspicious files
	if len(result.SuspiciousFiles) > 0 {
		w(`<h2>Suspicious Files</h2>`)
		w(`<table><tr><th>Severity</th><th>File</th><th>Reason</th></tr>`)
		for _, sf := range result.SuspiciousFiles {
			w(`<tr><td><span class="sev %s">%s</span></td><td class="code">%s</td><td>%s</td></tr>`,
				sf.Severity, sf.Severity, html.EscapeString(sf.File), html.EscapeString(sf.Reason))
		}
		w(`</table>`)
	}

	// Suspicious IPs
	if len(result.SuspiciousIPs) > 0 {
		w(`<h2>Suspicious IPs</h2>`)
		w(`<table><tr><th>IP</th><th>Hits</th><th>Patterns</th></tr>`)
		for _, ip := range result.SuspiciousIPs {
			w(`<tr><td class="code">%s</td><td>%d</td><td>%s</td></tr>`,
				html.EscapeString(ip.IP), ip.HitCount, html.EscapeString(strings.Join(ip.PatternsMatched, ", ")))
		}
		w(`</table>`)
	}

	// Timeline
	if len(result.Timeline) > 0 {
		w(`<h2>Infection Timeline</h2>`)
		for _, e := range result.Timeline {
			ts := e.Timestamp
			if len(ts) > 19 {
				ts = ts[:19]
			}
			w(`<div class="timeline-item"><span class="ts">%s</span><span><span class="sev %s">%s</span> %s</span></div>`,
				html.EscapeString(ts), e.Severity, e.Type, html.EscapeString(e.Description))
		}
	}

	// Footer
	w(`<div class="footer">`)
	w(`Generated by AN4SCAN v4.0 on %s`, time.Now().Format("2006-01-02 15:04:05"))
	w(`</div>`)
	w(`</div></body></html>`)

	return nil
}

func writeHTMLFindingsTable(w func(string, ...interface{}), title string, findings []Finding) {
	if len(findings) == 0 {
		return
	}
	w(`<h2>%s (%d)</h2>`, title, len(findings))
	w(`<table><tr><th>Severity</th><th>ID</th><th>File</th><th>Description</th><th>Detail</th></tr>`)
	for _, f := range findings {
		line := ""
		if f.LineNumber > 0 {
			line = fmt.Sprintf(":%d", f.LineNumber)
		}
		content := f.LineContent
		if len(content) > 100 {
			content = content[:100] + "..."
		}
		w(`<tr><td><span class="sev %s">%s</span></td><td>%s</td><td class="code">%s%s</td><td>%s</td><td class="code">%s</td></tr>`,
			f.Severity, f.Severity, html.EscapeString(f.SignatureID),
			html.EscapeString(f.FilePath), line,
			html.EscapeString(f.Description), html.EscapeString(content))
	}
	w(`</table>`)
}
