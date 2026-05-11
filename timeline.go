package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

var (
	tsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`),
		regexp.MustCompile(`Modified:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`),
		regexp.MustCompile(`Created:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`),
	}
	logTsPattern = regexp.MustCompile(`\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})`)
)

func extractTimestamp(text string) string {
	for _, re := range tsPatterns {
		m := re.FindStringSubmatch(text)
		if m != nil {
			t, err := time.Parse("2006-01-02 15:04:05", m[1])
			if err == nil {
				return t.Format(time.RFC3339)
			}
		}
	}
	return ""
}

func extractLogTimestamp(text string) string {
	m := logTsPattern.FindStringSubmatch(text)
	if m != nil {
		t, err := time.Parse("02/Jan/2006:15:04:05", m[1])
		if err == nil {
			return t.Format(time.RFC3339)
		}
	}
	return extractTimestamp(text)
}

func buildTimeline(root string, result *ScanResult) []TimelineEvent {
	var events []TimelineEvent

	// Mtime findings
	for _, f := range result.MtimeFindings {
		if ts := extractTimestamp(f.LineContent); ts != "" {
			events = append(events, TimelineEvent{
				Timestamp: ts, Type: "file_modified", Severity: f.Severity,
				Description: f.Description, File: f.FilePath, SignatureID: f.SignatureID,
			})
		}
	}

	// Malicious files
	seen := make(map[string]bool)
	for _, f := range result.Findings {
		if (f.Severity == CRITICAL || f.Severity == HIGH) && !seen[f.FilePath] {
			seen[f.FilePath] = true
			fpath := filepath.Join(root, f.FilePath)
			info, err := os.Stat(fpath)
			if err != nil {
				continue
			}
			mtime := info.ModTime()
			events = append(events, TimelineEvent{
				Timestamp:   mtime.Format(time.RFC3339),
				Type:        "malware_file",
				Severity:    f.Severity,
				Description: "Malware detected: " + f.Description,
				File:        f.FilePath,
				SignatureID: f.SignatureID,
				Extra:       "mtime=" + mtime.Format("2006-01-02 15:04:05"),
			})
		}
	}

	// Log findings
	for _, f := range result.LogFindings {
		if ts := extractLogTimestamp(f.LineContent); ts != "" {
			events = append(events, TimelineEvent{
				Timestamp: ts, Type: "exploit_attempt", Severity: f.Severity,
				Description: f.Description, File: f.FilePath, SignatureID: f.SignatureID,
			})
		}
	}

	// DB admin events
	for _, f := range result.DBFindings {
		if f.FilePath == "DB:admin_user" {
			if ts := extractTimestamp(f.LineContent); ts != "" {
				events = append(events, TimelineEvent{
					Timestamp: ts, Type: "suspicious_admin", Severity: f.Severity,
					Description: f.Description, File: f.FilePath, SignatureID: f.SignatureID,
				})
			}
		}
	}

	// Reference: composer.lock
	lockPath := filepath.Join(root, "composer.lock")
	if info, err := os.Stat(lockPath); err == nil {
		events = append(events, TimelineEvent{
			Timestamp:   info.ModTime().Format(time.RFC3339),
			Type:        "reference",
			Severity:    INFO,
			Description: "Last composer update (reference point)",
			File:        "composer.lock",
			SignatureID: "REF",
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})

	return events
}
