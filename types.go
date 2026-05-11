package main

// Severity levels
const (
	CRITICAL = "CRITICAL"
	HIGH     = "HIGH"
	MEDIUM   = "MEDIUM"
	LOW      = "LOW"
	INFO     = "INFO"
)

var severityOrder = map[string]int{
	CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
}

var severityColors = map[string]string{
	CRITICAL: "\033[91;1m",
	HIGH:     "\033[91m",
	MEDIUM:   "\033[93m",
	LOW:      "\033[96m",
	INFO:     "\033[90m",
}

const (
	Reset = "\033[0m"
	Bold  = "\033[1m"
	Dim   = "\033[2m"
)

const MaxFileSize = 5 * 1024 * 1024

// Finding represents a single scan finding.
type Finding struct {
	FilePath    string `json:"file_path"`
	SignatureID string `json:"signature_id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	LineNumber  int    `json:"line_number"`
	LineContent string `json:"line_content"`
	Context     string `json:"context,omitempty"`
}

// SuspiciousFile represents a file with a suspicious name/path.
type SuspiciousFile struct {
	File     string `json:"file"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// ScanResult holds all results from a scan.
type ScanResult struct {
	ScanPath           string            `json:"scan_path"`
	StartTime          string            `json:"start_time"`
	EndTime            string            `json:"end_time"`
	DurationSeconds    float64           `json:"duration_seconds"`
	TotalFilesScanned  int               `json:"total_files_scanned"`
	Findings           []Finding         `json:"findings"`
	SuspiciousFiles    []SuspiciousFile  `json:"suspicious_files"`
	DBFindings         []Finding         `json:"db_findings"`
	PermissionFindings []Finding         `json:"permission_findings"`
	MtimeFindings      []Finding         `json:"mtime_findings"`
	YaraFindings       []Finding         `json:"yara_findings"`
	LogFindings        []Finding         `json:"log_findings"`
	CMSInfo            CMSInfo           `json:"cms_info"`
	Plugins            []PluginInfo      `json:"plugins,omitempty"`
	PluginFindings     []PluginFinding   `json:"plugin_findings,omitempty"`
	IntegrityResult    IntegrityResult   `json:"integrity_result,omitempty"`
	IntegrityFindings  []Finding         `json:"integrity_findings,omitempty"`
	VersionInfo        map[string]string `json:"version_info"`
	CVEFindings        []Finding         `json:"cve_findings"`
	Timeline           []TimelineEvent   `json:"timeline"`
	SuspiciousIPs      []SuspiciousIP    `json:"suspicious_ips"`
	Summary            ScanSummary       `json:"summary"`
}

// TimelineEvent represents an event in the infection timeline.
type TimelineEvent struct {
	Timestamp   string `json:"timestamp"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	File        string `json:"file"`
	SignatureID string `json:"signature_id"`
	Extra       string `json:"extra,omitempty"`
}

// SuspiciousIP represents an IP with suspicious activity.
type SuspiciousIP struct {
	IP              string   `json:"ip"`
	HitCount        int      `json:"hit_count"`
	PatternsMatched []string `json:"patterns_matched"`
	SamplePaths     []string `json:"sample_paths"`
}

// ScanSummary holds summary statistics.
type ScanSummary struct {
	TotalFindings       int            `json:"total_findings"`
	TotalSuspiciousFiles int           `json:"total_suspicious_files"`
	AffectedFiles       int            `json:"affected_files"`
	BySeverity          map[string]int `json:"by_severity"`
	ByCategory          map[string]int `json:"by_category"`
	Modules             map[string]int `json:"modules"`
}

// Signature definition types
type SignatureDef struct {
	ID          string
	Severity    string
	Category    string
	Description string
	Pattern     string
	Extensions  []string // nil means all
}

type DBSignatureDef struct {
	ID          string
	Severity    string
	Category    string
	Description string
	Pattern     string
}

type SuspiciousFilenameDef struct {
	Pattern  string
	Severity string
	Reason   string
}

type LogExploitPatternDef struct {
	ID          string
	Severity    string
	Category    string
	Description string
	URLPattern  string
	BodyPattern string // empty means none
}

type CVEDef struct {
	AffectedUpTo string
	CVEID        string
	Severity     string
	Description  string
	Patch        string
}

type YaraRulesetDef struct {
	Name        string
	Description string
	URL         string
	Strip       int
	Globs       []string
}
