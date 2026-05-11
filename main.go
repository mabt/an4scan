package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Scan modules
	flagDB := flag.Bool("db", false, "Scan database for injected malware")
	flagMtime := flag.Bool("mtime", false, "Detect recently modified core files + integrity check")
	flagMtimeDays := flag.Int("mtime-days", 7, "Days window for --mtime")
	flagPerms := flag.Bool("permissions", false, "Check file permissions (world-writable, SUID/SGID)")
	flagVersion := flag.Bool("version", false, "Detect Magento version and check known CVEs")
	flagLogs := flag.Bool("logs", false, "Analyze access logs for exploit attempts")
	flagLogPath := flag.String("log-path", "", "Comma-separated path(s) to access log files")
	flagYara := flag.Bool("yara", false, "Enable YARA scanning")
	flagYaraRules := flag.String("yara-rules", "", "Path to additional YARA rules file or directory")
	flagPlugins := flag.Bool("plugins", false, "Scan plugins/modules for known vulnerabilities")
	flagIntegrity := flag.Bool("integrity", false, "Check core file integrity (WP: uses wordpress.org checksums)")
	flagAll := flag.Bool("all", false, "Enable all scan modules")
	flagDeep := flag.Bool("deep", false, "Show all findings including suspicions (default: confirmed threats only)")

	// Output
	flagJSON := flag.Bool("json", false, "Output report in JSON format")
	flagOutput := flag.String("output", "", "Write report to file")
	flagHTML := flag.String("html", "", "Write HTML report to file")
	flagQuiet := flag.Bool("quiet", false, "Quiet mode - only show summary line")
	flagDiff := flag.String("diff", "", "Compare with previous scan JSON (or 'auto' for last saved)")
	flagSave := flag.Bool("save", false, "Save scan results for future diffing (in .an4scan/)")
	flagSeverity := flag.String("severity", "", "Override minimum severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	flagVerbose := flag.Bool("verbose", false, "Verbose output (show scan errors)")

	// Tuning
	flagWorkers := flag.Int("workers", 4, "Parallel workers")
	flagWhitelist := flag.String("whitelist", "", "Comma-separated paths to exclude (relative to Magento root)")

	// Ruleset management
	flagUpdate := flag.Bool("update", false, "Download/update community YARA rulesets")
	flagStatus := flag.Bool("status", false, "Show status of installed YARA rulesets")

	// Shorthand aliases
	flag.BoolVar(flagJSON, "j", false, "Output report in JSON format")
	flag.BoolVar(flagQuiet, "q", false, "Quiet mode")
	flag.StringVar(flagSeverity, "s", "", "Override minimum severity filter")
	flag.BoolVar(flagVerbose, "v", false, "Verbose output")
	flag.IntVar(flagWorkers, "w", 4, "Parallel workers")
	flag.StringVar(flagOutput, "o", "", "Write report to file")

	// reorderArgs moves non-flag args to the end so flag.Parse works regardless of order.
	reorderArgs := func(args []string) []string {
		var flags, positional []string
		for i := 0; i < len(args); i++ {
			if strings.HasPrefix(args[i], "-") {
				flags = append(flags, args[i])
				// Check if this flag takes a value (has = or next arg is value)
				if !strings.Contains(args[i], "=") {
					// Check if it's a flag that takes a value
					name := strings.TrimLeft(args[i], "-")
					needsVal := map[string]bool{
						"severity": true, "s": true, "workers": true, "w": true,
						"output": true, "o": true, "whitelist": true,
						"log-path": true, "yara-rules": true, "mtime-days": true,
						"html": true, "diff": true,
					}
					if needsVal[name] && i+1 < len(args) {
						i++
						flags = append(flags, args[i])
					}
				}
			} else {
				positional = append(positional, args[i])
			}
		}
		return append(flags, positional...)
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `AN4SCAN - Magento 2 Malware Scanner (Go)

Usage: %s [flags] <path>

Examples:
  %s /var/www/magento2                        # scan confirmed threats only
  %s /var/www/magento2 --deep                 # include suspicions
  %s /var/www/magento2 --all                  # all modules
  %s /var/www/magento2 --all --deep           # full audit
  %s /var/www/magento2 --all -q               # summary only
  %s /var/www/magento2 -j > report.json       # JSON export
  %s --update                                 # download YARA rulesets
  %s --status                                 # show installed rulesets

Flags:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}

	// Reorder args: move positional path arg to end so flags work anywhere
	reorderedArgs := reorderArgs(os.Args[1:])
	flag.CommandLine.Parse(reorderedArgs)

	// Standalone commands
	if *flagUpdate {
		fmt.Printf("\n%s  AN4SCAN — YARA Ruleset Updater%s\n\n", Bold, Reset)
		yaraUpdate(*flagVerbose)
		fmt.Println()
		yaraShowStatus()
		fmt.Println()
		os.Exit(0)
	}

	if *flagStatus {
		fmt.Printf("\n%s  AN4SCAN — YARA Ruleset Status%s\n\n", Bold, Reset)
		yaraShowStatus()
		fmt.Println()
		os.Exit(0)
	}

	// Path is required for scanning
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: path is required for scanning")
		flag.Usage()
		os.Exit(1)
	}

	scanPath, err := filepath.Abs(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(scanPath)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: path does not exist or is not a directory: %s\n", scanPath)
		os.Exit(1)
	}

	// --all enables everything
	if *flagAll {
		*flagDB = true
		*flagPerms = true
		*flagMtime = true
		*flagYara = true
		*flagVersion = true
		*flagLogs = true
		*flagPlugins = true
		*flagIntegrity = true
	}

	// Severity
	minSeverity := HIGH
	if *flagSeverity != "" {
		minSeverity = strings.ToUpper(*flagSeverity)
	} else if *flagDeep {
		minSeverity = LOW
	}

	// Whitelist
	var whitelist []string
	if *flagWhitelist != "" {
		whitelist = strings.Split(*flagWhitelist, ",")
	}

	// Log paths
	var logPaths []string
	if *flagLogPath != "" {
		logPaths = strings.Split(*flagLogPath, ",")
	}

	// Redirect output to file if needed
	if *flagOutput != "" {
		f, err := os.Create(*flagOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		os.Stdout = f
	}

	scanner := NewScanner(scanPath)
	scanner.Workers = *flagWorkers
	scanner.MinSeverity = minSeverity
	scanner.Whitelist = whitelist
	scanner.JSONOutput = *flagJSON
	scanner.Verbose = *flagVerbose
	scanner.Quiet = *flagQuiet
	scanner.ScanDB = *flagDB
	scanner.CheckMtime = *flagMtime
	scanner.MtimeDays = *flagMtimeDays
	scanner.CheckPermissions = *flagPerms
	scanner.UseYara = *flagYara
	scanner.YaraRulesPath = *flagYaraRules
	scanner.CheckVersion = *flagVersion
	scanner.AnalyzeLogs = *flagLogs
	scanner.LogPaths = logPaths
	scanner.CheckPlugins = *flagPlugins
	scanner.CheckIntegrity = *flagIntegrity
	scanner.HTMLOutput = *flagHTML
	scanner.DiffPath = *flagDiff
	scanner.SaveScan = *flagSave
	scanner.Init()

	result := scanner.Scan()
	printReport(result, *flagJSON, *flagQuiet)

	// HTML report
	if *flagHTML != "" {
		if err := writeHTMLReport(result, *flagHTML); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
		} else {
			fmt.Printf("  HTML report saved to: %s\n\n", *flagHTML)
		}
	}

	// Save scan for future diffing
	if *flagSave {
		savedPath, err := saveScanResult(result, scanPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving scan: %v\n", err)
		} else {
			fmt.Printf("  Scan saved to: %s\n\n", savedPath)
		}
	}

	// Diff with previous scan
	if *flagDiff != "" {
		diffPath := *flagDiff
		if diffPath == "auto" {
			diffPath = findPreviousScan(scanPath)
			if diffPath == "" {
				fmt.Fprintln(os.Stderr, "No previous scan found. Run with -save first.")
			}
		}
		if diffPath != "" {
			diff, err := diffScans(result, diffPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error computing diff: %v\n", err)
			} else {
				printDiffReport(diff)
			}
		}
	}

	// Exit code based on severity
	if result.Summary.BySeverity[CRITICAL] > 0 {
		os.Exit(2)
	}
	if result.Summary.BySeverity[HIGH] > 0 {
		os.Exit(1)
	}
}
