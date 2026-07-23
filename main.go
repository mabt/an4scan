package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var version = "dev"

// printFlagsOneLine prints each flag as "  -name<type>   description" on a
// single line, with descriptions aligned. Replaces flag.PrintDefaults() which
// wraps to two lines per flag.
func printFlagsOneLine() {
	type row struct{ name, desc string }
	var rows []row
	width := 0
	flag.VisitAll(func(f *flag.Flag) {
		name := "-" + f.Name
		if t, _ := flag.UnquoteUsage(f); t != "" {
			name += " " + t
		}
		if len(name) > width {
			width = len(name)
		}
		rows = append(rows, row{name, f.Usage})
	})
	for _, r := range rows {
		fmt.Fprintf(os.Stderr, "  %-*s   %s\n", width, r.name, r.desc)
	}
}

func main() {
	// Scan modules
	flagDB := flag.Bool("db", true, "Scan database for injected malware")
	flagMtime := flag.Bool("mtime", true, "Detect recently modified core files + integrity check")
	flagMtimeDays := flag.Int("mtime-days", 7, "Days window for --mtime")
	flagPerms := flag.Bool("permissions", true, "Check file permissions (world-writable, SUID/SGID)")
	flagVersion := flag.Bool("version", true, "Detect Magento version and check known CVEs")
	flagLogs := flag.Bool("logs", false, "Analyze access logs for exploit attempts (off by default; can be slow on large/shared logs)")
	flagLogPath := flag.String("log-path", "", "Comma-separated path(s) to access log files")
	flagYara := flag.Bool("yara", true, "Enable YARA scanning")
	flagYaraRules := flag.String("yara-rules", "", "Path to additional YARA rules file or directory")
	flagPlugins := flag.Bool("plugins", true, "Scan plugins/modules for known vulnerabilities")
	flagIntegrity := flag.Bool("integrity", true, "Check core file integrity (WP: uses wordpress.org checksums)")
	flagProcesses := flag.Bool("processes", true, "Scan running processes for malware (reverse shells, miners, rootkits)")
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
	flagNoUpdate := flag.Bool("no-update", false, "Skip automatic YARA ruleset update")
	flagNice := flag.Bool("nice", false, "Gentle scan: lowest CPU/disk priority + 1 worker (for production servers)")
	flagNoCache := flag.Bool("no-cache", false, "Disable incremental scan cache (rescan all files)")
	flagCacheDir := flag.String("cache-dir", "", "Base directory for the incremental cache (default: outside the scanned tree — /var/lib/an4scan/cache as root, else ~/.cache/an4scan)")

	// Automation
	flagCron := flag.Bool("cron", false, "Cron mode: silent, only report findings NEW since last scan")
	flagWebhook := flag.String("webhook", "", "Webhook URL to POST new findings to (used with --cron)")
	flagQuarantine := flag.Bool("quarantine", false, "List confirmed-malware files to quarantine (dry-run)")
	flagForce := flag.Bool("force", false, "Apply quarantine moves (used with --quarantine)")

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
						"html": true, "diff": true, "webhook": true, "cache-dir": true,
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
		fmt.Fprintf(os.Stderr, `AN4SCAN %s — CMS Malware Scanner

Usage: %s [flags] <path>

Examples:
  %s /var/www/html                            # scan (all modules enabled)
  %s /var/www/html --deep                     # include suspicions
  %s /var/www/html -q                         # summary only
  %s /var/www/html -j > report.json           # JSON export
  %s /var/www/html --html report.html         # HTML report
  %s --update                                 # download YARA rulesets
  %s --status                                 # show installed rulesets

Flags:
`, version, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		printFlagsOneLine()
	}

	// Reorder args: move positional path arg to end so flags work anywhere
	reorderedArgs := reorderArgs(os.Args[1:])
	flag.CommandLine.Parse(reorderedArgs)

	// Cron mode: silent scan, alert only on new findings
	if *flagCron {
		*flagQuiet = true
	}

	// Gentle mode: lowest CPU/IO priority, single worker unless -w given
	if *flagNice {
		setLowPriority()
		workersSet := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "workers" || f.Name == "w" {
				workersSet = true
			}
		})
		if !workersSet {
			*flagWorkers = 1
		}
	}

	// Standalone commands
	if *flagUpdate {
		fmt.Printf("\n%s  AN4SCAN %s — YARA Ruleset Updater%s\n\n", Bold, version, Reset)
		yaraUpdate(*flagVerbose)
		fmt.Println()
		yaraShowStatus()
		fmt.Println()
		os.Exit(0)
	}

	if *flagStatus {
		fmt.Printf("\n%s  AN4SCAN %s — YARA Ruleset Status%s\n\n", Bold, version, Reset)
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
	// Resolve symlinks so WalkDir traverses the real directory
	scanPath, err = filepath.EvalSymlinks(scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
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
		*flagProcesses = true
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

	// Build a template scanner with all flags (used for both single and multi-site)
	tmpl := NewScanner(scanPath)
	tmpl.Workers = *flagWorkers
	tmpl.MinSeverity = minSeverity
	tmpl.Whitelist = whitelist
	tmpl.JSONOutput = *flagJSON
	tmpl.Verbose = *flagVerbose
	tmpl.Quiet = *flagQuiet
	tmpl.ScanDB = *flagDB
	tmpl.CheckMtime = *flagMtime
	tmpl.MtimeDays = *flagMtimeDays
	tmpl.CheckPermissions = *flagPerms
	tmpl.UseYara = *flagYara
	tmpl.YaraRulesPath = *flagYaraRules
	tmpl.NoAutoUpdate = *flagNoUpdate
	tmpl.NoCache = *flagNoCache
	tmpl.CacheDir = *flagCacheDir
	tmpl.CheckVersion = *flagVersion
	tmpl.AnalyzeLogs = *flagLogs
	tmpl.LogPaths = logPaths
	tmpl.CheckPlugins = *flagPlugins
	tmpl.CheckIntegrity = *flagIntegrity
	tmpl.CheckProcesses = *flagProcesses
	tmpl.HTMLOutput = *flagHTML
	tmpl.DiffPath = *flagDiff
	tmpl.SaveScan = *flagSave

	// Discover sites: if path is a CMS root, single site. Otherwise, find all CMS sites.
	sites := discoverSites(scanPath, 3)

	if len(sites) == 0 {
		fmt.Fprintf(os.Stderr, "No CMS installation detected under %s\n", scanPath)
		os.Exit(1)
	}

	// Single site mode
	if len(sites) == 1 {
		scanner := NewScanner(sites[0].Path)
		*scanner = *tmpl
		scanner.Path = sites[0].Path
		scanner.Init()

		result := scanner.Scan()

		if *flagCron {
			os.Exit(runCronScan(result, sites[0].Path, *flagWebhook))
		}

		printReport(result, *flagJSON, *flagQuiet)

		if *flagQuarantine {
			quarantineFindings(result, sites[0].Path, *flagForce)
		}

		if *flagHTML != "" {
			if err := writeHTMLReport(result, *flagHTML); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
			} else if !*flagQuiet {
				fmt.Printf("  HTML report saved to: %s\n\n", *flagHTML)
			}
		}

		if *flagSave {
			savedPath, err := saveScanResult(result, sites[0].Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error saving scan: %v\n", err)
			} else if !*flagQuiet {
				fmt.Printf("  Scan saved to: %s\n\n", savedPath)
			}
		}

		if *flagDiff != "" {
			diffPath := *flagDiff
			if diffPath == "auto" {
				diffPath = findPreviousScan(sites[0].Path)
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

		if result.Summary.BySeverity[CRITICAL] > 0 {
			os.Exit(2)
		}
		if result.Summary.BySeverity[HIGH] > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Multi-site mode
	multiResult := runMultiSiteScan(sites, tmpl)

	if *flagCron {
		exitCode := 0
		for _, site := range multiResult.Sites {
			if site.ScanResult == nil {
				continue
			}
			if code := runCronScan(site.ScanResult, site.Path, *flagWebhook); code > exitCode {
				exitCode = code
			}
		}
		os.Exit(exitCode)
	}

	printMultiSiteReport(multiResult, *flagJSON)

	if *flagQuarantine {
		for _, site := range multiResult.Sites {
			if site.ScanResult != nil {
				quarantineFindings(site.ScanResult, site.Path, *flagForce)
			}
		}
	}

	if *flagHTML != "" {
		writeMultiSiteHTML(multiResult, *flagHTML)
		if !*flagQuiet {
			fmt.Printf("  HTML reports saved with prefix: %s\n\n", *flagHTML)
		}
	}

	if multiResult.Summary.BySeverity[CRITICAL] > 0 {
		os.Exit(2)
	}
	if multiResult.Summary.BySeverity[HIGH] > 0 {
		os.Exit(1)
	}
}
