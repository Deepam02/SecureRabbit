package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deepam02/securerabbit/internal/config"
	"github.com/deepam02/securerabbit/internal/reporter"
	"github.com/deepam02/securerabbit/internal/scanner"
	"github.com/deepam02/securerabbit/internal/types"
	"github.com/spf13/cobra"
)

var (
	cfgFile      string
	projectPath  string
	scanMode     string
	llmProvider  string
	staticOnly   bool
	outputFormat string
	outputPath   string
)

var rootCmd = &cobra.Command{
	Use:   "securerabbit",
	Short: "SecureRabbit - Security Code Analysis Tool",
	Long: `SecureRabbit is a hybrid security analysis tool that combines 
static analysis with LLM-powered deep reasoning to detect OWASP Top 10 
vulnerabilities in your code.`,
	Version: "1.0.0",
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for security vulnerabilities",
	Long: `Scan performs security analysis on a project using static rules 
and optionally LLM analysis. Supports deep, smart, and diff scan modes.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	cobra.OnInitialize(initConfig)
	
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .securerabbit.yml)")
	
	// Scan command flags
	scanCmd.Flags().StringVar(&projectPath, "path", ".", "path to project to scan")
	scanCmd.Flags().StringVar(&scanMode, "mode", "smart", "scan mode: deep, smart, or diff")
	scanCmd.Flags().StringVar(&llmProvider, "llm-provider", "", "LLM provider: openai, anthropic, or gemini")
	scanCmd.Flags().BoolVar(&staticOnly, "static-only", false, "run static analysis only, skip LLM")
	scanCmd.Flags().StringVar(&outputFormat, "format", "", "output format: json or markdown")
	scanCmd.Flags().StringVar(&outputPath, "output", "", "output file path")
	
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
}

func initConfig() {
	// Configuration initialization is handled per command
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine project path
	if len(args) > 0 {
		projectPath = args[0]
	}
	
	// Get absolute path
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("invalid project path: %w", err)
	}
	projectPath = absPath
	
	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	
	// Override config with CLI flags
	if scanMode != "" {
		cfg.Scan.Mode = types.ScanMode(scanMode)
	}
	if llmProvider != "" {
		cfg.LLM.Provider = llmProvider
	}
	if staticOnly {
		cfg.LLM.Provider = "" // Disable LLM
	}
	if outputFormat != "" {
		cfg.Output.Format = outputFormat
	}
	if outputPath != "" {
		cfg.Output.Path = outputPath
	}
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Display scan info
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("  SecureRabbit - Security Code Analysis")
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Printf("Project:  %s\n", projectPath)
	fmt.Printf("Mode:     %s\n", cfg.Scan.Mode)
	if cfg.LLM.Provider != "" {
		fmt.Printf("LLM:      %s (%s)\n", cfg.LLM.Provider, cfg.LLM.Model)
	} else {
		fmt.Println("LLM:      Disabled (Static Analysis Only)")
	}
	fmt.Printf("Output:   %s (%s)\n", cfg.Output.Format, cfg.Output.Path)
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println()
	
	// Get project info
	projInfo, err := scanner.GetProjectInfo(projectPath)
	if err != nil {
		return fmt.Errorf("failed to analyze project: %w", err)
	}
	
	if gitRepo, ok := projInfo["is_git_repo"].(bool); ok && gitRepo {
		if branch, ok := projInfo["git_branch"].(string); ok {
			fmt.Printf("Git repository detected (branch: %s)\n\n", branch)
		}
	}
	
	// Create scanner
	fmt.Println("Initializing scanner...")
	scnr, err := scanner.NewScanner(cfg, projectPath)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}
	
	// Run scan
	ctx := context.Background()
	var result *types.ScanResult
	
	if cfg.Scan.Mode == types.ScanModeDiff {
		result, err = scnr.ScanDiff(ctx, projectPath)
	} else {
		result, err = scnr.Scan(ctx, projectPath)
	}
	
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	
	// Generate report
	fmt.Println("\nGenerating report...")
	rep := reporter.NewReporter(cfg.Output.Format, cfg.Output.Path)
	if err := rep.Generate(result); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}
	
	// Display summary
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("  Scan Complete!")
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Printf("Files Scanned:    %d\n", result.FilesScanned)
	fmt.Printf("Total Findings:   %d\n", result.TotalFindings)
	fmt.Printf("Scan Duration:    %s\n", result.Duration)
	fmt.Printf("Report saved to:  %s\n", cfg.Output.Path)
	fmt.Println("═══════════════════════════════════════════════════")
	
	// Display severity breakdown
	if result.TotalFindings > 0 {
		fmt.Println()
		displaySeveritySummary(result)
	}
	
	return nil
}

func displaySeveritySummary(result *types.ScanResult) {
	counts := make(map[types.Severity]int)
	for _, finding := range result.Findings {
		counts[finding.Severity]++
	}
	
	fmt.Println("Findings by Severity:")
	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}
	
	for _, sev := range severities {
		count := counts[sev]
		if count > 0 {
			emoji := getSeverityEmoji(sev)
			fmt.Printf("  %s %-10s: %d\n", emoji, sev, count)
		}
	}
}

func getSeverityEmoji(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical:
		return "🔴"
	case types.SeverityHigh:
		return "🟠"
	case types.SeverityMedium:
		return "🟡"
	case types.SeverityLow:
		return "🔵"
	case types.SeverityInfo:
		return "⚪"
	default:
		return "⚫"
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("SecureRabbit v1.0.0")
		fmt.Println("Security Code Analysis Tool")
		fmt.Println("https://github.com/deepam02/securerabbit")
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize SecureRabbit configuration",
	Long:  `Create a default .securerabbit.yml configuration file in the current directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := ".securerabbit.yml"
		
		// Check if config already exists
		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("configuration file already exists: %s", configPath)
		}
		
		// Create default config
		defaultConfig := `# SecureRabbit Configuration

scan:
  mode: "smart"              # Options: deep, smart, diff
  languages:
    - go
    - python
    - javascript
  max_concurrency: 4

llm:
  provider: "openai"         # Options: openai, anthropic, gemini
  model: "gpt-4"
  api_key_env: "OPENAI_API_KEY"
  max_tokens: 4096
  temperature: 0.2
  timeout: 60
  max_retries: 3
  enabled_in_smart: true

rules:
  gosec:
    enabled: true
    severity:
      - high
      - medium
    confidence:
      - high
      - medium
  regex:
    enabled: true
  ast:
    enabled: true

output:
  format: "markdown"         # Options: json, markdown
  path: "./securerabbit-report.md"

ignore:
  - "vendor/"
  - "node_modules/"
  - ".git/"
  - "test/"
  - "*_test.go"
`
		
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
		
		fmt.Printf("✓ Created configuration file: %s\n", configPath)
		fmt.Println("\nNext steps:")
		fmt.Println("1. Set your LLM API key in environment variable (e.g., OPENAI_API_KEY)")
		fmt.Println("2. Customize the configuration as needed")
		fmt.Println("3. Run: securerabbit scan")
		
		return nil
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}
