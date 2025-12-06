package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/deepam02/securerabbit/internal/config"
	"github.com/deepam02/securerabbit/internal/findings"
	"github.com/deepam02/securerabbit/internal/llm"
	"github.com/deepam02/securerabbit/internal/project"
	"github.com/deepam02/securerabbit/internal/rules"
	"github.com/deepam02/securerabbit/internal/selector"
	"github.com/deepam02/securerabbit/internal/types"
)

// Scanner orchestrates the security scanning workflow
type Scanner struct {
	config       *config.Config
	ruleEngine   *rules.Engine
	llmProvider  llm.LLMProvider
	selector     *selector.Selector
	merger       *findings.Merger
	gitAnalyzer  *project.GitAnalyzer
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config, projectPath string) (*Scanner, error) {
	// Create rule engine
	ruleEngine := rules.NewEngine(
		cfg.Rules.Gosec.Enabled,
		cfg.Rules.Regex.Enabled,
		cfg.Rules.AST.Enabled,
	)
	
	// Create LLM provider if configured
	var llmProvider llm.LLMProvider
	var err error
	if cfg.LLM.Provider != "" {
		llmProvider, err = llm.NewProvider(&cfg.LLM)
		if err != nil {
			return nil, fmt.Errorf("failed to create LLM provider: %w", err)
		}
	}
	
	// Create file selector
	fileSelector := selector.NewSelector(projectPath, cfg.Ignore)
	
	// Create findings merger
	findingsMerger := findings.NewMerger()
	
	// Create git analyzer
	gitAnalyzer := project.NewGitAnalyzer(projectPath)
	
	return &Scanner{
		config:      cfg,
		ruleEngine:  ruleEngine,
		llmProvider: llmProvider,
		selector:    fileSelector,
		merger:      findingsMerger,
		gitAnalyzer: gitAnalyzer,
	}, nil
}

// Scan performs a security scan on the project
func (s *Scanner) Scan(ctx context.Context, projectPath string) (*types.ScanResult, error) {
	startTime := time.Now()
	
	result := &types.ScanResult{
		ProjectPath: projectPath,
		ScanMode:    s.config.Scan.Mode,
		StartTime:   startTime,
		StaticOnly:  s.llmProvider == nil,
	}
	
	if s.llmProvider != nil {
		result.LLMProvider = s.llmProvider.Name()
	}
	
	// Step 1: Run static analysis on all files
	fmt.Println("Running static analysis...")
	staticFindings, filesScanned, err := s.runStaticAnalysis(ctx, projectPath)
	if err != nil {
		return nil, fmt.Errorf("static analysis failed: %w", err)
	}
	result.FilesScanned = filesScanned
	
	fmt.Printf("Static analysis complete. Found %d issues in %d files.\n", len(staticFindings), filesScanned)
	
	// Step 2: Select files for LLM analysis (if not static-only)
	var llmFindings []types.Finding
	if !result.StaticOnly && s.config.Scan.Mode != types.ScanModeDiff {
		fmt.Println("\nSelecting files for LLM analysis...")
		selectedFiles, err := s.selector.SelectFiles(ctx, s.config.Scan.Mode, s.config.Scan.Languages, staticFindings)
		if err != nil {
			return nil, fmt.Errorf("file selection failed: %w", err)
		}
		
		fmt.Printf("Selected %d files for LLM analysis.\n", len(selectedFiles))
		
		// Step 3: Run LLM analysis on selected files
		if len(selectedFiles) > 0 {
			fmt.Println("\nRunning LLM analysis...")
			llmFindings, err = s.runLLMAnalysis(ctx, selectedFiles, staticFindings)
			if err != nil {
				fmt.Printf("Warning: LLM analysis failed: %v\n", err)
				// Continue with static findings only
			} else {
				fmt.Printf("LLM analysis complete. Found %d additional insights.\n", len(llmFindings))
			}
		}
	}
	
	// Step 4: Merge and deduplicate findings
	fmt.Println("\nMerging findings...")
	allFindings := s.merger.Merge(staticFindings, llmFindings)
	result.Findings = allFindings
	result.TotalFindings = len(allFindings)
	
	// Complete the scan
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	
	return result, nil
}

// runStaticAnalysis runs all static analysis rules on the project
func (s *Scanner) runStaticAnalysis(ctx context.Context, projectPath string) ([]types.Finding, int, error) {
	allFindings := make([]types.Finding, 0)
	filesScanned := 0
	
	// Get all source files
	files, err := s.selector.SelectFiles(ctx, types.ScanModeDeep, s.config.Scan.Languages, nil)
	if err != nil {
		return nil, 0, err
	}
	
	// Process files concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.config.Scan.MaxConcurrency)
	
	for _, file := range files {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Analyze file
			fileFindings, err := s.ruleEngine.AnalyzeFile(ctx, filePath)
			if err != nil {
				// Log error but continue
				return
			}
			
			// Add findings
			mu.Lock()
			allFindings = append(allFindings, fileFindings...)
			filesScanned++
			mu.Unlock()
		}(file.Path)
	}
	
	wg.Wait()
	
	return allFindings, filesScanned, nil
}

// runLLMAnalysis runs LLM analysis on selected files
func (s *Scanner) runLLMAnalysis(ctx context.Context, files []types.FileInfo, staticFindings []types.Finding) ([]types.Finding, error) {
	allFindings := make([]types.Finding, 0)
	
	// Process files with rate limiting
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 2) // Limit concurrent LLM calls
	
	for _, file := range files {
		wg.Add(1)
		go func(fileInfo types.FileInfo) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Analyze file with LLM
			fileFindings, err := s.analyzeFileWithLLM(ctx, fileInfo, staticFindings)
			if err != nil {
				// Log error but continue
				fmt.Printf("Warning: LLM analysis failed for %s: %v\n", fileInfo.Path, err)
				return
			}
			
			// Add findings
			mu.Lock()
			allFindings = append(allFindings, fileFindings...)
			mu.Unlock()
		}(file)
	}
	
	wg.Wait()
	
	return allFindings, nil
}

// analyzFileWithLLM analyzes a single file using LLM
func (s *Scanner) analyzeFileWithLLM(ctx context.Context, file types.FileInfo, staticFindings []types.Finding) ([]types.Finding, error) {
	// Read file content
	content, err := os.ReadFile(file.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	
	// Create code chunk
	chunk := types.CodeChunk{
		FilePath:  file.Path,
		Language:  file.Language,
		StartLine: 1,
		EndLine:   strings.Count(string(content), "\n") + 1,
		Content:   string(content),
	}
	
	// Filter static findings for this file
	fileStaticFindings := make([]types.Finding, 0)
	for _, finding := range staticFindings {
		if finding.FilePath == file.Path {
			fileStaticFindings = append(fileStaticFindings, finding)
		}
	}
	chunk.StaticIssues = fileStaticFindings
	
	// Prepare LLM request
	req := llm.LLMRequest{
		CodeChunk:      chunk,
		StaticFindings: fileStaticFindings,
		MaxTokens:      s.config.LLM.MaxTokens,
		Temperature:    s.config.LLM.Temperature,
	}
	
	// Call LLM
	response, err := s.llmProvider.AnalyzeCode(ctx, req)
	if err != nil {
		return nil, err
	}
	
	return response.Findings, nil
}

// ScanDiff performs a scan on git diff changes only
func (s *Scanner) ScanDiff(ctx context.Context, projectPath string) (*types.ScanResult, error) {
	if !s.gitAnalyzer.IsGitRepository() {
		return nil, fmt.Errorf("project is not a git repository")
	}
	
	startTime := time.Now()
	
	result := &types.ScanResult{
		ProjectPath: projectPath,
		ScanMode:    types.ScanModeDiff,
		StartTime:   startTime,
		StaticOnly:  s.llmProvider == nil,
	}
	
	if s.llmProvider != nil {
		result.LLMProvider = s.llmProvider.Name()
	}
	
	// Get changed files
	changedFiles, err := s.gitAnalyzer.GetChangedFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %w", err)
	}
	
	if len(changedFiles) == 0 {
		fmt.Println("No changed files detected.")
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime).String()
		return result, nil
	}
	
	fmt.Printf("Analyzing %d changed files...\n", len(changedFiles))
	
	// Analyze only changed files
	allFindings := make([]types.Finding, 0)
	
	for _, file := range changedFiles {
		// Run static analysis
		fileFindings, err := s.ruleEngine.AnalyzeFile(ctx, file.Path)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, fileFindings...)
		result.FilesScanned++
	}
	
	// Merge findings
	result.Findings = s.merger.Merge(allFindings)
	result.TotalFindings = len(result.Findings)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	
	return result, nil
}

// GetProjectInfo returns information about the project
func GetProjectInfo(projectPath string) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	// Get absolute path
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, err
	}
	info["absolute_path"] = absPath
	
	// Check if directory exists
	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("project path does not exist: %w", err)
	}
	
	if !stat.IsDir() {
		return nil, fmt.Errorf("project path is not a directory")
	}
	
	info["is_directory"] = true
	
	// Check for Git repository
	gitAnalyzer := project.NewGitAnalyzer(absPath)
	info["is_git_repo"] = gitAnalyzer.IsGitRepository()
	
	if info["is_git_repo"].(bool) {
		branch, err := gitAnalyzer.GetCurrentBranch()
		if err == nil {
			info["git_branch"] = branch
		}
	}
	
	return info, nil
}
