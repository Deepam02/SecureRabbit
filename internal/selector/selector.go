package selector

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// Selector determines which files should be analyzed by LLM in smart mode
type Selector struct {
	projectPath string
	ignorePaths []string
}

// NewSelector creates a new file selector
func NewSelector(projectPath string, ignorePaths []string) *Selector {
	return &Selector{
		projectPath: projectPath,
		ignorePaths: ignorePaths,
	}
}

// SelectFiles returns files that should be analyzed based on scan mode
func (s *Selector) SelectFiles(ctx context.Context, mode types.ScanMode, languages []string, staticFindings []types.Finding) ([]types.FileInfo, error) {
	switch mode {
	case types.ScanModeDeep:
		return s.selectAllFiles(ctx, languages)
	case types.ScanModeSmart:
		return s.selectHighRiskFiles(ctx, languages, staticFindings)
	case types.ScanModeDiff:
		// Diff mode selection is handled by git module
		return []types.FileInfo{}, nil
	default:
		return []types.FileInfo{}, nil
	}
}

// selectAllFiles returns all source files in the project
func (s *Selector) selectAllFiles(ctx context.Context, languages []string) ([]types.FileInfo, error) {
	files := make([]types.FileInfo, 0)
	
	err := filepath.WalkDir(s.projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		// Skip ignored paths
		if s.shouldIgnore(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		// Skip directories
		if d.IsDir() {
			return nil
		}
		
		// Check if file matches target languages
		language := detectLanguage(path)
		if language == "" || !contains(languages, language) {
			return nil
		}
		
		// Calculate file info
		fileInfo := s.analyzeFile(path, language)
		files = append(files, fileInfo)
		
		return nil
	})
	
	return files, err
}

// selectHighRiskFiles returns files that should be prioritized for LLM analysis
func (s *Selector) selectHighRiskFiles(ctx context.Context, languages []string, staticFindings []types.Finding) ([]types.FileInfo, error) {
	allFiles, err := s.selectAllFiles(ctx, languages)
	if err != nil {
		return nil, err
	}
	
	// Calculate risk scores
	for i := range allFiles {
		allFiles[i].RiskScore = s.calculateRiskScore(&allFiles[i], staticFindings)
	}
	
	// Filter high-risk files (risk score > 50)
	highRiskFiles := make([]types.FileInfo, 0)
	for _, file := range allFiles {
		if file.RiskScore > 50.0 {
			highRiskFiles = append(highRiskFiles, file)
		}
	}
	
	return highRiskFiles, nil
}

// analyzeFile creates FileInfo for a single file
func (s *Selector) analyzeFile(path string, language string) types.FileInfo {
	info := types.FileInfo{
		Path:     path,
		Language: language,
	}
	
	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return info
	}
	
	contentStr := string(content)
	contentLower := strings.ToLower(contentStr)
	
	// Count lines of code
	info.LOC = strings.Count(contentStr, "\n") + 1
	
	// Check for security-sensitive keywords
	info.HasCrypto = strings.Contains(contentLower, "crypt") ||
		strings.Contains(contentLower, "cipher") ||
		strings.Contains(contentLower, "encrypt") ||
		strings.Contains(contentLower, "hash")
	
	info.HasDatabase = strings.Contains(contentLower, "sql") ||
		strings.Contains(contentLower, "database") ||
		strings.Contains(contentLower, "query") ||
		strings.Contains(contentLower, "db.")
	
	info.HasAuth = strings.Contains(contentLower, "auth") ||
		strings.Contains(contentLower, "login") ||
		strings.Contains(contentLower, "password") ||
		strings.Contains(contentLower, "token") ||
		strings.Contains(contentLower, "jwt")
	
	return info
}

// calculateRiskScore calculates a risk score for a file
func (s *Selector) calculateRiskScore(file *types.FileInfo, staticFindings []types.Finding) float64 {
	score := 0.0
	
	// Count static findings in this file
	findingCount := 0
	for _, finding := range staticFindings {
		if finding.FilePath == file.Path {
			findingCount++
			// Weight by severity
			switch finding.Severity {
			case types.SeverityCritical:
				score += 30
			case types.SeverityHigh:
				score += 20
			case types.SeverityMedium:
				score += 10
			case types.SeverityLow:
				score += 5
			}
		}
	}
	file.StaticFindings = findingCount
	
	// Add points for security-sensitive code
	if file.HasCrypto {
		score += 15
	}
	if file.HasDatabase {
		score += 20
	}
	if file.HasAuth {
		score += 25
	}
	
	// Add points for risky file names
	fileName := strings.ToLower(filepath.Base(file.Path))
	riskyNames := []string{"auth", "login", "admin", "password", "secret", "key", "token", "credential"}
	for _, risky := range riskyNames {
		if strings.Contains(fileName, risky) {
			score += 10
			break
		}
	}
	
	// Normalize score to 0-100
	if score > 100 {
		score = 100
	}
	
	return score
}

// shouldIgnore checks if a path should be ignored
func (s *Selector) shouldIgnore(path string) bool {
	relPath, err := filepath.Rel(s.projectPath, path)
	if err != nil {
		return false
	}
	
	// Check against ignore patterns
	for _, ignore := range s.ignorePaths {
		ignore = strings.TrimSuffix(ignore, "/")
		if strings.HasPrefix(relPath, ignore) {
			return true
		}
		if matched, _ := filepath.Match(ignore, relPath); matched {
			return true
		}
	}
	
	// Always ignore common directories
	commonIgnores := []string{
		".git", "node_modules", "vendor", ".vscode", ".idea",
		"bin", "obj", "dist", "build", "__pycache__",
	}
	
	for _, ignore := range commonIgnores {
		if strings.Contains(relPath, ignore) {
			return true
		}
	}
	
	return false
}

// detectLanguage detects programming language from file extension
func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	
	languageMap := map[string]string{
		".go":   "go",
		".py":   "python",
		".js":   "javascript",
		".ts":   "typescript",
		".java": "java",
		".c":    "c",
		".cpp":  "cpp",
		".cs":   "csharp",
		".rb":   "ruby",
		".php":  "php",
		".rs":   "rust",
	}
	
	return languageMap[ext]
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
