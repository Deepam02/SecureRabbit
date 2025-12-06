package project

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// GitAnalyzer handles Git-related operations for diff scanning
type GitAnalyzer struct {
	projectPath string
}

// NewGitAnalyzer creates a new Git analyzer
func NewGitAnalyzer(projectPath string) *GitAnalyzer {
	return &GitAnalyzer{
		projectPath: projectPath,
	}
}

// GetChangedFiles returns files changed in the current branch
func (g *GitAnalyzer) GetChangedFiles() ([]types.FileInfo, error) {
	// Get list of changed files
	cmd := exec.Command("git", "diff", "--name-only", "HEAD")
	cmd.Dir = g.projectPath
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %w", err)
	}
	
	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	fileInfos := make([]types.FileInfo, 0, len(files))
	
	for _, file := range files {
		if file == "" {
			continue
		}
		
		fullPath := g.projectPath + "/" + file
		fileInfo := types.FileInfo{
			Path: fullPath,
		}
		fileInfos = append(fileInfos, fileInfo)
	}
	
	return fileInfos, nil
}

// GetChangedLines returns the line ranges changed in a file
func (g *GitAnalyzer) GetChangedLines(filePath string) ([]LineRange, error) {
	// Get diff for specific file
	cmd := exec.Command("git", "diff", "-U0", "HEAD", filePath)
	cmd.Dir = g.projectPath
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get diff: %w", err)
	}
	
	return parseDiffOutput(string(output)), nil
}

// IsGitRepository checks if the project is a Git repository
func (g *GitAnalyzer) IsGitRepository() bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = g.projectPath
	
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	
	err := cmd.Run()
	return err == nil
}

// GetCurrentBranch returns the current Git branch name
func (g *GitAnalyzer) GetCurrentBranch() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = g.projectPath
	
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get current branch: %w", err)
	}
	
	return strings.TrimSpace(string(output)), nil
}

// LineRange represents a range of lines in a file
type LineRange struct {
	Start int
	End   int
}

// parseDiffOutput parses git diff output to extract changed line ranges
func parseDiffOutput(diff string) []LineRange {
	ranges := make([]LineRange, 0)
	lines := strings.Split(diff, "\n")
	
	for _, line := range lines {
		// Look for @@ -old +new @@ format
		if !strings.HasPrefix(line, "@@") {
			continue
		}
		
		// Extract the +start,count part
		parts := strings.Split(line, "@@")
		if len(parts) < 2 {
			continue
		}
		
		rangePart := strings.TrimSpace(parts[1])
		fields := strings.Fields(rangePart)
		
		for _, field := range fields {
			if strings.HasPrefix(field, "+") {
				// Parse +start,count
				rangeStr := strings.TrimPrefix(field, "+")
				var start, count int
				
				if strings.Contains(rangeStr, ",") {
					fmt.Sscanf(rangeStr, "%d,%d", &start, &count)
				} else {
					fmt.Sscanf(rangeStr, "%d", &start)
					count = 1
				}
				
				if count > 0 {
					ranges = append(ranges, LineRange{
						Start: start,
						End:   start + count - 1,
					})
				}
			}
		}
	}
	
	return ranges
}
