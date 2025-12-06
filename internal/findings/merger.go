package findings

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// Merger handles deduplication and merging of findings
type Merger struct{}

// NewMerger creates a new findings merger
func NewMerger() *Merger {
	return &Merger{}
}

// Merge combines findings from multiple sources and removes duplicates
func (m *Merger) Merge(findingGroups ...[]types.Finding) []types.Finding {
	// Flatten all findings
	allFindings := make([]types.Finding, 0)
	for _, group := range findingGroups {
		allFindings = append(allFindings, group...)
	}
	
	// Generate IDs for findings
	for i := range allFindings {
		allFindings[i].ID = m.generateID(&allFindings[i])
	}
	
	// Deduplicate based on similarity
	deduplicated := m.deduplicate(allFindings)
	
	// Sort by severity and file path
	sort.Slice(deduplicated, func(i, j int) bool {
		// First sort by severity
		if deduplicated[i].Severity != deduplicated[j].Severity {
			return severityValue(deduplicated[i].Severity) > severityValue(deduplicated[j].Severity)
		}
		// Then by file path
		if deduplicated[i].FilePath != deduplicated[j].FilePath {
			return deduplicated[i].FilePath < deduplicated[j].FilePath
		}
		// Finally by line number
		return deduplicated[i].StartLine < deduplicated[j].StartLine
	})
	
	return deduplicated
}

// deduplicate removes duplicate findings
func (m *Merger) deduplicate(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	result := make([]types.Finding, 0)
	
	for _, finding := range findings {
		// Create a similarity key
		key := m.similarityKey(&finding)
		
		if !seen[key] {
			seen[key] = true
			result = append(result, finding)
		} else {
			// If we've seen this before, try to merge information
			for i := range result {
				if m.similarityKey(&result[i]) == key {
					result[i] = m.mergeSimilarFindings(result[i], finding)
					break
				}
			}
		}
	}
	
	return result
}

// similarityKey creates a key for identifying similar findings
func (m *Merger) similarityKey(f *types.Finding) string {
	// Findings are similar if they have the same file, similar lines, and similar title
	title := strings.ToLower(strings.TrimSpace(f.Title))
	return fmt.Sprintf("%s:%d-%d:%s", f.FilePath, f.StartLine/5*5, f.EndLine/5*5, title)
}

// mergeSimilarFindings combines information from similar findings
func (m *Merger) mergeSimilarFindings(existing, new types.Finding) types.Finding {
	// Prefer LLM findings for description and recommendation
	if new.Source == types.SourceLLM && existing.Source != types.SourceLLM {
		if existing.Description == "" {
			existing.Description = new.Description
		} else {
			existing.Description = new.Description + "\n\nStatic Analysis: " + existing.Description
		}
		if existing.Recommendation == "" {
			existing.Recommendation = new.Recommendation
		}
	}
	
	// Combine sources
	if new.Source != existing.Source {
		existing.RawOutput += fmt.Sprintf("\n[Also detected by %s]", new.Source)
	}
	
	// Use higher severity
	if severityValue(new.Severity) > severityValue(existing.Severity) {
		existing.Severity = new.Severity
	}
	
	// Update OWASP ID if missing
	if existing.OWASPID == "" && new.OWASPID != "" {
		existing.OWASPID = new.OWASPID
	}
	
	// Update CWE if missing
	if existing.CWE == "" && new.CWE != "" {
		existing.CWE = new.CWE
	}
	
	return existing
}

// generateID creates a unique ID for a finding
func (m *Merger) generateID(f *types.Finding) string {
	data := fmt.Sprintf("%s:%d:%d:%s:%s",
		f.FilePath, f.StartLine, f.EndLine, f.Title, f.Source)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// severityValue returns a numeric value for severity (higher = more severe)
func severityValue(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// FilterByFiles filters findings to only include specified files
func FilterByFiles(findings []types.Finding, files []string) []types.Finding {
	if len(files) == 0 {
		return findings
	}
	
	fileSet := make(map[string]bool)
	for _, f := range files {
		fileSet[f] = true
	}
	
	filtered := make([]types.Finding, 0)
	for _, finding := range findings {
		if fileSet[finding.FilePath] {
			filtered = append(filtered, finding)
		}
	}
	
	return filtered
}

// FilterBySeverity filters findings by minimum severity
func FilterBySeverity(findings []types.Finding, minSeverity types.Severity) []types.Finding {
	minValue := severityValue(minSeverity)
	
	filtered := make([]types.Finding, 0)
	for _, finding := range findings {
		if severityValue(finding.Severity) >= minValue {
			filtered = append(filtered, finding)
		}
	}
	
	return filtered
}

// GroupByFile groups findings by file path
func GroupByFile(findings []types.Finding) map[string][]types.Finding {
	groups := make(map[string][]types.Finding)
	
	for _, finding := range findings {
		groups[finding.FilePath] = append(groups[finding.FilePath], finding)
	}
	
	return groups
}

// GroupBySeverity groups findings by severity
func GroupBySeverity(findings []types.Finding) map[types.Severity][]types.Finding {
	groups := make(map[types.Severity][]types.Finding)
	
	for _, finding := range findings {
		groups[finding.Severity] = append(groups[finding.Severity], finding)
	}
	
	return groups
}

// CountBySeverity returns counts of findings by severity
func CountBySeverity(findings []types.Finding) map[types.Severity]int {
	counts := make(map[types.Severity]int)
	
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	
	return counts
}
