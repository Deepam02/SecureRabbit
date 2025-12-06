package rules

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// RegexEngine uses regex patterns to detect security issues
type RegexEngine struct {
	rules []RegexRule
}

// RegexRule defines a single regex-based security rule
type RegexRule struct {
	ID          string
	Title       string
	Description string
	Pattern     *regexp.Regexp
	Severity    types.Severity
	OWASPID     string
	CWE         string
	Recommendation string
}

// NewRegexEngine creates a new regex rule engine
func NewRegexEngine() *RegexEngine {
	return &RegexEngine{
		rules: getDefaultRegexRules(),
	}
}

// Analyze scans a file using regex patterns
func (r *RegexEngine) Analyze(ctx context.Context, filePath string) ([]types.Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()
	
	findings := make([]types.Finding, 0)
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Check each rule against the line
		for _, rule := range r.rules {
			if rule.Pattern.MatchString(line) {
				finding := types.Finding{
					Title:          rule.Title,
					Description:    rule.Description,
					FilePath:       filePath,
					StartLine:      lineNum,
					EndLine:        lineNum,
					Severity:       rule.Severity,
					OWASPID:        rule.OWASPID,
					CWE:            rule.CWE,
					Source:         types.SourceRegex,
					CodeSnippet:    line,
					Recommendation: rule.Recommendation,
				}
				findings = append(findings, finding)
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("error reading file: %w", err)
	}
	
	return findings, nil
}

// getDefaultRegexRules returns the default set of regex security rules
func getDefaultRegexRules() []RegexRule {
	return []RegexRule{
		{
			ID:          "REGEX001",
			Title:       "Hardcoded API Key",
			Description: "Hardcoded API key or secret detected",
			Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret|access[_-]?token)\s*[:=]\s*['""]?[a-zA-Z0-9]{20,}['""]?`),
			Severity:    types.SeverityHigh,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-798",
			Recommendation: "Store secrets in environment variables or secure vaults like AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault.",
		},
		{
			ID:          "REGEX002",
			Title:       "Hardcoded Password",
			Description: "Hardcoded password detected",
			Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['""][^'""]{3,}['""]`),
			Severity:    types.SeverityHigh,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-259",
			Recommendation: "Never hardcode passwords. Use environment variables, configuration files with restricted permissions, or secret management systems.",
		},
		{
			ID:          "REGEX003",
			Title:       "Hardcoded Private Key",
			Description: "Private key detected in code",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
			Severity:    types.SeverityCritical,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-321",
			Recommendation: "Remove private keys from code. Store them securely in key management systems and never commit them to version control.",
		},
		{
			ID:          "REGEX004",
			Title:       "AWS Access Key",
			Description: "AWS Access Key ID detected",
			Pattern:     regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
			Severity:    types.SeverityCritical,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-798",
			Recommendation: "Immediately rotate this AWS key. Use IAM roles or AWS Secrets Manager instead of hardcoding credentials.",
		},
		{
			ID:          "REGEX005",
			Title:       "Weak Cryptographic Hash (MD5)",
			Description: "Use of MD5 cryptographic hash detected",
			Pattern:     regexp.MustCompile(`(?i)md5\s*\(`),
			Severity:    types.SeverityMedium,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-327",
			Recommendation: "Replace MD5 with SHA-256 or stronger hashing algorithms. MD5 is cryptographically broken.",
		},
		{
			ID:          "REGEX006",
			Title:       "Weak Cryptographic Hash (SHA1)",
			Description: "Use of SHA1 cryptographic hash detected",
			Pattern:     regexp.MustCompile(`(?i)sha1\s*\(`),
			Severity:    types.SeverityMedium,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-327",
			Recommendation: "Replace SHA1 with SHA-256 or stronger hashing algorithms. SHA1 is considered weak.",
		},
		{
			ID:          "REGEX007",
			Title:       "SQL Query String Concatenation",
			Description: "Potential SQL injection via string concatenation",
			Pattern:     regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*['""]\s*\+`),
			Severity:    types.SeverityHigh,
			OWASPID:     "A03:2021-Injection",
			CWE:         "CWE-89",
			Recommendation: "Use parameterized queries or prepared statements instead of string concatenation.",
		},
		{
			ID:          "REGEX008",
			Title:       "Insecure HTTP URL",
			Description: "Use of insecure HTTP protocol detected",
			Pattern:     regexp.MustCompile(`http://[a-zA-Z0-9.-]+\.(com|org|net|io)`),
			Severity:    types.SeverityLow,
			OWASPID:     "A02:2021-Cryptographic Failures",
			CWE:         "CWE-319",
			Recommendation: "Use HTTPS instead of HTTP for secure communication.",
		},
		{
			ID:          "REGEX009",
			Title:       "Debug Mode Enabled",
			Description: "Debug mode appears to be enabled",
			Pattern:     regexp.MustCompile(`(?i)(debug|DEBUG)\s*[:=]\s*(true|True|TRUE|1)`),
			Severity:    types.SeverityMedium,
			OWASPID:     "A05:2021-Security Misconfiguration",
			CWE:         "CWE-489",
			Recommendation: "Disable debug mode in production environments to prevent information disclosure.",
		},
		{
			ID:          "REGEX010",
			Title:       "Potential Command Injection",
			Description: "Potential command injection vulnerability",
			Pattern:     regexp.MustCompile(`(?i)(exec|system|popen|shell_exec)\s*\([^)]*\+`),
			Severity:    types.SeverityHigh,
			OWASPID:     "A03:2021-Injection",
			CWE:         "CWE-78",
			Recommendation: "Avoid executing shell commands with user input. Use parameterized APIs or sanitize input thoroughly.",
		},
	}
}
