package providers

import (
	"fmt"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// PromptTemplate contains the system and user prompt templates for LLM analysis
const (
	SystemPrompt = `You are a security expert specialized in code review and vulnerability detection. 
Your task is to analyze code for security issues related to OWASP Top 10.

Focus on detecting:
- Injection flaws (SQL, Command, LDAP, etc.)
- Broken authentication and session management
- Sensitive data exposure
- XML external entities (XXE)
- Broken access control
- Security misconfiguration
- Cross-site scripting (XSS)
- Insecure deserialization
- Using components with known vulnerabilities
- Insufficient logging and monitoring
- Cryptographic failures
- Server-side request forgery (SSRF)

Provide structured, actionable findings in JSON format.`

	UserPromptTemplate = `Analyze the following code for security vulnerabilities:

File: %s
Language: %s
Lines: %d-%d

Code:
%s

%s

Respond with a JSON array of findings. Each finding should have:
{
  "title": "Brief title of the issue",
  "description": "Detailed explanation of the vulnerability",
  "severity": "critical|high|medium|low",
  "owasp_id": "OWASP category (e.g., A03:2021-Injection)",
  "cwe": "CWE identifier if applicable",
  "line_start": line number where issue starts,
  "line_end": line number where issue ends,
  "recommendation": "How to fix this issue"
}

If no security issues are found, return an empty array: []

Only respond with valid JSON, no additional text.`
)

// BuildPrompt constructs the complete prompt for LLM analysis
func BuildPrompt(req LLMRequest) (system string, user string) {
	staticContext := ""
	if len(req.StaticFindings) > 0 {
		staticContext = "Static analysis has already detected the following issues:\n"
		for _, finding := range req.StaticFindings {
			staticContext += fmt.Sprintf("- %s (Line %d): %s\n", 
				finding.Source, finding.StartLine, finding.Title)
		}
		staticContext += "\nPlease provide additional security insights beyond these static findings."
	}
	
	userPrompt := fmt.Sprintf(
		UserPromptTemplate,
		req.CodeChunk.FilePath,
		req.CodeChunk.Language,
		req.CodeChunk.StartLine,
		req.CodeChunk.EndLine,
		req.CodeChunk.Content,
		staticContext,
	)
	
	return SystemPrompt, userPrompt
}

// ParseSeverity normalizes severity strings from LLM output
func ParseSeverity(severity string) string {
	switch severity {
	case "critical", "Critical", "CRITICAL":
		return string(types.SeverityCritical)
	case "high", "High", "HIGH":
		return string(types.SeverityHigh)
	case "medium", "Medium", "MEDIUM", "moderate", "Moderate":
		return string(types.SeverityMedium)
	case "low", "Low", "LOW":
		return string(types.SeverityLow)
	default:
		return string(types.SeverityInfo)
	}
}
