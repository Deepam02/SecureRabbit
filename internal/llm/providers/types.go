package providers

import (
	"context"

	"github.com/deepam02/securerabbit/internal/types"
)// LLMProvider defines the interface that all LLM providers must implement
type LLMProvider interface {
	// AnalyzeCode analyzes a code chunk and returns security findings
	AnalyzeCode(ctx context.Context, req LLMRequest) (LLMResponse, error)
	
	// Name returns the provider name
	Name() string
	
	// Model returns the model being used
	Model() string
}

// LLMRequest contains the input for LLM analysis
type LLMRequest struct {
	CodeChunk      types.CodeChunk
	StaticFindings []types.Finding
	MaxTokens      int
	Temperature    float64
}

// LLMResponse contains the output from LLM analysis
type LLMResponse struct {
	Findings   []types.Finding
	RawOutput  string
	TokensUsed int
}

// LLMFinding represents a finding from LLM in intermediate format
type LLMFinding struct {
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	OWASPID        string `json:"owasp_id"`
	CWE            string `json:"cwe"`
	LineStart      int    `json:"line_start"`
	LineEnd        int    `json:"line_end"`
	Recommendation string `json:"recommendation"`
}
