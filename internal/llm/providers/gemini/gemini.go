package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/deepam02/securerabbit/internal/llm/providers"
	"github.com/deepam02/securerabbit/internal/types"
)

const geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s"

// Provider implements the LLM provider interface for Google Gemini
type Provider struct {
	apiKey      string
	model       string
	maxRetries  int
	timeout     time.Duration
	httpClient  *http.Client
}

// NewProvider creates a new Gemini provider
func NewProvider(apiKey, model string, timeout int, maxRetries int) *Provider {
	return &Provider{
		apiKey:     apiKey,
		model:      model,
		maxRetries: maxRetries,
		timeout:    time.Duration(timeout) * time.Second,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "gemini"
}

// Model returns the model being used
func (p *Provider) Model() string {
	return p.model
}

// AnalyzeCode sends code to Gemini for analysis
func (p *Provider) AnalyzeCode(ctx context.Context, req providers.LLMRequest) (providers.LLMResponse, error) {
	systemPrompt, userPrompt := providers.BuildPrompt(req)
	
	// Combine system and user prompts for Gemini
	combinedPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, userPrompt)
	
	// Build Gemini request
	geminiReq := GeminiRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: combinedPrompt},
				},
			},
		},
		GenerationConfig: GenerationConfig{
			Temperature:     req.Temperature,
			MaxOutputTokens: req.MaxTokens,
		},
	}
	
	var lastErr error
	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			time.Sleep(backoff)
		}
		
		response, err := p.makeRequest(ctx, geminiReq)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Parse findings from response
		findings, err := p.parseResponse(response, req.CodeChunk)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Calculate tokens used (approximation)
		tokensUsed := response.UsageMetadata.PromptTokenCount + response.UsageMetadata.CandidatesTokenCount
		
		return providers.LLMResponse{
			Findings:   findings,
			RawOutput:  response.Candidates[0].Content.Parts[0].Text,
			TokensUsed: tokensUsed,
		}, nil
	}
	
	return providers.LLMResponse{}, fmt.Errorf("failed after %d retries: %w", p.maxRetries, lastErr)
}

// makeRequest sends the HTTP request to Gemini API
func (p *Provider) makeRequest(ctx context.Context, req GeminiRequest) (*GeminiResponse, error) {
	url := fmt.Sprintf(geminiAPIURL, p.model, p.apiKey)
	
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &geminiResp, nil
}

// parseResponse extracts findings from Gemini response
func (p *Provider) parseResponse(response *GeminiResponse, chunk types.CodeChunk) ([]types.Finding, error) {
	if len(response.Candidates) == 0 || len(response.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no content in response")
	}
	
	content := response.Candidates[0].Content.Parts[0].Text
	
	// Parse JSON array of findings
	var llmFindings []providers.LLMFinding
	if err := json.Unmarshal([]byte(content), &llmFindings); err != nil {
		// Try to extract JSON from markdown code blocks
		content = extractJSONFromMarkdown(content)
		if err := json.Unmarshal([]byte(content), &llmFindings); err != nil {
			return nil, fmt.Errorf("failed to parse findings JSON: %w", err)
		}
	}
	
	// Convert to standard Finding format
	findings := make([]types.Finding, 0, len(llmFindings))
	for _, lf := range llmFindings {
		finding := types.Finding{
			Title:          lf.Title,
			Description:    lf.Description,
			FilePath:       chunk.FilePath,
			StartLine:      chunk.StartLine + lf.LineStart - 1,
			EndLine:        chunk.StartLine + lf.LineEnd - 1,
			Severity:       types.Severity(providers.ParseSeverity(lf.Severity)),
			OWASPID:        lf.OWASPID,
			CWE:            lf.CWE,
			Source:         types.SourceLLM,
			Recommendation: lf.Recommendation,
		}
		findings = append(findings, finding)
	}
	
	return findings, nil
}

// extractJSONFromMarkdown removes markdown code block markers
func extractJSONFromMarkdown(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
	} else if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```")
	}
	
	if strings.HasSuffix(content, "```") {
		content = strings.TrimSuffix(content, "```")
	}
	
	return strings.TrimSpace(content)
}

// Gemini API types

type GeminiRequest struct {
	Contents         []Content        `json:"contents"`
	GenerationConfig GenerationConfig `json:"generationConfig,omitempty"`
}

type Content struct {
	Parts []Part `json:"parts"`
	Role  string `json:"role,omitempty"`
}

type Part struct {
	Text string `json:"text"`
}

type GenerationConfig struct {
	Temperature     float64 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
}

type GeminiResponse struct {
	Candidates    []Candidate   `json:"candidates"`
	UsageMetadata UsageMetadata `json:"usageMetadata"`
}

type Candidate struct {
	Content       Content `json:"content"`
	FinishReason  string  `json:"finishReason"`
	Index         int     `json:"index"`
	SafetyRatings []SafetyRating `json:"safetyRatings"`
}

type SafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

type UsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}
