package anthropic

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

const anthropicAPIURL = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"

// Provider implements the LLM provider interface for Anthropic
type Provider struct {
	apiKey      string
	model       string
	maxRetries  int
	timeout     time.Duration
	httpClient  *http.Client
}

// NewProvider creates a new Anthropic provider
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
	return "anthropic"
}

// Model returns the model being used
func (p *Provider) Model() string {
	return p.model
}

// AnalyzeCode sends code to Anthropic for analysis
func (p *Provider) AnalyzeCode(ctx context.Context, req providers.LLMRequest) (providers.LLMResponse, error) {
	systemPrompt, userPrompt := providers.BuildPrompt(req)
	
	// Build Anthropic request
	anthropicReq := AnthropicRequest{
		Model:       p.model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		System:      systemPrompt,
		Messages: []Message{
			{Role: "user", Content: userPrompt},
		},
	}
	
	var lastErr error
	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			time.Sleep(backoff)
		}
		
		response, err := p.makeRequest(ctx, anthropicReq)
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
		
		return providers.LLMResponse{
			Findings:   findings,
			RawOutput:  response.Content[0].Text,
			TokensUsed: response.Usage.InputTokens + response.Usage.OutputTokens,
		}, nil
	}
	
	return providers.LLMResponse{}, fmt.Errorf("failed after %d retries: %w", p.maxRetries, lastErr)
}

// makeRequest sends the HTTP request to Anthropic API
func (p *Provider) makeRequest(ctx context.Context, req AnthropicRequest) (*AnthropicResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	
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
	
	var anthropicResp AnthropicResponse
	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &anthropicResp, nil
}

// parseResponse extracts findings from Anthropic response
func (p *Provider) parseResponse(response *AnthropicResponse, chunk types.CodeChunk) ([]types.Finding, error) {
	if len(response.Content) == 0 {
		return nil, fmt.Errorf("no content in response")
	}
	
	content := response.Content[0].Text
	
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
	// Remove ```json and ``` markers
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

// Anthropic API types

type AnthropicRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature,omitempty"`
	System      string    `json:"system,omitempty"`
	Messages    []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AnthropicResponse struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	Content []ContentBlock  `json:"content"`
	Model   string          `json:"model"`
	Usage   UsageInfo       `json:"usage"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type UsageInfo struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
