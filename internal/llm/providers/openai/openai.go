package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/deepam02/securerabbit/internal/llm/providers"
	"github.com/deepam02/securerabbit/internal/types"
)

const openaiAPIURL = "https://api.openai.com/v1/chat/completions"

// Provider implements the LLM provider interface for OpenAI
type Provider struct {
	apiKey      string
	model       string
	maxRetries  int
	timeout     time.Duration
	httpClient  *http.Client
}

// NewProvider creates a new OpenAI provider
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
	return "openai"
}

// Model returns the model being used
func (p *Provider) Model() string {
	return p.model
}

// AnalyzeCode sends code to OpenAI for analysis
func (p *Provider) AnalyzeCode(ctx context.Context, req providers.LLMRequest) (providers.LLMResponse, error) {
	systemPrompt, userPrompt := providers.BuildPrompt(req)
	
	// Build OpenAI request
	openaiReq := OpenAIRequest{
		Model: p.model,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	}
	
	var lastErr error
	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			time.Sleep(backoff)
		}
		
		response, err := p.makeRequest(ctx, openaiReq)
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
			RawOutput:  response.Choices[0].Message.Content,
			TokensUsed: response.Usage.TotalTokens,
		}, nil
	}
	
	return providers.LLMResponse{}, fmt.Errorf("failed after %d retries: %w", p.maxRetries, lastErr)
}

// makeRequest sends the HTTP request to OpenAI API
func (p *Provider) makeRequest(ctx context.Context, req OpenAIRequest) (*OpenAIResponse, error) {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", openaiAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	
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
	
	var openaiResp OpenAIResponse
	if err := json.Unmarshal(body, &openaiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &openaiResp, nil
}

// parseResponse extracts findings from OpenAI response
func (p *Provider) parseResponse(response *OpenAIResponse, chunk types.CodeChunk) ([]types.Finding, error) {
	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}
	
	content := response.Choices[0].Message.Content
	
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
	if len(content) > 7 && content[:7] == "```json" {
		content = content[7:]
	} else if len(content) > 3 && content[:3] == "```" {
		content = content[3:]
	}
	
	if len(content) > 3 && content[len(content)-3:] == "```" {
		content = content[:len(content)-3]
	}
	
	return content
}

// OpenAI API types

type OpenAIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}
