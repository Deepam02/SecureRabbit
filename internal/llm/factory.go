package llm

import (
	"fmt"

	"github.com/deepam02/securerabbit/internal/config"
	"github.com/deepam02/securerabbit/internal/llm/providers/anthropic"
	"github.com/deepam02/securerabbit/internal/llm/providers/gemini"
	"github.com/deepam02/securerabbit/internal/llm/providers/openai"
)

// NewProvider creates a new LLM provider based on configuration
func NewProvider(cfg *config.LLMConfig) (LLMProvider, error) {
	apiKey, err := cfg.GetAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}
	
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60
	}
	
	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}
	
	switch cfg.Provider {
	case "openai":
		model := cfg.Model
		if model == "" {
			model = "gpt-4"
		}
		return openai.NewProvider(apiKey, model, timeout, maxRetries), nil
		
	case "anthropic":
		model := cfg.Model
		if model == "" {
			model = "claude-3-sonnet-20240229"
		}
		return anthropic.NewProvider(apiKey, model, timeout, maxRetries), nil
		
	case "gemini":
		model := cfg.Model
		if model == "" {
			model = "gemini-pro"
		}
		return gemini.NewProvider(apiKey, model, timeout, maxRetries), nil
		
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", cfg.Provider)
	}
}
