package llm

import (
	"github.com/deepam02/securerabbit/internal/llm/providers"
)

// Re-export provider types for convenience
type (
	LLMProvider = providers.LLMProvider
	LLMRequest  = providers.LLMRequest
	LLMResponse = providers.LLMResponse
	LLMFinding  = providers.LLMFinding
)

// Re-export helper functions
var (
	BuildPrompt   = providers.BuildPrompt
	ParseSeverity = providers.ParseSeverity
)
