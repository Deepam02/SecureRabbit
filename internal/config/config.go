package config

import (
	"fmt"
	"os"

	"github.com/deepam02/securerabbit/internal/types"
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Scan   ScanConfig   `mapstructure:"scan"`
	LLM    LLMConfig    `mapstructure:"llm"`
	Rules  RulesConfig  `mapstructure:"rules"`
	Output OutputConfig `mapstructure:"output"`
	Ignore []string     `mapstructure:"ignore"`
}

// ScanConfig holds scan-related settings
type ScanConfig struct {
	Mode           types.ScanMode `mapstructure:"mode"`
	Languages      []string       `mapstructure:"languages"`
	MaxConcurrency int            `mapstructure:"max_concurrency"`
}

// LLMConfig holds LLM provider settings
type LLMConfig struct {
	Provider      string  `mapstructure:"provider"`
	Model         string  `mapstructure:"model"`
	APIKeyEnv     string  `mapstructure:"api_key_env"`
	MaxTokens     int     `mapstructure:"max_tokens"`
	Temperature   float64 `mapstructure:"temperature"`
	Timeout       int     `mapstructure:"timeout"`
	MaxRetries    int     `mapstructure:"max_retries"`
	EnabledInSmart bool   `mapstructure:"enabled_in_smart"`
}

// RulesConfig controls which rule engines are enabled
type RulesConfig struct {
	Gosec GosecConfig `mapstructure:"gosec"`
	Regex RegexConfig `mapstructure:"regex"`
	AST   ASTConfig   `mapstructure:"ast"`
}

// GosecConfig holds Gosec-specific settings
type GosecConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	Severity    []string `mapstructure:"severity"`
	Confidence  []string `mapstructure:"confidence"`
	ExcludeRules []string `mapstructure:"exclude_rules"`
}

// RegexConfig holds regex rule settings
type RegexConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// ASTConfig holds AST rule settings
type ASTConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// OutputConfig defines output format and location
type OutputConfig struct {
	Format string `mapstructure:"format"`
	Path   string `mapstructure:"path"`
}

// Load loads configuration from file and environment
func Load(configPath string) (*Config, error) {
	v := viper.New()
	
	// Set defaults
	setDefaults(v)
	
	// Load config file if specified
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName(".securerabbit")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
	}
	
	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is okay, we have defaults
	}
	
	// Environment variables override
	v.AutomaticEnv()
	
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Scan defaults
	v.SetDefault("scan.mode", "smart")
	v.SetDefault("scan.languages", []string{"go", "python", "javascript"})
	v.SetDefault("scan.max_concurrency", 4)
	
	// LLM defaults
	v.SetDefault("llm.provider", "openai")
	v.SetDefault("llm.model", "gpt-4")
	v.SetDefault("llm.api_key_env", "OPENAI_API_KEY")
	v.SetDefault("llm.max_tokens", 4096)
	v.SetDefault("llm.temperature", 0.2)
	v.SetDefault("llm.timeout", 60)
	v.SetDefault("llm.max_retries", 3)
	v.SetDefault("llm.enabled_in_smart", true)
	
	// Rules defaults
	v.SetDefault("rules.gosec.enabled", true)
	v.SetDefault("rules.gosec.severity", []string{"high", "medium"})
	v.SetDefault("rules.gosec.confidence", []string{"high", "medium"})
	v.SetDefault("rules.regex.enabled", true)
	v.SetDefault("rules.ast.enabled", true)
	
	// Output defaults
	v.SetDefault("output.format", "markdown")
	v.SetDefault("output.path", "./securerabbit-report.md")
	
	// Ignore defaults
	v.SetDefault("ignore", []string{"vendor/", "node_modules/", ".git/"})
}

// GetAPIKey retrieves the API key from environment variable
func (c *LLMConfig) GetAPIKey() (string, error) {
	if c.APIKeyEnv == "" {
		return "", fmt.Errorf("API key environment variable not configured")
	}
	
	apiKey := os.Getenv(c.APIKeyEnv)
	if apiKey == "" {
		return "", fmt.Errorf("API key not found in environment variable: %s", c.APIKeyEnv)
	}
	
	return apiKey, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate scan mode
	switch c.Scan.Mode {
	case types.ScanModeDeep, types.ScanModeSmart, types.ScanModeDiff:
		// Valid
	default:
		return fmt.Errorf("invalid scan mode: %s", c.Scan.Mode)
	}
	
	// Validate LLM provider
	if c.LLM.Provider != "" {
		validProviders := map[string]bool{
			"openai":    true,
			"anthropic": true,
			"gemini":    true,
			"custom":    true,
		}
		if !validProviders[c.LLM.Provider] {
			return fmt.Errorf("invalid LLM provider: %s", c.LLM.Provider)
		}
	}
	
	// Validate output format
	if c.Output.Format != "json" && c.Output.Format != "markdown" {
		return fmt.Errorf("invalid output format: %s (must be json or markdown)", c.Output.Format)
	}
	
	return nil
}
