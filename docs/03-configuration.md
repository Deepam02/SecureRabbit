# Configuration Guide

SecureRabbit uses YAML configuration files for flexible customization.

## Configuration File Location

SecureRabbit looks for configuration in this order:
1. `--config` flag (explicit path)
2. `.securerabbit.yml` in current directory
3. `.securerabbit.yaml` in current directory
4. `$HOME/.securerabbit.yml`

## Complete Configuration Reference

```yaml
# Scan settings
scan:
  mode: "smart"                    # Options: deep, smart, diff
  languages:                       # Languages to analyze
    - go
    - python
    - javascript
    - java
    - c
    - cpp
    - csharp
  max_concurrency: 4               # Parallel file processing

# LLM configuration
llm:
  provider: "openai"               # Options: openai, anthropic, gemini
  model: "gpt-4"                   # Model name
  api_key_env: "OPENAI_API_KEY"   # Environment variable name
  max_tokens: 4096                 # Maximum tokens per request
  temperature: 0.2                 # LLM temperature (0.0-1.0)
  timeout: 60                      # Request timeout in seconds
  max_retries: 3                   # Retry attempts on failure
  enabled_in_smart: true           # Use LLM in smart mode

# Static analysis rules
rules:
  gosec:
    enabled: true                  # Enable Gosec (Go only)
    severity:                      # Filter by severity
      - critical
      - high
      - medium
    confidence:                    # Filter by confidence
      - high
      - medium
  
  regex:
    enabled: true                  # Enable regex rules
  
  ast:
    enabled: true                  # Enable AST analysis

# Output settings
output:
  format: "markdown"               # Options: json, markdown
  path: "./securerabbit-report.md" # Output file path

# Files/directories to ignore
ignore:
  - "vendor/"
  - "node_modules/"
  - ".git/"
  - "test/"
  - "tests/"
  - "*_test.go"
  - "*.min.js"
  - "dist/"
  - "build/"
```

## Scan Mode Configuration

### Deep Mode
```yaml
scan:
  mode: "deep"
```
- Analyzes all files
- Uses LLM on every file
- Comprehensive but slower
- Best for: Security audits, first-time analysis

### Smart Mode (Recommended)
```yaml
scan:
  mode: "smart"
```
- Runs static analysis on all files
- Uses LLM only on high-risk files
- Balanced speed and coverage
- Best for: Regular development, CI/CD

### Diff Mode
```yaml
scan:
  mode: "diff"
```
- Analyzes only Git changes
- Fast incremental scanning
- Best for: Pre-commit hooks, pull requests

## LLM Provider Configuration

### OpenAI
```yaml
llm:
  provider: "openai"
  model: "gpt-4"                   # or "gpt-3.5-turbo"
  api_key_env: "OPENAI_API_KEY"
  max_tokens: 4096
  temperature: 0.2
```

### Anthropic Claude
```yaml
llm:
  provider: "anthropic"
  model: "claude-3-opus-20240229"  # or claude-3-sonnet
  api_key_env: "ANTHROPIC_API_KEY"
  max_tokens: 4096
  temperature: 0.2
```

### Google Gemini
```yaml
llm:
  provider: "gemini"
  model: "gemini-pro"
  api_key_env: "GEMINI_API_KEY"
  max_tokens: 4096
  temperature: 0.2
```

## Environment-Specific Configurations

### Development
```yaml
scan:
  mode: "smart"
  max_concurrency: 2

llm:
  provider: "openai"
  model: "gpt-3.5-turbo"  # Faster, cheaper
  temperature: 0.1         # More deterministic

output:
  format: "markdown"
```

### CI/CD
```yaml
scan:
  mode: "diff"
  max_concurrency: 4

rules:
  gosec:
    severity:
      - critical
      - high

output:
  format: "json"
  path: "./security-report.json"
```

### Security Audit
```yaml
scan:
  mode: "deep"
  max_concurrency: 8

llm:
  provider: "anthropic"
  model: "claude-3-opus-20240229"
  temperature: 0.0

output:
  format: "markdown"
```

## CLI Override

CLI flags override configuration file settings:

```bash
# Override mode
securerabbit scan --mode deep

# Override provider
securerabbit scan --llm-provider anthropic

# Override output
securerabbit scan --format json --output custom.json

# Use specific config file
securerabbit scan --config /path/to/config.yml
```

## Best Practices

1. **Commit your config** - Add `.securerabbit.yml` to version control
2. **Never commit API keys** - Always use environment variables
3. **Start with smart mode** - Balance between speed and coverage
4. **Adjust concurrency** - Based on your machine's resources
5. **Use ignore patterns** - Exclude vendored code and build artifacts

## Next Steps

- [Scan Modes Explained](05-scan-modes.md)
- [LLM Provider Setup](13-llm-providers.md)
- [Performance Tuning](14-performance.md)
