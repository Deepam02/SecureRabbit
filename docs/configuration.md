# Configuration Guide

Complete reference for configuring SecureRabbit.

## Table of Contents

- [Configuration File](#configuration-file)
- [Scan Configuration](#scan-configuration)
- [LLM Configuration](#llm-configuration)
- [Rule Configuration](#rule-configuration)
- [Output Configuration](#output-configuration)
- [Ignore Patterns](#ignore-patterns)
- [Environment Variables](#environment-variables)
- [Examples](#examples)

## Configuration File

SecureRabbit uses a YAML configuration file named `.securerabbit.yml` by default.

### File Location

The tool searches for configuration in this order:
1. Path specified by `--config` flag
2. `.securerabbit.yml` in current directory
3. `.securerabbit.yaml` in current directory
4. Default built-in configuration

### Generate Default Config

```bash
securerabbit init
```

## Scan Configuration

```yaml
scan:
  mode: "smart"              # Scan mode: deep, smart, or diff
  languages:                 # Languages to analyze
    - go
    - python
    - javascript
    - typescript
    - java
    - ruby
    - php
    - rust
  max_concurrency: 4         # Number of parallel workers
```

### `scan.mode`

**Type:** `string`  
**Default:** `"smart"`  
**Options:** `"deep"`, `"smart"`, `"diff"`

Determines which scan mode to use by default.

- **`deep`**: Analyzes all files with LLM
- **`smart`**: Analyzes only high-risk files with LLM
- **`diff`**: Analyzes only changed files (Git required)

### `scan.languages`

**Type:** `[]string`  
**Default:** `["go", "python", "javascript"]`

List of programming languages to analyze. Files with other extensions are ignored.

**Supported languages:**
- `go` - Go
- `python` - Python
- `javascript` - JavaScript
- `typescript` - TypeScript
- `java` - Java
- `c` - C
- `cpp` - C++
- `csharp` - C#
- `ruby` - Ruby
- `php` - PHP
- `rust` - Rust

### `scan.max_concurrency`

**Type:** `int`  
**Default:** `4`

Number of files to analyze concurrently during static analysis.

**Recommendations:**
- **Low memory systems:** `2`
- **Standard systems:** `4`
- **High-end systems:** `8-16`

## LLM Configuration

```yaml
llm:
  provider: "openai"         # LLM provider
  model: "gpt-4"             # Model name
  api_key_env: "OPENAI_API_KEY" # Environment variable for API key
  max_tokens: 4096           # Maximum tokens per request
  temperature: 0.2           # LLM temperature (0.0-1.0)
  timeout: 60                # Request timeout (seconds)
  max_retries: 3             # Number of retry attempts
  enabled_in_smart: true     # Enable LLM in smart mode
```

### `llm.provider`

**Type:** `string`  
**Default:** `"openai"`  
**Options:** `"openai"`, `"anthropic"`, `"gemini"`

LLM provider to use for AI-powered analysis.

### `llm.model`

**Type:** `string`  
**Default:** Depends on provider

Specific model to use from the provider.

**OpenAI models:**
- `gpt-4` - Most capable, higher cost
- `gpt-4-turbo-preview` - Faster GPT-4
- `gpt-3.5-turbo` - Faster, lower cost

**Anthropic models:**
- `claude-3-opus-20240229` - Most capable
- `claude-3-sonnet-20240229` - Balanced
- `claude-3-haiku-20240307` - Fastest, lowest cost

**Google models:**
- `gemini-pro` - Balanced performance
- `gemini-pro-vision` - Multimodal capabilities

### `llm.api_key_env`

**Type:** `string`  
**Default:** `"OPENAI_API_KEY"` (or provider-specific)

Name of environment variable containing the API key.

**Provider defaults:**
- OpenAI: `OPENAI_API_KEY`
- Anthropic: `ANTHROPIC_API_KEY`
- Gemini: `GEMINI_API_KEY`

### `llm.max_tokens`

**Type:** `int`  
**Default:** `4096`

Maximum number of tokens in the LLM response.

**Recommendations:**
- **Short files:** `2048`
- **Medium files:** `4096`
- **Large files:** `8192`
- **Very large files:** `16384` (if model supports)

### `llm.temperature`

**Type:** `float`  
**Default:** `0.2`  
**Range:** `0.0` to `1.0`

Controls randomness in LLM responses.

- **`0.0`**: Deterministic, focused responses
- **`0.2`**: Slightly creative (recommended for security)
- **`0.5`**: Balanced
- **`1.0`**: Very creative, less predictable

**For security analysis, use low values (0.1-0.3)** for consistent, focused results.

### `llm.timeout`

**Type:** `int`  
**Default:** `60`  
**Unit:** seconds

HTTP request timeout for LLM API calls.

### `llm.max_retries`

**Type:** `int`  
**Default:** `3`

Number of retry attempts on API failure (with exponential backoff).

### `llm.enabled_in_smart`

**Type:** `bool`  
**Default:** `true`

Whether to use LLM in smart mode. If `false`, smart mode only uses static analysis.

## Rule Configuration

```yaml
rules:
  gosec:
    enabled: true
    severity:
      - high
      - medium
    confidence:
      - high
      - medium
  regex:
    enabled: true
  ast:
    enabled: true
```

### `rules.gosec`

Go security checker integration (currently placeholder).

**`rules.gosec.enabled`**  
**Type:** `bool`  
**Default:** `true`

Enable Gosec integration for Go files.

**`rules.gosec.severity`**  
**Type:** `[]string`  
**Default:** `["high", "medium"]`  
**Options:** `"high"`, `"medium"`, `"low"`

Minimum severity levels to report.

**`rules.gosec.confidence`**  
**Type:** `[]string`  
**Default:** `["high", "medium"]`  
**Options:** `"high"`, `"medium"`, `"low"`

Minimum confidence levels to report.

### `rules.regex`

**Type:** `bool`  
**Default:** `true`

Enable regex-based pattern matching rules.

**Detects:**
- Hardcoded credentials
- Weak cryptography
- SQL injection patterns
- Command injection
- Insecure protocols
- Debug mode enabled

### `rules.ast`

**Type:** `bool`  
**Default:** `true`

Enable AST (Abstract Syntax Tree) analysis for Go files.

**Detects:**
- Weak random number generation
- Empty password validation
- Ignored error returns
- Unsafe type assertions

## Output Configuration

```yaml
output:
  format: "markdown"         # Output format
  path: "./securerabbit-report.md" # Output file path
```

### `output.format`

**Type:** `string`  
**Default:** `"markdown"`  
**Options:** `"json"`, `"markdown"`

Output report format.

- **`markdown`**: Human-readable, rich formatting
- **`json`**: Machine-readable, CI/CD integration

### `output.path`

**Type:** `string`  
**Default:** `"./securerabbit-report.md"`

Path where the report will be saved.

**Supports:**
- Relative paths: `./reports/security.md`
- Absolute paths: `/tmp/scan-results.json`
- Dynamic names: `security-$(date +%Y%m%d).md` (in shell)

## Ignore Patterns

```yaml
ignore:
  - "vendor/"
  - "node_modules/"
  - ".git/"
  - "dist/"
  - "build/"
  - "test/"
  - "tests/"
  - "*_test.go"
  - "*.test.js"
  - "**/*.min.js"
  - "**/*.generated.go"
```

**Type:** `[]string`  
**Default:** See above

Files and directories to exclude from scanning.

**Pattern syntax:**
- `dir/` - Directory
- `*.ext` - File extension
- `**/pattern` - Recursive match
- `file.go` - Specific file

**Common patterns:**
```yaml
ignore:
  # Dependencies
  - "vendor/"
  - "node_modules/"
  - "Pods/"
  
  # Build artifacts
  - "dist/"
  - "build/"
  - "bin/"
  - "target/"
  
  # Version control
  - ".git/"
  - ".svn/"
  
  # Tests
  - "test/"
  - "tests/"
  - "*_test.go"
  - "*.test.js"
  - "**/__tests__/**"
  
  # Generated files
  - "*.generated.go"
  - "*.pb.go"
  - "*.min.js"
  - "*.bundle.js"
  
  # Documentation
  - "docs/"
  - "documentation/"
  
  # IDE
  - ".vscode/"
  - ".idea/"
  - "*.swp"
```

## Environment Variables

### API Keys

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# Google Gemini
export GEMINI_API_KEY="..."
```

### Custom Config Location

```bash
export SECURERABBIT_CONFIG="/path/to/custom-config.yml"
```

### Override Settings

```bash
# Disable LLM temporarily
export SECURERABBIT_STATIC_ONLY=true

# Change output format
export SECURERABBIT_OUTPUT_FORMAT=json
```

## Examples

### Minimal Configuration

```yaml
scan:
  languages:
    - go

llm:
  provider: "openai"

output:
  format: "markdown"
```

### Cost-Optimized Configuration

```yaml
scan:
  mode: "smart"
  max_concurrency: 2

llm:
  provider: "openai"
  model: "gpt-3.5-turbo"      # Cheaper model
  max_tokens: 2048            # Lower token limit
  enabled_in_smart: true
  temperature: 0.1            # More deterministic

rules:
  regex:
    enabled: true
  ast:
    enabled: true
  gosec:
    enabled: false            # Disable expensive checks

output:
  format: "json"
```

### High-Security Configuration

```yaml
scan:
  mode: "deep"                # Comprehensive scan
  languages:
    - go
    - python
    - javascript
  max_concurrency: 8

llm:
  provider: "openai"
  model: "gpt-4"              # Best model
  max_tokens: 8192            # More detailed analysis
  temperature: 0.1            # Consistent results
  max_retries: 5

rules:
  gosec:
    enabled: true
    severity:
      - high
      - medium
      - low                   # Include all severities
    confidence:
      - high
      - medium
      - low
  regex:
    enabled: true
  ast:
    enabled: true

output:
  format: "markdown"

ignore:
  - "vendor/"                 # Only ignore dependencies
  - "node_modules/"
```

### CI/CD Configuration

```yaml
scan:
  mode: "diff"                # Only changed files
  max_concurrency: 4

llm:
  provider: "openai"
  model: "gpt-3.5-turbo"
  max_tokens: 4096
  timeout: 30                 # Shorter timeout
  max_retries: 2

rules:
  regex:
    enabled: true
  ast:
    enabled: true

output:
  format: "json"
  path: "./ci-security-results.json"

ignore:
  - "test/"
  - "*_test.go"
  - "*.test.js"
```

### Multi-Language Configuration

```yaml
scan:
  mode: "smart"
  languages:
    - go
    - python
    - javascript
    - typescript
    - java
    - ruby

llm:
  provider: "anthropic"
  model: "claude-3-sonnet-20240229"
  max_tokens: 4096

rules:
  gosec:
    enabled: true
  regex:
    enabled: true
  ast:
    enabled: true

output:
  format: "markdown"

ignore:
  - "vendor/"
  - "node_modules/"
  - "venv/"
  - ".venv/"
  - "target/"
```

## Validation

SecureRabbit validates your configuration on startup. Common errors:

### Invalid Provider
```
Error: unsupported LLM provider: invalid-provider
Valid options: openai, anthropic, gemini
```

### Missing API Key
```
Error: API key not found in environment variable: OPENAI_API_KEY
Please set the environment variable or update llm.api_key_env in config
```

### Invalid Mode
```
Error: invalid scan mode: invalid-mode
Valid options: deep, smart, diff
```

## Best Practices

1. **Version control your config** - Commit `.securerabbit.yml` (without secrets)
2. **Use environment variables for secrets** - Never hardcode API keys
3. **Start conservative** - Begin with smart mode, graduate to deep
4. **Tune for your needs** - Adjust concurrency and token limits based on usage
5. **Document overrides** - Comment why you're ignoring specific files
6. **Test configurations** - Use `--static-only` to validate settings quickly

## Next Steps

- Read the [Usage Guide](./usage.md)
- Learn about [security best practices](./security.md)
- Explore [advanced usage patterns](./usage.md#advanced-usage)

---

**Questions?** [Open an issue](https://github.com/deepam02/securerabbit/issues) or [start a discussion](https://github.com/deepam02/securerabbit/discussions).
