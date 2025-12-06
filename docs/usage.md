# Usage Guide

Complete guide to using SecureRabbit for security analysis.

## Table of Contents

- [Command Reference](#command-reference)
- [Scan Modes](#scan-modes)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Advanced Usage](#advanced-usage)
- [Best Practices](#best-practices)

## Command Reference

### `securerabbit scan`

Run a security scan on your project.

```bash
securerabbit scan [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Path to project directory |
| `--mode` | string | `smart` | Scan mode: `deep`, `smart`, or `diff` |
| `--llm-provider` | string | - | LLM provider: `openai`, `anthropic`, or `gemini` |
| `--static-only` | bool | `false` | Run static analysis only, skip LLM |
| `--format` | string | - | Output format: `json` or `markdown` |
| `--output` | string | - | Output file path |
| `--config` | string | `.securerabbit.yml` | Config file path |

#### Examples

```bash
# Basic scan with defaults
securerabbit scan

# Scan specific directory
securerabbit scan --path ./src

# Use different LLM provider
securerabbit scan --llm-provider anthropic

# Save as JSON
securerabbit scan --format json --output results.json

# Deep scan with custom config
securerabbit scan --mode deep --config custom-config.yml

# Static-only scan (no API calls)
securerabbit scan --static-only
```

### `securerabbit init`

Initialize a new configuration file.

```bash
securerabbit init
```

Creates `.securerabbit.yml` in the current directory with default settings.

### `securerabbit version`

Display version information.

```bash
securerabbit version
```

## Scan Modes

### Deep Mode

Analyzes **all** files with both static rules and LLM analysis.

```bash
securerabbit scan --mode deep
```

**Use when:**
- Starting a new project security audit
- Comprehensive security review needed
- API cost is not a concern
- You want maximum coverage

**Characteristics:**
- ✅ Most comprehensive analysis
- ✅ Detects subtle vulnerabilities
- ❌ Higher API costs
- ❌ Longer scan time

### Smart Mode (Default)

Uses risk scoring to analyze only **high-risk** files with LLM.

```bash
securerabbit scan --mode smart
# or just
securerabbit scan
```

**Use when:**
- Regular security checks
- Cost optimization is important
- Balancing speed and accuracy
- Incremental security improvements

**Characteristics:**
- ✅ Cost-effective
- ✅ Fast execution
- ✅ Good accuracy
- ✅ Focuses on risky code

**Risk Scoring Factors:**
- Static findings (weighted by severity)
- Security-sensitive code patterns (crypto, auth, database)
- File naming conventions (auth, admin, password, etc.)
- Lines of code (larger files = higher risk)

### Diff Mode

Scans only **changed files** in your Git repository.

```bash
securerabbit scan --mode diff
```

**Use when:**
- Pre-commit checks
- CI/CD pipeline integration
- Code review process
- Pull request validation

**Characteristics:**
- ✅ Very fast
- ✅ Minimal API usage
- ✅ Perfect for CI/CD
- ⚠️ Only scans uncommitted changes

**Requirements:**
- Project must be a Git repository
- Changes must be uncommitted or in current branch

## Configuration

### Configuration File

SecureRabbit uses a YAML configuration file (`.securerabbit.yml`).

```yaml
# Scan configuration
scan:
  mode: "smart"                # Default scan mode
  languages:                   # Languages to analyze
    - go
    - python
    - javascript
    - typescript
  max_concurrency: 4           # Parallel file processing

# LLM configuration
llm:
  provider: "openai"           # LLM provider
  model: "gpt-4"               # Model name
  api_key_env: "OPENAI_API_KEY" # Environment variable for API key
  max_tokens: 4096             # Max tokens per request
  temperature: 0.2             # LLM temperature (0-1)
  timeout: 60                  # Request timeout in seconds
  max_retries: 3               # Retry attempts on failure
  enabled_in_smart: true       # Enable LLM in smart mode

# Rule configuration
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

# Output configuration
output:
  format: "markdown"           # Output format
  path: "./securerabbit-report.md" # Output path

# Files/directories to ignore
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
```

### Environment Variables

#### LLM API Keys

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# Google Gemini
export GEMINI_API_KEY="..."
```

#### Custom Config Path

```bash
export SECURERABBIT_CONFIG="./configs/production.yml"
```

### CLI Override

CLI flags override configuration file settings:

```bash
# Override provider
securerabbit scan --llm-provider anthropic

# Override mode
securerabbit scan --mode deep

# Override output
securerabbit scan --format json --output custom.json
```

## Output Formats

### Markdown (Default)

Human-readable report with sections:

```bash
securerabbit scan --format markdown
```

**Features:**
- Rich formatting with emojis
- Organized by file and severity
- Code snippets included
- Recommendations highlighted
- OWASP/CWE mappings

**Example:**
```markdown
# SecureRabbit Security Scan Report

## Summary
- **Total Findings:** 15
- **Critical:** 2
- **High:** 5

### findings.md

#### 1. SQL Injection Vulnerability

**Severity:** 🔴 Critical | **Source:** llm | **Line:** 45

**Description:**
The code constructs SQL queries using string concatenation...

**Recommendation:**
Use parameterized queries or prepared statements...
```

### JSON

Machine-readable format for automation:

```bash
securerabbit scan --format json --output results.json
```

**Features:**
- Structured data
- Easy to parse
- CI/CD integration
- Programmatic processing

**Example:**
```json
{
  "project_path": "/path/to/project",
  "scan_mode": "smart",
  "start_time": "2024-12-06T10:30:00Z",
  "end_time": "2024-12-06T10:32:34Z",
  "duration": "2m34s",
  "files_scanned": 45,
  "total_findings": 15,
  "llm_provider": "openai",
  "findings": [
    {
      "id": "a1b2c3d4",
      "title": "SQL Injection Vulnerability",
      "description": "...",
      "file_path": "src/db/query.go",
      "start_line": 45,
      "end_line": 47,
      "severity": "critical",
      "owasp_id": "A03:2021-Injection",
      "cwe": "CWE-89",
      "source": "llm",
      "recommendation": "..."
    }
  ]
}
```

## Advanced Usage

### Scanning Multiple Projects

```bash
#!/bin/bash
# scan-all-projects.sh

for project in project1 project2 project3; do
    echo "Scanning $project..."
    securerabbit scan --path ./$project --output reports/${project}-report.md
done
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Go
        uses: actions/setup-go@v2
        with:
          go-version: '1.21'
      
      - name: Install SecureRabbit
        run: go install github.com/deepam02/securerabbit/cmd/securerabbit@latest
      
      - name: Run Security Scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: securerabbit scan --mode diff --format json --output results.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: results.json
```

#### GitLab CI

```yaml
security_scan:
  stage: test
  image: golang:1.21
  script:
    - go install github.com/deepam02/securerabbit/cmd/securerabbit@latest
    - securerabbit scan --static-only --format json --output results.json
  artifacts:
    reports:
      junit: results.json
```

### Filtering Results

Use `jq` to filter JSON output:

```bash
# Get only critical findings
securerabbit scan --format json | jq '.findings[] | select(.severity == "critical")'

# Count findings by severity
securerabbit scan --format json | jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'

# Get findings for specific file
securerabbit scan --format json | jq '.findings[] | select(.file_path | contains("auth.go"))'
```

### Custom Ignore Patterns

Add to `.securerabbit.yml`:

```yaml
ignore:
  - "vendor/"
  - "node_modules/"
  - "**/*.min.js"
  - "**/*.generated.go"
  - "docs/"
  - "examples/"
  - "**/testdata/**"
```

### Multiple Configurations

Use different configs for different environments:

```bash
# Development - fast, static-only
securerabbit scan --config .securerabbit.dev.yml --static-only

# Staging - smart mode
securerabbit scan --config .securerabbit.staging.yml

# Production - deep scan
securerabbit scan --config .securerabbit.prod.yml --mode deep
```

## Best Practices

### 1. Start with Static-Only

Begin with fast static analysis:
```bash
securerabbit scan --static-only
```

### 2. Use Smart Mode Regularly

Run smart scans during development:
```bash
securerabbit scan --mode smart
```

### 3. Deep Scans Periodically

Schedule comprehensive scans weekly/monthly:
```bash
securerabbit scan --mode deep
```

### 4. Diff Mode for PRs

Always scan changes before merging:
```bash
securerabbit scan --mode diff
```

### 5. Ignore False Positives

Document false positives in config:
```yaml
ignore:
  - "src/safe_crypto.go"  # Reviewed - using secure implementation
```

### 6. Version Control Reports

Add reports directory to `.gitignore`:
```
reports/
securerabbit-report.md
```

### 7. Monitor API Usage

Track API costs by reviewing token usage in reports.

### 8. Incremental Adoption

Gradually enable more rules as you fix issues.

## Troubleshooting

### Slow Scans

- Use `--static-only` for faster results
- Reduce `max_concurrency` if memory-constrained
- Use smart or diff mode instead of deep

### High API Costs

- Use smart mode with appropriate risk thresholds
- Scan only changed files with diff mode
- Reduce `max_tokens` in configuration

### Too Many False Positives

- Adjust ignore patterns
- Use static-only mode for initial cleanup
- Fine-tune LLM temperature (lower = more conservative)

### Missing Findings

- Enable all rule types
- Use deep mode for comprehensive analysis
- Check ignore patterns aren't excluding important files

## Next Steps

- Learn about [configuration options](./configuration.md)
- Read [security best practices](./security.md)
- Explore the [architecture](../IMPLEMENTATION.md)

---

**Need help?** [Open an issue](https://github.com/deepam02/securerabbit/issues) or [start a discussion](https://github.com/deepam02/securerabbit/discussions).
