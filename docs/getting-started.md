# Getting Started with SecureRabbit

This guide will help you get up and running with SecureRabbit in minutes.

## Prerequisites

- **Go 1.21 or higher** - [Download Go](https://golang.org/dl/)
- **Git** (for diff mode scanning)
- **API Key** from one of:
  - OpenAI (GPT-4/GPT-3.5)
  - Anthropic (Claude)
  - Google (Gemini)

## Installation

### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/deepam02/securerabbit.git
cd securerabbit

# Build the binary
go build -o bin/securerabbit ./cmd/securerabbit

# Verify installation
./bin/securerabbit version
```

### Option 2: Install Directly

```bash
go install github.com/deepam02/securerabbit/cmd/securerabbit@latest
```

### Option 3: Download Pre-built Binary

Download the latest release from [GitHub Releases](https://github.com/deepam02/securerabbit/releases).

## Initial Setup

### 1. Initialize Configuration

Navigate to your project directory and run:

```bash
securerabbit init
```

This creates a `.securerabbit.yml` configuration file with sensible defaults:

```yaml
scan:
  mode: "smart"
  languages:
    - go
    - python
    - javascript
  max_concurrency: 4

llm:
  provider: "openai"
  model: "gpt-4"
  api_key_env: "OPENAI_API_KEY"
  max_tokens: 4096
  temperature: 0.2

rules:
  gosec:
    enabled: true
  regex:
    enabled: true
  ast:
    enabled: true

output:
  format: "markdown"
  path: "./securerabbit-report.md"

ignore:
  - "vendor/"
  - "node_modules/"
  - ".git/"
  - "test/"
  - "*_test.go"
```

### 2. Set Up API Key

Choose your preferred LLM provider and set the API key:

#### For OpenAI:
```bash
export OPENAI_API_KEY="sk-..."
```

#### For Anthropic:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

#### For Google Gemini:
```bash
export GEMINI_API_KEY="..."
```

**Important:** Never commit API keys to version control. Add `.securerabbit.yml` to `.gitignore` if it contains sensitive data.

### 3. Configure for Your Project

Edit `.securerabbit.yml` to match your project:

```yaml
scan:
  languages:
    - go          # If you have Go code
    - python      # If you have Python code
    - javascript  # If you have JavaScript/TypeScript

llm:
  provider: "openai"    # or "anthropic" or "gemini"
  model: "gpt-4"        # or "gpt-3.5-turbo", "claude-3-sonnet-20240229", etc.
```

## Your First Scan

### Quick Scan (Static Only)

Start with a fast static-only scan:

```bash
securerabbit scan --static-only
```

This runs regex and AST-based rules without using LLM, giving you immediate results.

### Smart Scan (Recommended)

Run a smart scan that uses AI for high-risk files only:

```bash
securerabbit scan
```

This is the default mode and provides the best balance of accuracy and cost.

### Deep Scan (Comprehensive)

For a thorough analysis of all files:

```bash
securerabbit scan --mode deep
```

**Note:** Deep scans may consume more API credits as they analyze all files with LLM.

## Understanding the Output

After a scan completes, you'll see a summary:

```
═══════════════════════════════════════════════════
  Scan Complete!
═══════════════════════════════════════════════════
Files Scanned:    45
Total Findings:   15
Scan Duration:    2m 34s
Report saved to:  ./securerabbit-report.md
═══════════════════════════════════════════════════

Findings by Severity:
  🔴 Critical  : 2
  🟠 High      : 5
  🟡 Medium    : 6
  🔵 Low       : 2
```

### View the Report

Open the generated report file:

```bash
# For Markdown
cat securerabbit-report.md

# Or open in your default editor
code securerabbit-report.md
```

The report contains:
- Summary of findings by severity
- Detailed descriptions of each vulnerability
- Code snippets showing the issue
- Recommendations for fixing each issue
- OWASP and CWE mappings

## Common Use Cases

### CI/CD Integration

Run SecureRabbit in your CI pipeline:

```bash
# Exit with error if critical/high severity issues found
securerabbit scan --static-only --format json --output results.json
```

### Pre-Commit Hook

Add SecureRabbit to your pre-commit hooks:

```bash
#!/bin/bash
# .git/hooks/pre-commit

securerabbit scan --mode diff --static-only
if [ $? -ne 0 ]; then
    echo "Security issues detected. Please fix before committing."
    exit 1
fi
```

### Scanning Specific Directories

```bash
# Scan only a specific directory
cd /path/to/your/project/src/auth
securerabbit scan .
```

### Custom Output Location

```bash
securerabbit scan --output reports/security-$(date +%Y%m%d).md
```

## Troubleshooting

### "API key not found"

Make sure you've set the environment variable:
```bash
echo $OPENAI_API_KEY  # Should print your key
```

### "No files selected for analysis"

Check your `.securerabbit.yml` ignore patterns. You might be excluding too many files.

### "Rate limit exceeded"

Reduce concurrency in `.securerabbit.yml`:
```yaml
scan:
  max_concurrency: 2  # Lower number
```

Or use static-only mode:
```bash
securerabbit scan --static-only
```

### "File not found" errors

Ensure you're running SecureRabbit from your project root directory.

## Next Steps

- Read the [Usage Guide](./usage.md) for advanced features
- Configure [custom rules](./configuration.md)
- Learn about [security best practices](./security.md)
- Integrate with your CI/CD pipeline

## Getting Help

- 📖 Check the [full documentation](./usage.md)
- 🐛 [Report issues](https://github.com/deepam02/securerabbit/issues)
- 💬 [Ask questions](https://github.com/deepam02/securerabbit/discussions)

---

**Ready to secure your code? Run your first scan now!** 🚀
