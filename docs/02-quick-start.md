# Quick Start Tutorial

Get started with SecureRabbit in 5 minutes!

## Step 1: Initialize Configuration

```bash
cd your-project
securerabbit init
```

This creates a `.securerabbit.yml` file with default settings.

## Step 2: Configure Your LLM Provider (Optional)

Edit `.securerabbit.yml`:

```yaml
llm:
  provider: "openai"
  model: "gpt-4"
  api_key_env: "OPENAI_API_KEY"
```

Set your API key:
```bash
export OPENAI_API_KEY="your-api-key-here"
```

## Step 3: Run Your First Scan

### Smart Scan (Recommended)
Analyzes high-risk files only:
```bash
securerabbit scan --mode smart
```

### Deep Scan
Full project analysis:
```bash
securerabbit scan --mode deep
```

### Diff Scan
Only changed files (requires Git):
```bash
securerabbit scan --mode diff
```

### Static-Only Scan
No LLM, faster:
```bash
securerabbit scan --static-only
```

## Step 4: Review the Report

By default, the report is saved to `./securerabbit-report.md`:

```bash
# View in terminal
cat securerabbit-report.md

# Open in your editor
code securerabbit-report.md
```

## Example Output

```markdown
# SecureRabbit Security Scan Report

## Summary
- Files Scanned: 42
- Total Findings: 8
- Critical: 2 | High: 3 | Medium: 2 | Low: 1

### Findings by File

#### src/auth/login.go
🔴 **Hardcoded Password** (Line 45)
Description: Password is hardcoded in source code...
Recommendation: Use environment variables or secret management...
```

## Common Options

```bash
# Custom output format
securerabbit scan --format json --output results.json

# Specific path
securerabbit scan --path ./src

# Different LLM provider
securerabbit scan --llm-provider anthropic

# Help
securerabbit scan --help
```

## Next Steps

- [Configuration Guide](03-configuration.md) - Customize your setup
- [Scan Modes](05-scan-modes.md) - Learn about different scan modes
- [CLI Usage](08-cli-usage.md) - Complete CLI reference
