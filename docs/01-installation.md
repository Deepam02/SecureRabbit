# Installation Guide

## Prerequisites

- **Go 1.21 or higher**
- **Git** (for diff scanning mode)
- **LLM API Key** (optional, for AI-powered analysis)

## Installation Methods

### Method 1: Install with Go

```bash
go install github.com/deepam02/securerabbit/cmd/securerabbit@latest
```

This will install the `securerabbit` binary to your `$GOPATH/bin` directory.

### Method 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/deepam02/securerabbit.git
cd securerabbit

# Build the binary
go build -o bin/securerabbit ./cmd/securerabbit

# Optional: Move to PATH
sudo mv bin/securerabbit /usr/local/bin/
```

### Method 3: Download Pre-built Binary

Download the latest release from the [GitHub Releases](https://github.com/deepam02/securerabbit/releases) page.

```bash
# Linux/macOS
chmod +x securerabbit
sudo mv securerabbit /usr/local/bin/

# Windows
# Add the directory containing securerabbit.exe to your PATH
```

## Verify Installation

```bash
securerabbit version
```

Expected output:
```
SecureRabbit v1.0.0
Security Code Analysis Tool
https://github.com/deepam02/securerabbit
```

## Setup API Keys

For LLM-powered analysis, set up your API key:

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# Google Gemini
export GEMINI_API_KEY="..."
```

To make these permanent, add them to your `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
```

## Next Steps

- [Quick Start Tutorial](02-quick-start.md)
- [Configuration Guide](03-configuration.md)
