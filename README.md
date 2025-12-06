# SecureRabbit 🐰🔒

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/deepam02/securerabbit)

SecureRabbit is an advanced security code analysis tool that combines **static analysis** with **AI-powered deep reasoning** to detect OWASP Top 10 vulnerabilities in your codebase.

## 🚀 Quick Start

```bash
# Install
go install github.com/deepam02/securerabbit/cmd/securerabbit@latest

# Initialize configuration
securerabbit init

# Run your first scan
export OPENAI_API_KEY="your-api-key"
securerabbit scan --mode smart
```

## ✨ Key Features

- 🔍 **Hybrid Analysis Engine** - Combines static rules with LLM intelligence
- 🤖 **Multi-LLM Support** - Works with OpenAI, Anthropic Claude, and Google Gemini
- 🎯 **Smart Scanning** - Prioritizes high-risk files for efficient analysis
- 📊 **Multiple Scan Modes** - Deep, Smart, and Git Diff scanning
- 🛡️ **OWASP Top 10 Coverage** - Comprehensive security vulnerability detection
- 📝 **Flexible Reports** - JSON and Markdown output formats
- ⚡ **Fast & Concurrent** - Parallel processing for large codebases

## 📖 Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- 📘 **[Getting Started](docs/getting-started.md)** - Installation, setup, and your first scan
- 📗 **[Usage Guide](docs/usage.md)** - Complete command reference and examples
- 📙 **[Configuration](docs/configuration.md)** - Configure LLM providers, rules, and output
- 🔒 **[Security](docs/security.md)** - Best practices, API key management, and compliance

## 🎯 Use Cases

- **Pre-commit Hooks** - Catch vulnerabilities before they reach your repository
- **CI/CD Pipelines** - Automated security scanning in your build process
- **Code Reviews** - AI-assisted security review for pull requests
- **Security Audits** - Comprehensive analysis of existing codebases
- **Developer Training** - Learn secure coding practices through detailed findings

## 🛠️ Supported Languages

- ✅ Go (with AST analysis)
- ✅ Python
- ✅ JavaScript/TypeScript
- ✅ Java
- ✅ C/C++
- ✅ C#
- ✅ Ruby
- ✅ PHP

## 📊 Example Output

```markdown
# SecureRabbit Security Scan Report

**Generated:** 2024-12-06 14:30:45

## Summary
- Files Scanned: 42
- Total Findings: 8
- Critical: 2 | High: 3 | Medium: 2 | Low: 1

### Critical Issues
🔴 Hardcoded AWS Access Key (Line 45)
🔴 SQL Injection Vulnerability (Line 123)
```

## 🤝 Contributing

We welcome contributions! Please check out the documentation and feel free to open issues or submit pull requests.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Credits

Developed by [@deepam02](https://github.com/deepam02)

---

**Need Help?** Check out our [Getting Started Guide](docs/getting-started.md) or [open an issue](https://github.com/deepam02/securerabbit/issues).
