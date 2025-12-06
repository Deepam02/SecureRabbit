package rules

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// ASTEngine uses AST analysis to detect security issues
type ASTEngine struct {
	rules []ASTRule
}

// ASTRule defines a security rule that operates on AST
type ASTRule interface {
	Check(node ast.Node, fset *token.FileSet, filePath string) []types.Finding
	ID() string
	Name() string
}

// NewASTEngine creates a new AST analysis engine
func NewASTEngine() *ASTEngine {
	return &ASTEngine{
		rules: getDefaultASTRules(),
	}
}

// Analyze parses and analyzes a Go file using AST
func (a *ASTEngine) Analyze(ctx context.Context, filePath string) ([]types.Finding, error) {
	// Only analyze Go files
	if !strings.HasSuffix(filePath, ".go") {
		return []types.Finding{}, nil
	}
	
	// Parse the file
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}
	
	findings := make([]types.Finding, 0)
	
	// Apply each rule
	for _, rule := range a.rules {
		ruleFindings := rule.Check(node, fset, filePath)
		findings = append(findings, ruleFindings...)
	}
	
	return findings, nil
}

// getDefaultASTRules returns the default set of AST rules
func getDefaultASTRules() []ASTRule {
	return []ASTRule{
		&WeakRandomRule{},
		&EmptyPasswordRule{},
		&ErrorIgnoredRule{},
	}
}

// WeakRandomRule detects use of weak random number generators
type WeakRandomRule struct{}

func (r *WeakRandomRule) ID() string   { return "AST001" }
func (r *WeakRandomRule) Name() string { return "Weak Random Number Generator" }

func (r *WeakRandomRule) Check(node ast.Node, fset *token.FileSet, filePath string) []types.Finding {
	findings := make([]types.Finding, 0)
	
	ast.Inspect(node, func(n ast.Node) bool {
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		
		// Check for math/rand usage
		if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := selExpr.X.(*ast.Ident); ok {
				if ident.Name == "rand" {
					pos := fset.Position(n.Pos())
					finding := types.Finding{
						Title:       "Weak Random Number Generator",
						Description: "Use of math/rand for security-sensitive operations. Use crypto/rand instead.",
						FilePath:    filePath,
						StartLine:   pos.Line,
						EndLine:     pos.Line,
						Severity:    types.SeverityMedium,
						OWASPID:     "A02:2021-Cryptographic Failures",
						CWE:         "CWE-338",
						Source:      types.SourceAST,
						Recommendation: "Replace math/rand with crypto/rand for security-sensitive random number generation.",
					}
					findings = append(findings, finding)
				}
			}
		}
		
		return true
	})
	
	return findings
}

// EmptyPasswordRule detects empty password checks
type EmptyPasswordRule struct{}

func (r *EmptyPasswordRule) ID() string   { return "AST002" }
func (r *EmptyPasswordRule) Name() string { return "Empty Password Check" }

func (r *EmptyPasswordRule) Check(node ast.Node, fset *token.FileSet, filePath string) []types.Finding {
	findings := make([]types.Finding, 0)
	
	ast.Inspect(node, func(n ast.Node) bool {
		// Look for empty string comparisons with password variables
		binExpr, ok := n.(*ast.BinaryExpr)
		if !ok || binExpr.Op != token.EQL {
			return true
		}
		
		// Check if one side is an identifier containing "password"
		var varName string
		if ident, ok := binExpr.X.(*ast.Ident); ok {
			varName = strings.ToLower(ident.Name)
		}
		
		if strings.Contains(varName, "password") || strings.Contains(varName, "passwd") {
			// Check if comparing to empty string
			if basicLit, ok := binExpr.Y.(*ast.BasicLit); ok {
				if basicLit.Kind == token.STRING && (basicLit.Value == `""` || basicLit.Value == "''") {
					pos := fset.Position(n.Pos())
					finding := types.Finding{
						Title:       "Weak Password Validation",
						Description: "Empty password check detected. Ensure proper password strength validation.",
						FilePath:    filePath,
						StartLine:   pos.Line,
						EndLine:     pos.Line,
						Severity:    types.SeverityMedium,
						OWASPID:     "A07:2021-Identification and Authentication Failures",
						CWE:         "CWE-521",
						Source:      types.SourceAST,
						Recommendation: "Implement proper password strength requirements including minimum length, complexity, and entropy checks.",
					}
					findings = append(findings, finding)
				}
			}
		}
		
		return true
	})
	
	return findings
}

// ErrorIgnoredRule detects ignored errors
type ErrorIgnoredRule struct{}

func (r *ErrorIgnoredRule) ID() string   { return "AST003" }
func (r *ErrorIgnoredRule) Name() string { return "Error Ignored" }

func (r *ErrorIgnoredRule) Check(node ast.Node, fset *token.FileSet, filePath string) []types.Finding {
	findings := make([]types.Finding, 0)
	
	ast.Inspect(node, func(n ast.Node) bool {
		assignStmt, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		
		// Look for assignments with _ on the right side (ignored errors)
		for i, lhs := range assignStmt.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "_" {
				// Check if this is likely an error return
				if i == len(assignStmt.Lhs)-1 {
					pos := fset.Position(n.Pos())
					
					// Get code snippet
					source, _ := os.ReadFile(filePath)
					lines := strings.Split(string(source), "\n")
					snippet := ""
					if pos.Line > 0 && pos.Line <= len(lines) {
						snippet = lines[pos.Line-1]
					}
					
					finding := types.Finding{
						Title:       "Ignored Error Return Value",
						Description: "Error return value is explicitly ignored, which may lead to unhandled errors.",
						FilePath:    filePath,
						StartLine:   pos.Line,
						EndLine:     pos.Line,
						Severity:    types.SeverityLow,
						OWASPID:     "A09:2021-Security Logging and Monitoring Failures",
						CWE:         "CWE-391",
						Source:      types.SourceAST,
						CodeSnippet: snippet,
						Recommendation: "Handle or log errors appropriately instead of ignoring them.",
					}
					findings = append(findings, finding)
				}
			}
		}
		
		return true
	})
	
	return findings
}
