package rules

import (
	"context"
	
	"github.com/deepam02/securerabbit/internal/types"
)

// Engine coordinates all rule execution
type Engine struct {
	gosecEnabled bool
	regexEnabled bool
	astEnabled   bool
	
	gosecEngine *GosecEngine
	regexEngine *RegexEngine
	astEngine   *ASTEngine
}

// NewEngine creates a new rule engine
func NewEngine(gosecEnabled, regexEnabled, astEnabled bool) *Engine {
	engine := &Engine{
		gosecEnabled: gosecEnabled,
		regexEnabled: regexEnabled,
		astEnabled:   astEnabled,
	}
	
	if gosecEnabled {
		engine.gosecEngine = NewGosecEngine()
	}
	if regexEnabled {
		engine.regexEngine = NewRegexEngine()
	}
	if astEnabled {
		engine.astEngine = NewASTEngine()
	}
	
	return engine
}

// AnalyzeFile runs all enabled rule engines on a file
func (e *Engine) AnalyzeFile(ctx context.Context, filePath string) ([]types.Finding, error) {
	allFindings := make([]types.Finding, 0)
	
	// Run Gosec
	if e.gosecEnabled && e.gosecEngine != nil {
		findings, err := e.gosecEngine.Analyze(ctx, filePath)
		if err != nil {
			// Log error but continue with other engines
			// TODO: Add proper logging
		} else {
			allFindings = append(allFindings, findings...)
		}
	}
	
	// Run Regex rules
	if e.regexEnabled && e.regexEngine != nil {
		findings, err := e.regexEngine.Analyze(ctx, filePath)
		if err != nil {
			// Log error but continue
		} else {
			allFindings = append(allFindings, findings...)
		}
	}
	
	// Run AST rules
	if e.astEnabled && e.astEngine != nil {
		findings, err := e.astEngine.Analyze(ctx, filePath)
		if err != nil {
			// Log error but continue
		} else {
			allFindings = append(allFindings, findings...)
		}
	}
	
	return allFindings, nil
}

// AnalyzeProject runs all engines on the entire project
func (e *Engine) AnalyzeProject(ctx context.Context, projectPath string, languages []string) ([]types.Finding, error) {
	// This will be implemented to scan all files in project
	// For now, return empty
	return []types.Finding{}, nil
}
