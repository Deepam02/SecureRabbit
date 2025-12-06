package types

import "time"

// ScanMode defines the type of scan to perform
type ScanMode string

const (
	ScanModeDeep  ScanMode = "deep"
	ScanModeSmart ScanMode = "smart"
	ScanModeDiff  ScanMode = "diff"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingSource indicates where the finding originated
type FindingSource string

const (
	SourceGosec  FindingSource = "gosec"
	SourceRegex  FindingSource = "regex"
	SourceAST    FindingSource = "ast"
	SourceLLM    FindingSource = "llm"
)

// Finding represents a single security issue
type Finding struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	FilePath    string        `json:"file_path"`
	StartLine   int           `json:"start_line"`
	EndLine     int           `json:"end_line"`
	Severity    Severity      `json:"severity"`
	Confidence  string        `json:"confidence,omitempty"`
	OWASPID     string        `json:"owasp_id,omitempty"`
	CWE         string        `json:"cwe,omitempty"`
	Source      FindingSource `json:"source"`
	CodeSnippet string        `json:"code_snippet,omitempty"`
	Recommendation string     `json:"recommendation,omitempty"`
	RawOutput   string        `json:"raw_output,omitempty"`
}

// ScanResult contains all findings from a scan
type ScanResult struct {
	ProjectPath   string      `json:"project_path"`
	ScanMode      ScanMode    `json:"scan_mode"`
	StartTime     time.Time   `json:"start_time"`
	EndTime       time.Time   `json:"end_time"`
	Duration      string      `json:"duration"`
	FilesScanned  int         `json:"files_scanned"`
	Findings      []Finding   `json:"findings"`
	StaticOnly    bool        `json:"static_only"`
	LLMProvider   string      `json:"llm_provider,omitempty"`
	TotalFindings int         `json:"total_findings"`
}

// FileInfo represents metadata about a file to be scanned
type FileInfo struct {
	Path           string
	Language       string
	RiskScore      float64
	StaticFindings int
	LOC            int
	HasCrypto      bool
	HasDatabase    bool
	HasAuth        bool
	GitChurn       int
}

// CodeChunk represents a portion of code to analyze
type CodeChunk struct {
	FilePath    string
	Language    string
	StartLine   int
	EndLine     int
	Content     string
	StaticIssues []Finding
}

// ScanContext holds the runtime context for a scan operation
type ScanContext struct {
	ProjectPath     string
	Mode            ScanMode
	Languages       []string
	StaticOnly      bool
	LLMProvider     string
	OutputFormat    string
	OutputPath      string
	IgnorePaths     []string
	MaxConcurrency  int
	ChangedFilesOnly bool
}
