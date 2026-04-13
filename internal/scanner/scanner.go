package scanner

import "context"

// Severity represents the severity level of a discovered issue.
type Severity int

const (
	SeverityWarning  Severity = iota // Cost leaks
	SeverityCritical                 // Security faults
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityWarning:
		return "WARNING"
	default:
		return "UNKNOWN"
	}
}

// Issue represents a single finding from a scanner.
type Issue struct {
	Severity    Severity
	Scanner     string
	ResourceID  string
	Description string
	Suggestion  string
}

// Scanner is the interface that all specific checks must implement.
type Scanner interface {
	Name() string
	Scan(ctx context.Context) ([]Issue, error)
}
