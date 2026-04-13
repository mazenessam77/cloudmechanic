package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cloudmechanic/cloudmechanic/internal/scanner"
	"github.com/fatih/color"
)

var (
	critical = color.New(color.FgRed, color.Bold)
	warning  = color.New(color.FgYellow, color.Bold)
	success  = color.New(color.FgGreen, color.Bold)
	header   = color.New(color.FgCyan, color.Bold)
	dim      = color.New(color.Faint)
)

// Print renders the scan results in the specified format.
func Print(w io.Writer, issues []scanner.Issue, errors []error, elapsed time.Duration, format string) {
	switch format {
	case "json":
		printJSON(w, issues, errors, elapsed)
	case "csv":
		printCSV(w, issues)
	default:
		printTable(w, issues, errors, elapsed)
	}
}

// printTable renders the color-coded terminal report.
func printTable(w io.Writer, issues []scanner.Issue, errors []error, elapsed time.Duration) {
	fmt.Fprintln(w)
	header.Fprintln(w, "=== CloudMechanic Scan Report ===")
	fmt.Fprintln(w)

	if len(errors) > 0 {
		critical.Fprintf(w, "Scanner Errors (%d):\n", len(errors))
		for _, err := range errors {
			fmt.Fprintf(w, "  - %s\n", err)
		}
		fmt.Fprintln(w)
	}

	if len(issues) == 0 {
		success.Fprintln(w, "No issues found. Your account looks clean!")
		printSummary(w, issues, elapsed)
		return
	}

	criticals := filterBySeverity(issues, scanner.SeverityCritical)
	warnings := filterBySeverity(issues, scanner.SeverityWarning)

	if len(criticals) > 0 {
		critical.Fprintf(w, "Security Issues (%d):\n", len(criticals))
		for _, issue := range criticals {
			printIssue(w, issue, critical, "\xf0\x9f\x94\xb4")
		}
		fmt.Fprintln(w)
	}

	if len(warnings) > 0 {
		warning.Fprintf(w, "Cost Leaks (%d):\n", len(warnings))
		for _, issue := range warnings {
			printIssue(w, issue, warning, "\xf0\x9f\x9f\xa1")
		}
		fmt.Fprintln(w)
	}

	printSummary(w, issues, elapsed)
}

func printIssue(w io.Writer, issue scanner.Issue, c *color.Color, emoji string) {
	c.Fprintf(w, "  %s [%s] %s\n", emoji, issue.Severity, issue.Description)
	dim.Fprintf(w, "     Resource: %s\n", issue.ResourceID)
	dim.Fprintf(w, "     Fix:      %s\n", issue.Suggestion)
}

func printSummary(w io.Writer, issues []scanner.Issue, elapsed time.Duration) {
	critCount := len(filterBySeverity(issues, scanner.SeverityCritical))
	warnCount := len(filterBySeverity(issues, scanner.SeverityWarning))

	fmt.Fprintln(w, strings.Repeat("-", 50))
	success.Fprintf(w, "\xe2\x9c\x85 Scan complete in %s\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "   Total issues: %d (", len(issues))
	critical.Fprintf(w, "%d critical", critCount)
	fmt.Fprint(w, ", ")
	warning.Fprintf(w, "%d warnings", warnCount)
	fmt.Fprintln(w, ")")
	fmt.Fprintln(w)
}

// jsonReport is the structure written for JSON output.
type jsonReport struct {
	Summary jsonSummary    `json:"summary"`
	Issues  []jsonIssue    `json:"issues"`
	Errors  []string       `json:"errors,omitempty"`
}

type jsonSummary struct {
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
	Warnings int    `json:"warnings"`
	Elapsed  string `json:"elapsed"`
}

type jsonIssue struct {
	Severity    string `json:"severity"`
	Scanner     string `json:"scanner"`
	ResourceID  string `json:"resource_id"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

func printJSON(w io.Writer, issues []scanner.Issue, errors []error, elapsed time.Duration) {
	r := jsonReport{
		Summary: jsonSummary{
			Total:    len(issues),
			Critical: len(filterBySeverity(issues, scanner.SeverityCritical)),
			Warnings: len(filterBySeverity(issues, scanner.SeverityWarning)),
			Elapsed:  elapsed.Round(time.Millisecond).String(),
		},
	}

	for _, issue := range issues {
		r.Issues = append(r.Issues, jsonIssue{
			Severity:    issue.Severity.String(),
			Scanner:     issue.Scanner,
			ResourceID:  issue.ResourceID,
			Description: issue.Description,
			Suggestion:  issue.Suggestion,
		})
	}

	for _, err := range errors {
		r.Errors = append(r.Errors, err.Error())
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}

func printCSV(w io.Writer, issues []scanner.Issue) {
	cw := csv.NewWriter(w)
	cw.Write([]string{"severity", "scanner", "resource_id", "description", "suggestion"})
	for _, issue := range issues {
		cw.Write([]string{
			issue.Severity.String(),
			issue.Scanner,
			issue.ResourceID,
			issue.Description,
			issue.Suggestion,
		})
	}
	cw.Flush()
}

func filterBySeverity(issues []scanner.Issue, sev scanner.Severity) []scanner.Issue {
	var filtered []scanner.Issue
	for _, i := range issues {
		if i.Severity == sev {
			filtered = append(filtered, i)
		}
	}
	return filtered
}
