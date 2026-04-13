package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cloudmechanic",
	Short: "CloudMechanic - An OBD scanner for your AWS environment",
	Long: `CloudMechanic (sre-scan) quickly scans your AWS account to find
cost leaks and security vulnerabilities, outputting a color-coded,
actionable report in the terminal.`,
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
