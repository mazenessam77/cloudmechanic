package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Set via ldflags at build time by GoReleaser.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of CloudMechanic",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("CloudMechanic %s (commit: %s, built: %s)\n", Version, Commit, Date)
	},
}
