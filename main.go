package main

import (
	"os"

	"github.com/cloudmechanic/cloudmechanic/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
