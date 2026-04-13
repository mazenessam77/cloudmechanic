package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/cloudmechanic/cloudmechanic/internal/report"
	"github.com/cloudmechanic/cloudmechanic/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	flagRegion  string
	flagProfile string
)

func init() {
	scanCmd.Flags().StringVar(&flagRegion, "region", "", "AWS region to scan (defaults to AWS_REGION or config)")
	scanCmd.Flags().StringVar(&flagProfile, "profile", "", "AWS named profile to use")
	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all scanners against your AWS account",
	RunE:  runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	start := time.Now()

	// Build AWS config
	var cfgOpts []func(*awsconfig.LoadOptions) error
	if flagRegion != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(flagRegion))
	}
	if flagProfile != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithSharedConfigProfile(flagProfile))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return fmt.Errorf("unable to load AWS config: %w", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)

	// Register all scanners
	scanners := []scanner.Scanner{
		&scanner.UnattachedEBSScanner{Client: ec2Client},
		&scanner.OpenSecurityGroupScanner{Client: ec2Client},
	}

	// Run scanners concurrently
	issues, errs := runScanners(ctx, scanners)

	// Render report
	report.Print(os.Stdout, issues, errs, time.Since(start))

	return nil
}

// runScanners executes all scanners concurrently using goroutines and channels.
func runScanners(ctx context.Context, scanners []scanner.Scanner) ([]scanner.Issue, []error) {
	type result struct {
		issues []scanner.Issue
		err    error
	}

	ch := make(chan result, len(scanners))
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(s scanner.Scanner) {
			defer wg.Done()
			issues, err := s.Scan(ctx)
			ch <- result{issues: issues, err: err}
		}(s)
	}

	// Close channel once all goroutines complete
	go func() {
		wg.Wait()
		close(ch)
	}()

	var allIssues []scanner.Issue
	var allErrors []error
	for r := range ch {
		if r.err != nil {
			allErrors = append(allErrors, r.err)
			continue
		}
		allIssues = append(allIssues, r.issues...)
	}

	return allIssues, allErrors
}
