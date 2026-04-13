package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/cloudmechanic/cloudmechanic/internal/report"
	"github.com/cloudmechanic/cloudmechanic/internal/scanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	flagRegion     string
	flagProfile    string
	flagOutput     string
	flagAllRegions bool
)

func init() {
	scanCmd.Flags().StringVar(&flagRegion, "region", "", "AWS region to scan (defaults to AWS_REGION or config)")
	scanCmd.Flags().StringVar(&flagProfile, "profile", "", "AWS named profile to use")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "table", "Output format: table, json, csv")
	scanCmd.Flags().BoolVar(&flagAllRegions, "all-regions", false, "Scan all available AWS regions")
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

	// Build base AWS config.
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

	// Determine which regions to scan.
	regions, err := resolveRegions(ctx, cfg)
	if err != nil {
		return err
	}

	if flagOutput == "table" {
		info := color.New(color.FgCyan)
		if len(regions) > 1 {
			info.Fprintf(os.Stderr, "Scanning %d regions...\n", len(regions))
		}
	}

	// Build scanners for each region.
	var allScanners []scanner.Scanner
	for _, region := range regions {
		regionCfg := cfg.Copy()
		regionCfg.Region = region

		ec2Client := ec2.NewFromConfig(regionCfg)
		s3Client := s3.NewFromConfig(regionCfg)
		rdsClient := rds.NewFromConfig(regionCfg)
		cwClient := cloudwatch.NewFromConfig(regionCfg)
		stsClient := sts.NewFromConfig(regionCfg)

		allScanners = append(allScanners,
			&scanner.UnattachedEBSScanner{Client: ec2Client},
			&scanner.OpenSecurityGroupScanner{Client: ec2Client},
			&scanner.PublicS3Scanner{Client: s3Client},
			&scanner.IdleRDSScanner{RDS: rdsClient, CloudWatch: cwClient},
			&scanner.UnusedEIPScanner{Client: ec2Client},
			&scanner.OldSnapshotScanner{EC2: ec2Client, STS: stsClient},
		)
	}

	// IAM is global — only run once regardless of region count.
	iamClient := iam.NewFromConfig(cfg)
	allScanners = append(allScanners, &scanner.NoMFAScanner{Client: iamClient})

	// Run all scanners concurrently.
	issues, errs := runScanners(ctx, allScanners)

	// Render report.
	report.Print(os.Stdout, issues, errs, time.Since(start), flagOutput)

	return nil
}

// resolveRegions returns the list of regions to scan.
func resolveRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	if !flagAllRegions {
		region := cfg.Region
		if region == "" {
			region = "us-east-1"
		}
		return []string{region}, nil
	}

	ec2Client := ec2.NewFromConfig(cfg)
	out, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("opt-in-status"),
				Values: []string{"opt-in-not-required", "opted-in"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list regions: %w", err)
	}

	var regions []string
	for _, r := range out.Regions {
		regions = append(regions, aws.ToString(r.RegionName))
	}
	return regions, nil
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

	// Close channel once all goroutines complete.
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
