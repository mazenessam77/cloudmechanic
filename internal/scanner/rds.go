package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// RDSAPI is the interface for the RDS calls used by this scanner.
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// CloudWatchAPI is the interface for the CloudWatch calls used by this scanner.
type CloudWatchAPI interface {
	GetMetricData(ctx context.Context, params *cloudwatch.GetMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

// IdleRDSScanner finds RDS instances with zero connections over the last 7 days.
type IdleRDSScanner struct {
	RDS        RDSAPI
	CloudWatch CloudWatchAPI
}

func (s *IdleRDSScanner) Name() string {
	return "Idle RDS Instances"
}

func (s *IdleRDSScanner) Scan(ctx context.Context) ([]Issue, error) {
	descOut, err := s.RDS.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("rds scanner: %w", err)
	}

	var issues []Issue
	now := time.Now().UTC()
	lookback := now.Add(-7 * 24 * time.Hour)

	for _, db := range descOut.DBInstances {
		dbID := aws.ToString(db.DBInstanceIdentifier)
		dbClass := aws.ToString(db.DBInstanceClass)
		engine := aws.ToString(db.Engine)

		idle, err := s.hasZeroConnections(ctx, dbID, lookback, now)
		if err != nil {
			// Skip instances we can't get metrics for rather than failing the whole scan.
			continue
		}

		if idle {
			issues = append(issues, Issue{
				Severity:    SeverityWarning,
				Scanner:     s.Name(),
				ResourceID:  dbID,
				Description: fmt.Sprintf("RDS instance %s (%s, %s) has had 0 connections in the last 7 days", dbID, engine, dbClass),
				Suggestion:  "Consider stopping or deleting this instance, or taking a final snapshot and removing it.",
			})
		}
	}

	return issues, nil
}

// hasZeroConnections checks CloudWatch DatabaseConnections metric over the given window.
// Returns true if the maximum connection count across the period is 0.
func (s *IdleRDSScanner) hasZeroConnections(ctx context.Context, dbID string, start, end time.Time) (bool, error) {
	metricID := "db_conns"
	out, err := s.CloudWatch.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
		StartTime: &start,
		EndTime:   &end,
		MetricDataQueries: []cwtypes.MetricDataQuery{
			{
				Id: aws.String(metricID),
				MetricStat: &cwtypes.MetricStat{
					Metric: &cwtypes.Metric{
						Namespace:  aws.String("AWS/RDS"),
						MetricName: aws.String("DatabaseConnections"),
						Dimensions: []cwtypes.Dimension{
							{
								Name:  aws.String("DBInstanceIdentifier"),
								Value: aws.String(dbID),
							},
						},
					},
					Period: aws.Int32(86400), // 1 day
					Stat:   aws.String("Maximum"),
				},
			},
		},
	})
	if err != nil {
		return false, fmt.Errorf("cloudwatch query for %s: %w", dbID, err)
	}

	for _, result := range out.MetricDataResults {
		if aws.ToString(result.Id) != metricID {
			continue
		}
		// If there are data points and any value > 0, it's not idle.
		for _, val := range result.Values {
			if val > 0 {
				return false, nil
			}
		}
	}

	// Zero data points or all values are 0 → idle.
	return true, nil
}
