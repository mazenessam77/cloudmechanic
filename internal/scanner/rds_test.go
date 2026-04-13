package scanner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type mockRDS struct {
	output *rds.DescribeDBInstancesOutput
	err    error
}

func (m *mockRDS) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return m.output, m.err
}

type mockCloudWatch struct {
	output *cloudwatch.GetMetricDataOutput
	err    error
}

func (m *mockCloudWatch) GetMetricData(ctx context.Context, params *cloudwatch.GetMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	return m.output, m.err
}

func TestIdleRDSScanner_FindsIdleInstance(t *testing.T) {
	s := &IdleRDSScanner{
		RDS: &mockRDS{
			output: &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier: aws.String("mydb"),
						DBInstanceClass:      aws.String("db.t3.micro"),
						Engine:               aws.String("postgres"),
					},
				},
			},
		},
		CloudWatch: &mockCloudWatch{
			output: &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{
						Id:     aws.String("db_conns"),
						Values: []float64{0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
		},
	}

	issues, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if issues[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING, got %s", issues[0].Severity)
	}
}

func TestIdleRDSScanner_ActiveInstanceIsClean(t *testing.T) {
	s := &IdleRDSScanner{
		RDS: &mockRDS{
			output: &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier: aws.String("active-db"),
						DBInstanceClass:      aws.String("db.r5.large"),
						Engine:               aws.String("mysql"),
					},
				},
			},
		},
		CloudWatch: &mockCloudWatch{
			output: &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{
						Id:     aws.String("db_conns"),
						Values: []float64{5, 12, 8, 3, 15, 22, 7},
					},
				},
			},
		},
	}

	issues, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected 0 issues, got %d", len(issues))
	}
}
