package scanner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockDescribeAddresses struct {
	output *ec2.DescribeAddressesOutput
	err    error
}

func (m *mockDescribeAddresses) DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return m.output, m.err
}

func TestUnusedEIPScanner_FindsUnassociated(t *testing.T) {
	s := &UnusedEIPScanner{
		Client: &mockDescribeAddresses{
			output: &ec2.DescribeAddressesOutput{
				Addresses: []types.Address{
					{
						AllocationId: aws.String("eipalloc-111"),
						PublicIp:     aws.String("54.1.2.3"),
						// No AssociationId — unattached
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

func TestUnusedEIPScanner_SkipsAssociated(t *testing.T) {
	s := &UnusedEIPScanner{
		Client: &mockDescribeAddresses{
			output: &ec2.DescribeAddressesOutput{
				Addresses: []types.Address{
					{
						AllocationId:  aws.String("eipalloc-222"),
						PublicIp:      aws.String("54.4.5.6"),
						AssociationId: aws.String("eipassoc-abc"),
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
