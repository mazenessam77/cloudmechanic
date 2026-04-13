package scanner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockDescribeVolumes struct {
	output *ec2.DescribeVolumesOutput
	err    error
}

func (m *mockDescribeVolumes) DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return m.output, m.err
}

func TestUnattachedEBSScanner_FindsAvailableVolumes(t *testing.T) {
	s := &UnattachedEBSScanner{
		Client: &mockDescribeVolumes{
			output: &ec2.DescribeVolumesOutput{
				Volumes: []types.Volume{
					{
						VolumeId:   aws.String("vol-111"),
						Size:       aws.Int32(100),
						VolumeType: types.VolumeTypeGp3,
					},
					{
						VolumeId:   aws.String("vol-222"),
						Size:       aws.Int32(50),
						VolumeType: types.VolumeTypeGp2,
					},
				},
			},
		},
	}

	issues, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
	if issues[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", issues[0].Severity)
	}
	if issues[0].ResourceID != "vol-111" {
		t.Errorf("expected vol-111, got %s", issues[0].ResourceID)
	}
}

func TestUnattachedEBSScanner_NoVolumes(t *testing.T) {
	s := &UnattachedEBSScanner{
		Client: &mockDescribeVolumes{
			output: &ec2.DescribeVolumesOutput{Volumes: []types.Volume{}},
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
