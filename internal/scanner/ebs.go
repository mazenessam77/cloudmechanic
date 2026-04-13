package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2DescribeVolumesAPI is the interface for the EC2 DescribeVolumes call.
// Using an interface allows us to mock the AWS client in tests.
type EC2DescribeVolumesAPI interface {
	DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

// UnattachedEBSScanner finds EBS volumes that are not attached to any instance.
type UnattachedEBSScanner struct {
	Client EC2DescribeVolumesAPI
}

func (s *UnattachedEBSScanner) Name() string {
	return "Unattached EBS Volumes"
}

func (s *UnattachedEBSScanner) Scan(ctx context.Context) ([]Issue, error) {
	input := &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"available"},
			},
		},
	}

	result, err := s.Client.DescribeVolumes(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("ebs scanner: %w", err)
	}

	var issues []Issue
	for _, vol := range result.Volumes {
		volID := aws.ToString(vol.VolumeId)
		sizeGiB := aws.ToInt32(vol.Size)

		issues = append(issues, Issue{
			Severity:    SeverityWarning,
			Scanner:     s.Name(),
			ResourceID:  volID,
			Description: fmt.Sprintf("EBS volume %s (%d GiB, %s) is not attached to any instance", volID, sizeGiB, vol.VolumeType),
			Suggestion:  "Delete the volume or create a snapshot and then delete it to stop incurring charges.",
		})
	}

	return issues, nil
}
