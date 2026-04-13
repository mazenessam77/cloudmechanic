package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EC2DescribeAddressesAPI is the interface for the EC2 DescribeAddresses call.
type EC2DescribeAddressesAPI interface {
	DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

// UnusedEIPScanner finds Elastic IPs that are not associated with any instance or network interface.
type UnusedEIPScanner struct {
	Client EC2DescribeAddressesAPI
}

func (s *UnusedEIPScanner) Name() string {
	return "Unused Elastic IPs"
}

func (s *UnusedEIPScanner) Scan(ctx context.Context) ([]Issue, error) {
	result, err := s.Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("eip scanner: %w", err)
	}

	var issues []Issue
	for _, addr := range result.Addresses {
		if addr.AssociationId != nil {
			continue // associated — skip
		}

		allocID := aws.ToString(addr.AllocationId)
		publicIP := aws.ToString(addr.PublicIp)

		issues = append(issues, Issue{
			Severity:    SeverityWarning,
			Scanner:     s.Name(),
			ResourceID:  allocID,
			Description: fmt.Sprintf("Elastic IP %s (%s) is not associated with any resource", publicIP, allocID),
			Suggestion:  "Release this Elastic IP to stop incurring charges ($3.60/month when unattached).",
		})
	}

	return issues, nil
}
