package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EC2DescribeSecurityGroupsAPI is the interface for the EC2 DescribeSecurityGroups call.
type EC2DescribeSecurityGroupsAPI interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// OpenSecurityGroupScanner finds security groups with SSH (port 22) open to the world.
type OpenSecurityGroupScanner struct {
	Client EC2DescribeSecurityGroupsAPI
}

func (s *OpenSecurityGroupScanner) Name() string {
	return "Open Security Groups (SSH)"
}

func (s *OpenSecurityGroupScanner) Scan(ctx context.Context) ([]Issue, error) {
	input := &ec2.DescribeSecurityGroupsInput{}

	result, err := s.Client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("security group scanner: %w", err)
	}

	var issues []Issue
	for _, sg := range result.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)

		for _, perm := range sg.IpPermissions {
			if !isSSHPort(perm.FromPort, perm.ToPort, perm.IpProtocol) {
				continue
			}

			for _, ipRange := range perm.IpRanges {
				cidr := aws.ToString(ipRange.CidrIp)
				if cidr == "0.0.0.0/0" {
					issues = append(issues, Issue{
						Severity:    SeverityCritical,
						Scanner:     s.Name(),
						ResourceID:  sgID,
						Description: fmt.Sprintf("Security Group %s (%s) allows SSH (port 22) from 0.0.0.0/0", sgID, sgName),
						Suggestion:  "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager instead.",
					})
				}
			}

			for _, ipv6Range := range perm.Ipv6Ranges {
				cidr := aws.ToString(ipv6Range.CidrIpv6)
				if cidr == "::/0" {
					issues = append(issues, Issue{
						Severity:    SeverityCritical,
						Scanner:     s.Name(),
						ResourceID:  sgID,
						Description: fmt.Sprintf("Security Group %s (%s) allows SSH (port 22) from ::/0", sgID, sgName),
						Suggestion:  "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager instead.",
					})
				}
			}
		}
	}

	return issues, nil
}

// isSSHPort checks if the permission covers port 22.
// Handles explicit port 22 as well as rules with protocol "-1" (all traffic).
func isSSHPort(fromPort, toPort *int32, protocol *string) bool {
	proto := aws.ToString(protocol)
	if proto == "-1" {
		return true // all traffic includes SSH
	}
	if proto != "tcp" {
		return false
	}
	from := aws.ToInt32(fromPort)
	to := aws.ToInt32(toPort)
	return from <= 22 && to >= 22
}
