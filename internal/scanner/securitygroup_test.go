package scanner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockDescribeSGs struct {
	output *ec2.DescribeSecurityGroupsOutput
	err    error
}

func (m *mockDescribeSGs) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return m.output, m.err
}

func TestOpenSGScanner_FindsOpenSSH(t *testing.T) {
	s := &OpenSecurityGroupScanner{
		Client: &mockDescribeSGs{
			output: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-open"),
						GroupName: aws.String("launch-wizard-1"),
						IpPermissions: []types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(22),
								ToPort:     aws.Int32(22),
								IpRanges: []types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
						},
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
	if issues[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", issues[0].Severity)
	}
}

func TestOpenSGScanner_IgnoresRestrictedSSH(t *testing.T) {
	s := &OpenSecurityGroupScanner{
		Client: &mockDescribeSGs{
			output: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-safe"),
						GroupName: aws.String("restricted-sg"),
						IpPermissions: []types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(22),
								ToPort:     aws.Int32(22),
								IpRanges: []types.IpRange{
									{CidrIp: aws.String("10.0.0.0/8")},
								},
							},
						},
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

func TestOpenSGScanner_DetectsIPv6Open(t *testing.T) {
	s := &OpenSecurityGroupScanner{
		Client: &mockDescribeSGs{
			output: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-ipv6"),
						GroupName: aws.String("ipv6-open"),
						IpPermissions: []types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(22),
								ToPort:     aws.Int32(22),
								Ipv6Ranges: []types.Ipv6Range{
									{CidrIpv6: aws.String("::/0")},
								},
							},
						},
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
}

func TestOpenSGScanner_AllTrafficProtocol(t *testing.T) {
	s := &OpenSecurityGroupScanner{
		Client: &mockDescribeSGs{
			output: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []types.SecurityGroup{
					{
						GroupId:   aws.String("sg-all"),
						GroupName: aws.String("all-traffic"),
						IpPermissions: []types.IpPermission{
							{
								IpProtocol: aws.String("-1"),
								IpRanges: []types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
						},
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
}
