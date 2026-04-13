package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// STSAPI is the interface for the STS GetCallerIdentity call.
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// EC2DescribeSnapshotsAPI is the interface for the EC2 DescribeSnapshots call.
type EC2DescribeSnapshotsAPI interface {
	DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

// OldSnapshotScanner finds EBS snapshots older than 90 days owned by the current account.
type OldSnapshotScanner struct {
	EC2 EC2DescribeSnapshotsAPI
	STS STSAPI
}

func (s *OldSnapshotScanner) Name() string {
	return "Old EBS Snapshots (>90 days)"
}

func (s *OldSnapshotScanner) Scan(ctx context.Context) ([]Issue, error) {
	// Get current account ID to filter only our own snapshots.
	identity, err := s.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("snapshot scanner: unable to get account ID: %w", err)
	}
	accountID := aws.ToString(identity.Account)

	result, err := s.EC2.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{accountID},
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"completed"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("snapshot scanner: %w", err)
	}

	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour)
	var issues []Issue

	for _, snap := range result.Snapshots {
		if snap.StartTime == nil || snap.StartTime.After(cutoff) {
			continue
		}

		snapID := aws.ToString(snap.SnapshotId)
		age := int(time.Since(*snap.StartTime).Hours() / 24)
		sizeGiB := aws.ToInt32(snap.VolumeSize)

		issues = append(issues, Issue{
			Severity:    SeverityWarning,
			Scanner:     s.Name(),
			ResourceID:  snapID,
			Description: fmt.Sprintf("EBS snapshot %s (%d GiB) is %d days old", snapID, sizeGiB, age),
			Suggestion:  "Review if this snapshot is still needed. Delete old snapshots to reduce storage costs.",
		})
	}

	return issues, nil
}
