package scanner

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// IAMAPI is the interface for the IAM calls used by this scanner.
type IAMAPI interface {
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
}

// NoMFAScanner finds IAM users that have console access but no MFA device enabled.
type NoMFAScanner struct {
	Client IAMAPI
}

func (s *NoMFAScanner) Name() string {
	return "IAM Users Without MFA"
}

func (s *NoMFAScanner) Scan(ctx context.Context) ([]Issue, error) {
	listOut, err := s.Client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, fmt.Errorf("iam scanner: %w", err)
	}

	var issues []Issue
	for _, user := range listOut.Users {
		username := aws.ToString(user.UserName)

		mfaOut, err := s.Client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue // skip users we can't inspect
		}

		if len(mfaOut.MFADevices) == 0 {
			issues = append(issues, Issue{
				Severity:    SeverityCritical,
				Scanner:     s.Name(),
				ResourceID:  username,
				Description: fmt.Sprintf("IAM user %s has no MFA device enabled", username),
				Suggestion:  "Enable MFA for this user via the IAM console or enforce MFA with an IAM policy.",
			})
		}
	}

	return issues, nil
}
