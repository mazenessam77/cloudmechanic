package scanner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type mockIAM struct {
	users      *iam.ListUsersOutput
	mfaDevices map[string]*iam.ListMFADevicesOutput
	err        error
}

func (m *mockIAM) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return m.users, m.err
}

func (m *mockIAM) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	username := aws.ToString(params.UserName)
	if out, ok := m.mfaDevices[username]; ok {
		return out, nil
	}
	return &iam.ListMFADevicesOutput{}, nil
}

func TestNoMFAScanner_FindsUsersWithoutMFA(t *testing.T) {
	s := &NoMFAScanner{
		Client: &mockIAM{
			users: &iam.ListUsersOutput{
				Users: []iamtypes.User{
					{UserName: aws.String("alice")},
					{UserName: aws.String("bob")},
				},
			},
			mfaDevices: map[string]*iam.ListMFADevicesOutput{
				"alice": {MFADevices: []iamtypes.MFADevice{{SerialNumber: aws.String("arn:aws:iam::123:mfa/alice")}}},
				"bob":   {MFADevices: []iamtypes.MFADevice{}},
			},
		},
	}

	issues, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue (bob), got %d", len(issues))
	}
	if issues[0].ResourceID != "bob" {
		t.Errorf("expected bob, got %s", issues[0].ResourceID)
	}
	if issues[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", issues[0].Severity)
	}
}

func TestNoMFAScanner_AllUsersHaveMFA(t *testing.T) {
	s := &NoMFAScanner{
		Client: &mockIAM{
			users: &iam.ListUsersOutput{
				Users: []iamtypes.User{
					{UserName: aws.String("alice")},
				},
			},
			mfaDevices: map[string]*iam.ListMFADevicesOutput{
				"alice": {MFADevices: []iamtypes.MFADevice{{SerialNumber: aws.String("arn:aws:iam::123:mfa/alice")}}},
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
