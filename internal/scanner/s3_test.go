package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type mockS3 struct {
	buckets    *s3.ListBucketsOutput
	pabResults map[string]*s3.GetPublicAccessBlockOutput
	pabErrors  map[string]error
}

func (m *mockS3) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return m.buckets, nil
}

func (m *mockS3) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	name := aws.ToString(params.Bucket)
	if err, ok := m.pabErrors[name]; ok {
		return nil, err
	}
	if out, ok := m.pabResults[name]; ok {
		return out, nil
	}
	return &s3.GetPublicAccessBlockOutput{}, nil
}

func TestPublicS3Scanner_FullyBlocked(t *testing.T) {
	s := &PublicS3Scanner{
		Client: &mockS3{
			buckets: &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("secure-bucket")}},
			},
			pabResults: map[string]*s3.GetPublicAccessBlockOutput{
				"secure-bucket": {
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
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

func TestPublicS3Scanner_PartiallyBlocked(t *testing.T) {
	s := &PublicS3Scanner{
		Client: &mockS3{
			buckets: &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("leaky-bucket")}},
			},
			pabResults: map[string]*s3.GetPublicAccessBlockOutput{
				"leaky-bucket": {
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(false),
						BlockPublicPolicy:     aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
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

func TestPublicS3Scanner_NoPABConfig(t *testing.T) {
	s := &PublicS3Scanner{
		Client: &mockS3{
			buckets: &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("open-bucket")}},
			},
			pabErrors: map[string]error{
				"open-bucket": fmt.Errorf("NoSuchPublicAccessBlockConfiguration: The public access block configuration was not found"),
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
