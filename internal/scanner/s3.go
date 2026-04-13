package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3API is the interface for the S3 calls used by this scanner.
type S3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// PublicS3Scanner finds S3 buckets that do not have all public access blocked.
type PublicS3Scanner struct {
	Client S3API
}

func (s *PublicS3Scanner) Name() string {
	return "Public S3 Buckets"
}

func (s *PublicS3Scanner) Scan(ctx context.Context) ([]Issue, error) {
	listOut, err := s.Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3 scanner: %w", err)
	}

	var issues []Issue
	for _, bucket := range listOut.Buckets {
		name := aws.ToString(bucket.Name)

		pabOut, err := s.Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})

		if err != nil {
			// If the public access block config doesn't exist, the bucket is wide open.
			if isNoSuchPublicAccessBlockError(err) {
				issues = append(issues, newPublicBucketIssue(s.Name(), name, "no Public Access Block configuration exists"))
				continue
			}
			// Skip buckets we can't inspect (permissions, region mismatch, etc.)
			continue
		}

		if !isFullyBlocked(pabOut.PublicAccessBlockConfiguration) {
			issues = append(issues, newPublicBucketIssue(s.Name(), name, "Public Access Block is not fully enabled"))
		}
	}

	return issues, nil
}

func isFullyBlocked(cfg *types.PublicAccessBlockConfiguration) bool {
	if cfg == nil {
		return false
	}
	return aws.ToBool(cfg.BlockPublicAcls) &&
		aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.RestrictPublicBuckets)
}

func isNoSuchPublicAccessBlockError(err error) bool {
	return strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration")
}

func newPublicBucketIssue(scannerName, bucket, reason string) Issue {
	return Issue{
		Severity:    SeverityCritical,
		Scanner:     scannerName,
		ResourceID:  bucket,
		Description: fmt.Sprintf("S3 bucket %s is potentially public: %s", bucket, reason),
		Suggestion:  "Enable S3 Block Public Access on this bucket or verify the bucket policy is intentional.",
	}
}
