<p align="center">
  <h1 align="center">CloudMechanic</h1>
  <p align="center"><strong>An OBD scanner for your AWS environment.</strong></p>
  <p align="center">Find cost leaks and security vulnerabilities in seconds — not hours.</p>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go" alt="Go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/mazenessam77/cloudmechanic/releases"><img src="https://img.shields.io/github/v/release/mazenessam77/cloudmechanic?color=green" alt="Release"></a>
</p>

---

## The Problem

Every AWS account accumulates waste and risk over time:

- **Forgotten resources** — unattached EBS volumes, idle load balancers, unused Elastic IPs quietly burn money month after month.
- **Misconfigured security** — security groups left open to `0.0.0.0/0`, IAM users without MFA, public S3 buckets waiting to become the next headline.
- **Manual audits don't scale** — clicking through the AWS Console or writing one-off scripts is slow, error-prone, and never gets done consistently.

Teams discover these problems when the bill spikes or after a breach. By then, the damage is done.

## The Solution

**CloudMechanic** is a fast, single-binary CLI tool that scans your AWS account and delivers a color-coded, actionable report in your terminal.

- **Fast** — runs all checks concurrently using goroutines. Full scans complete in under 1 second.
- **Zero config** — uses your existing AWS CLI credentials. No agents, no SaaS, no signup.
- **Actionable** — every finding includes the resource ID and a specific remediation step.
- **Extensible** — built on a `Scanner` interface. Adding a new check is one file and one line of registration.

```
$ cloudmechanic scan

=== CloudMechanic Scan Report ===

Security Issues (3):
  🔴 [CRITICAL] Security Group sg-0db0d4a51a974f36b (caf-bastion-sg) allows SSH (port 22) from 0.0.0.0/0
     Resource: sg-0db0d4a51a974f36b
     Fix:      Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager instead.
  🔴 [CRITICAL] Security Group sg-09d33757e356808df (launch-wizard-2) allows SSH (port 22) from 0.0.0.0/0
     Resource: sg-09d33757e356808df
     Fix:      Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager instead.
  🔴 [CRITICAL] Security Group sg-02e017ca8231040c6 (launch-wizard-1) allows SSH (port 22) from 0.0.0.0/0
     Resource: sg-02e017ca8231040c6
     Fix:      Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager instead.

--------------------------------------------------
✅ Scan complete in 986ms
   Total issues: 3 (3 critical, 0 warnings)
```

## Prerequisites

1. **Go 1.21+** (only if building from source)
2. **AWS CLI configured** with valid credentials:
   ```bash
   aws configure
   # or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION
   ```
3. **IAM permissions** — the tool needs read-only access. At minimum:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:DescribeVolumes",
           "ec2:DescribeSecurityGroups",
           "ec2:DescribeAddresses",
           "ec2:DescribeSnapshots",
           "ec2:DescribeRegions",
           "ec2:DescribeNatGateways",
           "ec2:DescribeRouteTables",
           "ec2:DescribeVpcs",
           "ec2:DescribeFlowLogs",
           "s3:ListAllMyBuckets",
           "s3:GetPublicAccessBlock",
           "s3:GetEncryptionConfiguration",
           "s3:GetBucketVersioning",
           "rds:DescribeDBInstances",
           "cloudwatch:GetMetricData",
           "dynamodb:ListTables",
           "dynamodb:DescribeContinuousBackups",
           "dynamodb:DescribeTable",
           "lambda:ListFunctions",
           "lambda:GetFunctionUrlConfig",
           "iam:ListUsers",
           "iam:ListMFADevices",
           "sts:GetCallerIdentity"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

## Installation

### Homebrew (macOS / Linux)

```bash
brew tap mazenessam77/tap
brew install cloudmechanic
```

### Go Install

```bash
go install github.com/mazenessam77/cloudmechanic@latest
```

### Download Binary

Grab the latest release for your platform from the [Releases](https://github.com/mazenessam77/cloudmechanic/releases) page.

### Build from Source

```bash
git clone https://github.com/mazenessam77/cloudmechanic.git
cd cloudmechanic
go build -o cloudmechanic .
```

## Usage

### Run All Scanners

```bash
cloudmechanic scan
```

### Target a Specific Region

```bash
cloudmechanic scan --region us-west-2
```

### Scan All Regions

```bash
cloudmechanic scan --all-regions
```

### Use a Named AWS Profile

```bash
cloudmechanic scan --profile production
```

### JSON Output (for CI/CD pipelines)

```bash
cloudmechanic scan -o json
```

### CSV Output (for spreadsheets)

```bash
cloudmechanic scan -o csv > report.csv
```

### Check Version

```bash
cloudmechanic version
```

### Combine Flags

```bash
cloudmechanic scan --profile staging --region eu-west-1 -o json
```

## Current Scanners

| Scanner | Type | What It Finds |
|---------|------|---------------|
| **Unattached EBS** | Cost Leak | EBS volumes in `available` state (not attached to any instance) |
| **Open Security Groups** | Security | Security groups allowing `0.0.0.0/0` or `::/0` ingress on port 22 |
| **Public S3 Buckets** | Security | Buckets without full S3 Block Public Access enabled |
| **IAM Users Without MFA** | Security | IAM users with no MFA device enabled |
| **Idle RDS Instances** | Cost Leak | RDS instances with 0 connections over the last 7 days |
| **Unused Elastic IPs** | Cost Leak | Elastic IPs not associated with any resource ($3.60/mo each) |
| **Old EBS Snapshots** | Cost Leak | EBS snapshots older than 90 days |
| **DynamoDB Without Backups** | Security | Tables without Point-in-Time Recovery (PITR) |
| **DynamoDB Provisioned Capacity** | Cost Leak | Tables using provisioned mode that may benefit from on-demand |
| **Unused NAT Gateways** | Cost Leak | NAT Gateways not referenced in any route table (~$32/mo) |
| **VPCs Without Flow Logs** | Security | VPCs with no Flow Logs for network auditing |
| **Lambda Deprecated Runtimes** | Security | Functions running on EOL runtimes without security patches |
| **Lambda Public Function URLs** | Security | Functions with public URLs and no authentication |
| **S3 Buckets Without Encryption** | Security | Buckets with no default server-side encryption |
| **S3 Buckets Without Versioning** | Cost Leak | Buckets without versioning (risk of data loss) |

## Roadmap

- [x] Unused Elastic IPs
- [x] Public S3 Buckets
- [x] IAM Users without MFA
- [x] Idle RDS Instances (0 connections over 7 days)
- [x] Old EBS Snapshots (>90 days)
- [x] JSON / CSV output formats (`--output json`, `--output csv`)
- [x] Multi-region scanning (`--all-regions`)
- [x] DynamoDB backup & capacity checks
- [x] VPC Flow Logs & unused NAT Gateway checks
- [x] Lambda deprecated runtime & public URL checks
- [x] S3 encryption & versioning checks
- [ ] Custom severity thresholds
- [ ] HTML report export
- [ ] Slack / webhook notifications
- [ ] Cost estimation per issue

## Contributing

Contributions are welcome! CloudMechanic uses a simple `Scanner` interface — adding a new check is straightforward:

1. Create a new file in `internal/scanner/`
2. Implement the `Scanner` interface (`Name()` + `Scan()`)
3. Register it in `cmd/scan.go`
4. Submit a PR

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with Go, caffeine, and a healthy fear of surprise AWS bills.
</p>
