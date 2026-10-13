# PLACEHOLDER REFERENCE CORPUS: S3 BUCKET PUBLIC ACCESS PREVENTION
# NOTE: Replace with official Checkov CKV_AWS_20 and AWS S3 Security Best Practices documentation before production.

Service: s3
CheckID: CKV_AWS_20
Severity: high

## Security Risk
Enabling public read or write access on Amazon S3 buckets frequently causes severe data breach incidents, unauthorized data modification, and massive unintended egress bandwidth costs.

## Remediation Guidelines
1. Enable S3 Block Public Access at both the bucket level and account level.
2. In your IaC definition, verify that `block_public_acls`, `block_public_policy`, `ignore_public_acls`, and `restrict_public_buckets` are all explicitly set to `true`.
3. If web asset delivery is required, front the bucket using AWS CloudFront configured with Origin Access Control (OAC), keeping the storage bucket itself strictly private.
