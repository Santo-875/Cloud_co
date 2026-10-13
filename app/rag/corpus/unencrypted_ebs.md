# PLACEHOLDER REFERENCE CORPUS: ENCRYPTING EBS VOLUMES AT REST
# NOTE: Replace with official Checkov CKV_AWS_3 / CKV_AWS_8 and AWS EBS Encryption documentation before production.

Service: ebs
CheckID: CKV_AWS_3
Severity: medium

## Security Risk
Unencrypted Elastic Block Store (EBS) volumes risk data leakage if storage snapshots, detached volumes, or backups are inadvertently exposed or inspected without authorization.

## Remediation Guidelines
1. Ensure the `encrypted` parameter is set to `true` on all standalone EBS volume resources (`aws_ebs_volume`).
2. For EC2 instances, ensure `root_block_device.encrypted = true` in launch configurations or instance templates.
3. Utilize AWS Key Management Service (AWS KMS) default customer managed keys (CMK) or the AWS-managed `aws/ebs` key to enforce encryption at rest across all write operations.
