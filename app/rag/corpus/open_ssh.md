# PLACEHOLDER REFERENCE CORPUS: RESTRICTING PORT 22 SSH EXPOSURE
# NOTE: Replace with official Checkov CKV_AWS_24 and AWS VPC Security Group documentation before production.

Service: security_group
CheckID: CKV_AWS_24
Severity: high

## Security Risk
Exposing TCP port 22 (SSH) to the entire public internet (0.0.0.0/0) invites brute-force credential stuffing, automated botnet vulnerability scans, and potential unauthorized system takeovers.

## Remediation Guidelines
1. In the security group ingress configuration, replace CIDR `0.0.0.0/0` with your corporate VPN, static office IP, or a dedicated bastion host CIDR.
2. For secure instance administration without any exposed inbound SSH ports, utilize AWS Systems Manager (SSM) Session Manager.
3. If public administrative access is mandatory, employ an auto-scaled bastion jump host in a public subnet with multi-factor authentication.
