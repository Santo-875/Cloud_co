# AWS Pricing Calculator – Getting Started
# Pricing concept reference. NOTE: The Calculator has no API.

## Overview

The AWS Pricing Calculator helps you estimate the cost for your planned AWS services.
You can model your AWS infrastructure with monthly, 12-month, and upfront cost breakdowns.

**Important**: There is no API for the AWS Pricing Calculator. Estimates must be
created manually through the web console at https://calculator.aws/pricing/2/home

## Estimate conventions

The Calculator displays:
- **Monthly** cost
- **Upfront** cost (for Reserved Instances or Savings Plans)
- **12-month** total (monthly × 12 + upfront)

**Note**: The AWS Free Tier is NOT automatically applied to Calculator estimates unless
you explicitly configure it. Always check Free Tier exclusions.

## Exclusions

The following are NOT included in Calculator estimates:
- Taxes (VAT, GST, etc.)
- AWS Support plan costs
- AWS credits or promotional credits
- Enterprise Discount Program (EDP) discounts

## Cost dimensions supported

For EC2:
- Instance hours (by instance type and OS)
- EBS storage (GB-month, by volume type)
- Data transfer out (GB)

For S3:
- Storage (GB-month, Standard vs Infrequent Access)
- Request counts (GET, PUT, DELETE)
- Data transfer out (GB)

For RDS:
- Instance hours (by instance class and engine)
- Storage (GB-month)
- Multi-AZ surcharge
- Backup storage

## Price List API

For programmatic access to pricing data, use the AWS Price List API:
- No credentials required for public pricing data
- Endpoint: https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/
- Returns JSON with SKUs and pricing dimensions
- Use the bulk download for offline processing

**Note**: The Price List data is large (hundreds of MB per service). Extract only the
rates you need and store a versioned snapshot.
