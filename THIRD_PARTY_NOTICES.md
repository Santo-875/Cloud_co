# Third-Party Notices

Cloud Copilot uses content from the following third-party sources for its reference
library. All raw fetched content is stored locally under `data/raw/` (git-ignored)
and is never committed to the repository or redistributed. Only the source manifest
(`data/sources.yaml`), this notices file, and the parsing code are committed.

---

## 1. AWS Documentation (CLI User Guide, CLI Reference, Pricing Calculator, Well-Architected)

**Publisher:** Amazon Web Services, Inc.  
**URLs:** `https://docs.aws.amazon.com/`, `https://awscli.amazonaws.com/`  
**License:** AWS Site Terms — content is reference-only. Not redistributed.  
**Usage:** Fetched locally for offline RAG ingestion. Used only to extract patterns,
warnings, and methodology. AMI IDs and pricing rates from these pages are treated as
examples only; current values are verified via the AWS Price List.  
**Attribution:** © Amazon Web Services, Inc. or its affiliates. All rights reserved.

---

## 2. Terraform AWS Provider Documentation

**Publisher:** HashiCorp, Inc.  
**Repository:** `hashicorp/terraform-provider-aws`  
**Pinned version:** `v5.82.2`  
**Source path:** `website/docs/r/<resource>.html.markdown`  
**License:** Mozilla Public License 2.0 (MPL-2.0)  
**License text:** https://github.com/hashicorp/terraform-provider-aws/blob/main/LICENSE  
**Usage:** Resource argument reference, example usage, and import sections are
ingested for the RAG library. Content is used for reference only, is stored
locally under `data/raw/` (git-ignored), and is not redistributed.

---

## 3. AWS Price List Bulk Data

**Publisher:** Amazon Web Services, Inc.  
**URL:** `https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/`  
**License:** AWS pricing data is publicly available. Used for non-commercial cost
estimation only. Not redistributed in raw form.  
**Usage:** `scripts/refresh_prices.py` fetches price data and extracts only the
specific on-demand rates needed for the estimator into `app/cost/price_snapshot.json`.
The raw bulk JSON files (hundreds of MB) are not committed.  
**Attribution:** AWS pricing data © Amazon Web Services, Inc.

---

## 4. Checkov Policy Documentation

**Publisher:** Bridgecrew (now Palo Alto Networks)  
**Repository:** `bridgecrewio/checkov`  
**Pinned version:** `3.2.0`  
**License:** Apache License 2.0  
**License text:** https://github.com/bridgecrewio/checkov/blob/main/LICENSE  
**Usage:** Check IDs, descriptions, and remediation guidance are used for RAG
context in security findings explanations. Content is stored locally under
`data/raw/` (git-ignored) and is not redistributed.

---

## 5. AWS Well-Architected Framework Pillars

**Publisher:** Amazon Web Services, Inc.  
**URLs:** Security Pillar and Cost Optimization Pillar  
**License:** AWS Site Terms — content is reference-only. Not redistributed.  
**Usage:** Fetched locally for offline RAG ingestion. Used only to extract
security and cost best-practice guidelines.  
**Attribution:** © Amazon Web Services, Inc. or its affiliates. All rights reserved.

---

*This file was last updated: 2024-01-15*  
*For questions about third-party usage, see SECURITY.md and the project LICENSE.*
