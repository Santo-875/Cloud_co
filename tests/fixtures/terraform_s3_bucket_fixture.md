---
subcategory: "S3 (Simple Storage)"
layout: "aws"
page_title: "AWS: aws_s3_bucket"
description: |-
  Provides a S3 bucket resource.
---

# Resource: aws_s3_bucket

Provides a S3 bucket resource.

> **NOTE on `aws_s3_bucket` and `aws_s3_bucket_acl`**: Both resources manage the
> S3 bucket ACL. Do not use the `acl` argument in `aws_s3_bucket` together with
> `aws_s3_bucket_acl`. Conflicts will be created.

## Example Usage

### Private Bucket With Tags

```terraform
resource "aws_s3_bucket" "example" {
  bucket = "my-tf-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
```

## Argument Reference

The following arguments are supported:

* `bucket` - (Optional, Forces new resource) The name of the bucket. If omitted, Terraform will assign a random, unique name. Must be lowercase and less than or equal to 63 characters in length.
* `bucket_prefix` - (Optional, Forces new resource) Creates a unique bucket name beginning with the specified prefix. Conflicts with `bucket`. Must be lowercase and less than or equal to 37 characters in length.
* `force_destroy` - (Optional, Default:`false`) A boolean that indicates all objects (including any locked objects) should be deleted from the bucket *when the bucket is destroyed* so that the bucket can be destroyed without error. These objects are *not* recoverable.
* `object_lock_enabled` - (Optional, Forces new resource) Indicates whether this bucket has an Object Lock configuration enabled. Valid values are `true` or `false`.
* `tags` - (Optional) A map of tags to assign to the bucket.

**Important**: The `aws_s3_bucket` resource does NOT manage versioning, ACLs, server-side encryption, or public access blocks directly. Use companion resources instead:
- `aws_s3_bucket_versioning` – manages versioning configuration
- `aws_s3_bucket_public_access_block` – manages public access settings
- `aws_s3_bucket_server_side_encryption_configuration` – manages encryption

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the bucket.
* `arn` - The ARN of the bucket. Will be of format `arn:aws:s3:::bucketname`.
* `bucket_domain_name` - The bucket domain name. Will be of format `bucketname.s3.amazonaws.com`.
* `bucket_regional_domain_name` - The bucket region-specific domain name.
* `hosted_zone_id` - The Route 53 Hosted Zone ID for this bucket's region.
* `region` - The AWS region this bucket resides in.
* `tags_all` - A map of tags assigned to the resource, including those inherited from the provider.
* `website_endpoint` - (**Deprecated**) The website endpoint, if the bucket is configured with a website.
* `website_domain` - (**Deprecated**) The domain of the website endpoint.

## Import

S3 bucket can be imported using the `bucket` name, e.g.,

```console
$ terraform import aws_s3_bucket.bucket bucket-name
```
