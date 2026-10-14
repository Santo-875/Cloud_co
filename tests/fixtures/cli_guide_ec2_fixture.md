# CLI Guide Fixture: EC2 Instances
# Service: ec2
# CheckID: general
# Severity: medium

## Launching an instance

To launch an Amazon EC2 instance, use the `run-instances` command.

```bash
aws ec2 run-instances \
    --image-id ami-xxxxxxxx \
    --instance-type t3.micro \
    --key-name MyKeyPair \
    --security-group-ids sg-903004f8 \
    --subnet-id subnet-6e7f829e \
    --count 1
```

**WARNING**: Launching instances outside the free tier is billed while running, even when idle. Always verify the instance type and region before launching.

**Important**: Terminating an instance is permanent. Volumes marked delete-on-termination will also be deleted.

Use `--dry-run` to verify you have the necessary permissions before actually launching.

## Describing instances

Use `describe-instances` with filters and `--query` to list specific instances.

```bash
aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=web" \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name}'
```

## Tagging instances

```bash
aws ec2 create-tags \
    --resources i-1234567890abcdef0 \
    --tags Key=Name,Value=MyInstance
```

## Stopping and terminating

```bash
# Stop (preserves EBS volumes)
aws ec2 stop-instances --instance-ids i-1234567890abcdef0

# Terminate (PERMANENT – deletes volumes marked delete-on-termination)
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
```

**WARNING**: `terminate-instances` is permanent and cannot be undone.
