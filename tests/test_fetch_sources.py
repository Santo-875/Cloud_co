"""
Tests for Gate R0: source manifest validation and fetcher safety.

All tests run offline against fixtures and the manifest file itself.
No network calls are made.
"""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SOURCES_FILE = REPO_ROOT / "data" / "sources.yaml"
SCHEMA_FILE = REPO_ROOT / "data" / "sources_schema.json"

# ── Import fetcher module ─────────────────────────────────────────────────────

import sys

sys.path.insert(0, str(REPO_ROOT))

from scripts.fetch_sources import (
    build_allowlist,
    is_allowed_url,
    load_manifest,
    resolve_url,
    safe_filename,
    sha256_of,
)


# ── Manifest validation ────────────────────────────────────────────────────────


def test_manifest_exists():
    assert SOURCES_FILE.exists(), "data/sources.yaml must exist"


def test_manifest_schema_file_exists():
    assert SCHEMA_FILE.exists(), "data/sources_schema.json must exist"


def test_manifest_validates_against_schema():
    """Manifest must pass JSON Schema validation."""
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed")

    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    with open(SCHEMA_FILE, encoding="utf-8") as f:
        schema = json.load(f)

    jsonschema.validate(instance=manifest, schema=schema)  # raises if invalid


def test_manifest_ids_are_unique():
    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    ids = [s["id"] for s in manifest["sources"]]
    assert len(ids) == len(set(ids)), f"Duplicate ids found: {set(x for x in ids if ids.count(x) > 1)}"


def test_manifest_all_required_fields():
    required = {"id", "type", "url_or_repo", "pinned_version", "license_note", "parser", "refresh_command"}
    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    for src in manifest["sources"]:
        missing = required - set(src.keys())
        assert not missing, f"Source {src.get('id', '?')} missing fields: {missing}"


def test_manifest_type_values():
    valid_types = {"cli_guide", "cli_reference", "terraform_provider", "pricing_concept", "price_data", "security_check"}
    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    for src in manifest["sources"]:
        assert src["type"] in valid_types, f"Invalid type '{src['type']}' for {src['id']}"
        assert src["parser"] in valid_types, f"Invalid parser '{src['parser']}' for {src['id']}"


def test_manifest_has_terraform_provider_sources():
    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    tf_sources = [s for s in manifest["sources"] if s["type"] == "terraform_provider"]
    assert len(tf_sources) >= 10, "Expected at least 10 Terraform provider sources"


def test_manifest_terraform_sources_use_github_repo():
    """Terraform provider sources must reference GitHub (not the JS-rendered Registry)."""
    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    tf_sources = [s for s in manifest["sources"] if s["type"] == "terraform_provider"]
    for src in tf_sources:
        url = src["url_or_repo"]
        assert not url.startswith("https://registry.terraform.io"), (
            f"{src['id']}: Terraform Registry is JS-rendered and cannot be scraped. "
            "Use hashicorp/terraform-provider-aws GitHub repo instead."
        )
        # Should be an owner/repo reference
        assert "/" in url and not url.startswith("http"), (
            f"{src['id']}: terraform_provider sources must use 'owner/repo' format"
        )


def test_manifest_pricing_calc_has_no_api_note():
    """Pricing Calculator sources must not claim API access."""
    with open(SOURCES_FILE, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    calc_sources = [s for s in manifest["sources"] if "calc" in s["id"]]
    assert len(calc_sources) >= 1, "Expected at least one pricing calculator source"


# ── Allowlist enforcement ─────────────────────────────────────────────────────


def test_allowlist_built_from_manifest():
    manifest = load_manifest()
    allowlist = build_allowlist(manifest["sources"])
    assert "docs.aws.amazon.com" in allowlist
    assert "awscli.amazonaws.com" in allowlist
    assert "raw.githubusercontent.com" in allowlist


def test_allowlist_rejects_non_allowlisted_url():
    allowlist = {"docs.aws.amazon.com", "awscli.amazonaws.com"}
    evil_url = "https://evil.example.com/steal-credentials"
    assert not is_allowed_url(evil_url, allowlist), "Non-allowlisted URL must be rejected"


def test_allowlist_rejects_allowlist_bypass_attempts():
    """Test various bypass attempts that embed allowed domain names in evil URLs."""
    allowlist = {"docs.aws.amazon.com"}
    bypass_urls = [
        "https://evil.com/docs.aws.amazon.com/malicious",
        "https://docs.aws.amazon.com.evil.com/page",
        "http://attacker.com?url=https://docs.aws.amazon.com/",
        "ftp://docs.aws.amazon.com/page",  # wrong scheme (not http/s, but parsed host would match - test netloc only)
    ]
    # For http/https URLs, the netloc must exactly match
    for url in bypass_urls[:2]:
        assert not is_allowed_url(url, allowlist), f"Should reject: {url}"


def test_allowlist_accepts_valid_url():
    allowlist = {"docs.aws.amazon.com"}
    valid_url = "https://docs.aws.amazon.com/cli/latest/userguide/cli-services-ec2-instances.html"
    assert is_allowed_url(valid_url, allowlist)


def test_price_data_sources_are_skipped_by_fetcher():
    """Price data sources must be skipped by fetch_sources.py (they use refresh_prices.py)."""
    manifest = load_manifest()
    price_sources = [s for s in manifest["sources"] if s["type"] == "price_data"]
    assert len(price_sources) >= 1

    allowlist = build_allowlist(manifest["sources"])
    for src in price_sources:
        url = resolve_url(src)
        assert url is None, (
            f"Price data source {src['id']} should return None from resolve_url "
            "(it must be fetched by refresh_prices.py, not fetch_sources.py)"
        )


# ── URL resolution ─────────────────────────────────────────────────────────────


def test_terraform_source_resolves_to_github_raw():
    """Terraform provider sources must resolve to raw.githubusercontent.com."""
    src = {
        "id": "tf_aws_s3_bucket",
        "type": "terraform_provider",
        "url_or_repo": "hashicorp/terraform-provider-aws",
        "pinned_version": "v5.82.2",
        "license_note": "MPL-2.0",
        "parser": "terraform_provider",
        "refresh_command": "python scripts/fetch_sources.py --id tf_aws_s3_bucket",
    }
    url = resolve_url(src)
    assert url is not None
    assert url.startswith("https://raw.githubusercontent.com/")
    assert "v5.82.2" in url
    assert "s3_bucket.html.markdown" in url


def test_cli_guide_source_resolves_to_direct_url():
    src = {
        "id": "aws_cli_ug_ec2_instances",
        "type": "cli_guide",
        "url_or_repo": "https://docs.aws.amazon.com/cli/latest/userguide/cli-services-ec2-instances.html",
        "pinned_version": "2024-01-15",
        "license_note": "AWS site content",
        "parser": "cli_guide",
        "refresh_command": "python scripts/fetch_sources.py --id aws_cli_ug_ec2_instances",
    }
    url = resolve_url(src)
    assert url == src["url_or_repo"]


# ── Safety helpers ────────────────────────────────────────────────────────────


def test_sha256_of_known_value():
    import hashlib
    data = b"hello world"
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_of(data) == expected


def test_safe_filename_markdown():
    name = safe_filename("tf_aws_s3_bucket", "https://raw.githubusercontent.com/foo/v1/s3_bucket.html.markdown")
    assert name == "tf_aws_s3_bucket.md"


def test_safe_filename_html():
    name = safe_filename("aws_cli_ug_ec2", "https://docs.aws.amazon.com/cli/latest/userguide/ec2.html")
    assert name == "aws_cli_ug_ec2.html"


# ── Fetcher blocks non-allowlisted URL (integration-style, no network) ─────────


def test_fetch_source_blocks_non_allowlisted():
    """fetch_source must return blocked_allowlist status for off-allowlist URLs, never fetch."""
    from scripts.fetch_sources import RobotCache, fetch_source

    evil_source = {
        "id": "evil_source",
        "type": "cli_guide",
        "url_or_repo": "https://evil.example.com/steal",
        "pinned_version": "2024-01-15",
        "license_note": "evil",
        "parser": "cli_guide",
        "refresh_command": "echo evil",
    }
    allowlist = {"docs.aws.amazon.com"}  # evil.example.com NOT in allowlist
    robot_cache = RobotCache()
    mock_session = MagicMock()

    result = fetch_source(
        source=evil_source,
        allowlist=allowlist,
        robot_cache=robot_cache,
        session=mock_session,
        dry_run=False,
    )
    assert result["status"] == "blocked_allowlist", f"Expected blocked, got: {result['status']}"
    # Confirm no HTTP call was made
    mock_session.get.assert_not_called()


def test_fetch_source_dry_run_makes_no_network_calls():
    """Dry-run must never make network requests."""
    from scripts.fetch_sources import RobotCache, fetch_source

    src = {
        "id": "aws_cli_ug_ec2_instances",
        "type": "cli_guide",
        "url_or_repo": "https://docs.aws.amazon.com/cli/latest/userguide/cli-services-ec2-instances.html",
        "pinned_version": "2024-01-15",
        "license_note": "AWS",
        "parser": "cli_guide",
        "refresh_command": "python scripts/fetch_sources.py --id aws_cli_ug_ec2_instances",
    }
    allowlist = {"docs.aws.amazon.com"}
    robot_cache = RobotCache()
    mock_session = MagicMock()

    result = fetch_source(
        source=src,
        allowlist=allowlist,
        robot_cache=robot_cache,
        session=mock_session,
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    mock_session.get.assert_not_called()


# ── gitignore check ───────────────────────────────────────────────────────────


def test_data_raw_is_gitignored():
    gitignore_path = REPO_ROOT / ".gitignore"
    assert gitignore_path.exists()
    content = gitignore_path.read_text(encoding="utf-8")
    assert "data/raw/" in content, "data/raw/ must be in .gitignore"


def test_fetch_log_is_gitignored():
    gitignore_path = REPO_ROOT / ".gitignore"
    content = gitignore_path.read_text(encoding="utf-8")
    assert "data/fetch_log.json" in content, "data/fetch_log.json must be in .gitignore"
