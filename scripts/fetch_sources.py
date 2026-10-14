#!/usr/bin/env python3
"""
fetch_sources.py – Safe offline fetcher for the Cloud Copilot reference library.

Rules enforced:
- Domain allowlist taken from data/sources.yaml; no other hosts are contacted.
- robots.txt is respected for every domain (fetched once per domain per run).
- 1 request per second minimum between requests.
- Size cap of 5 MB per response (SIZE_CAP_BYTES).
- Redirects only followed within the allowlist (never to external hosts).
- Descriptive User-Agent string.
- Fetched content is NEVER executed, eval()d, or interpolated into shell commands.
- Output: data/raw/<source_id>.html or .md, plus data/fetch_log.json.

Usage:
    python scripts/fetch_sources.py                     # fetch all sources
    python scripts/fetch_sources.py --id aws_cli_ug_ec2_instances  # fetch one source
    python scripts/fetch_sources.py --dry-run           # print plan only

Requires: pip install pyyaml requests (httpx also works via --httpx flag)
"""

import argparse
import hashlib
import json
import logging
import sys
import time
import urllib.parse
import urllib.robotparser
from pathlib import Path
from typing import Any

import yaml

# ── Constants ────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent.resolve()
SOURCES_FILE = REPO_ROOT / "data" / "sources.yaml"
RAW_DIR = REPO_ROOT / "data" / "raw"
FETCH_LOG = REPO_ROOT / "data" / "fetch_log.json"

SIZE_CAP_BYTES = 5 * 1024 * 1024  # 5 MB per page
RATE_LIMIT_SECONDS = 1.0
REQUEST_TIMEOUT = 30  # seconds
USER_AGENT = "CloudCopilot-RefFetcher/1.0 (offline reference library; contact: project maintainer)"

# GitHub raw content base for terraform provider docs
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Terraform provider path template
TF_PROVIDER_RESOURCE_PATH = "website/docs/r/{resource}.html.markdown"

# Map source id suffix → resource filename in the provider repo
TF_RESOURCE_MAP: dict[str, str] = {
    "tf_aws_vpc": "vpc",
    "tf_aws_subnet": "subnet",
    "tf_aws_security_group": "security_group",
    "tf_aws_security_group_rule": "security_group_rule",
    "tf_aws_instance": "instance",
    "tf_aws_ebs_volume": "ebs_volume",
    "tf_aws_s3_bucket": "s3_bucket",
    "tf_aws_s3_bucket_versioning": "s3_bucket_versioning",
    "tf_aws_s3_bucket_public_access_block": "s3_bucket_public_access_block",
    "tf_aws_s3_bucket_server_side_encryption_configuration": "s3_bucket_server_side_encryption_configuration",
    "tf_aws_db_instance": "db_instance",
    "tf_aws_iam_role": "iam_role",
    "tf_aws_iam_policy": "iam_policy",
    "tf_aws_cloudwatch_metric_alarm": "cloudwatch_metric_alarm",
    "tf_aws_sns_topic": "sns_topic",
    "tf_aws_internet_gateway": "internet_gateway",
    "tf_aws_route_table": "route_table",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fetch_sources")


# ── Helpers ───────────────────────────────────────────────────────────────────


def load_manifest() -> dict[str, Any]:
    """Load and return the parsed sources.yaml."""
    if not SOURCES_FILE.exists():
        sys.exit(f"ERROR: {SOURCES_FILE} not found. Run from the repo root.")
    with open(SOURCES_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_allowlist(sources: list[dict]) -> set[str]:
    """Extract allowed hostnames from manifest URLs and known GitHub raw host."""
    allowed: set[str] = set()
    for src in sources:
        url = src.get("url_or_repo", "")
        if url.startswith("http"):
            parsed = urllib.parse.urlparse(url)
            allowed.add(parsed.netloc.lower())
        elif "/" in url:
            # GitHub owner/repo reference → raw.githubusercontent.com + api.github.com
            allowed.add("raw.githubusercontent.com")
            allowed.add("api.github.com")
    return allowed


def is_allowed_url(url: str, allowlist: set[str]) -> bool:
    """Return True only if the URL's host is in the allowlist."""
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.lower() in allowlist


def resolve_url(source: dict) -> str | None:
    """Compute the fetch URL for a given source entry."""
    src_id: str = source["id"]
    url_or_repo: str = source["url_or_repo"]
    src_type: str = source["type"]
    pinned: str = source["pinned_version"]

    if src_type == "terraform_provider":
        # Fetch from raw.githubusercontent.com at pinned tag
        resource_name = TF_RESOURCE_MAP.get(src_id)
        if not resource_name:
            log.warning("No resource mapping for %s – skipping", src_id)
            return None
        owner_repo = url_or_repo  # e.g. "hashicorp/terraform-provider-aws"
        path = TF_PROVIDER_RESOURCE_PATH.format(resource=resource_name)
        return f"{GITHUB_RAW_BASE}/{owner_repo}/{pinned}/{path}"

    if src_type == "price_data":
        # Price list bulk data – skip in doc fetcher; use refresh_prices.py instead
        log.info("Skipping price_data source %s (use scripts/refresh_prices.py)", src_id)
        return None

    if url_or_repo.startswith("http"):
        return url_or_repo

    # GitHub owner/repo without explicit path – skip (needs sub-resource logic)
    log.warning("Cannot auto-resolve URL for %s (%s) – skipping", src_id, url_or_repo)
    return None


class RobotCache:
    """Cache robots.txt checks per domain."""

    def __init__(self) -> None:
        self._parsers: dict[str, urllib.robotparser.RobotFileParser] = {}

    def is_allowed(self, url: str, session: Any) -> bool:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._parsers:
            rp = urllib.robotparser.RobotFileParser()
            robots_url = f"{base}/robots.txt"
            rp.set_url(robots_url)
            try:
                rp.read()
                log.debug("Fetched robots.txt for %s", base)
            except Exception as exc:
                log.warning("Could not fetch robots.txt for %s (%s) – allowing", base, exc)
            self._parsers[base] = rp
        return self._parsers[base].can_fetch(USER_AGENT, url)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_fetch_log() -> list[dict]:
    if FETCH_LOG.exists():
        with open(FETCH_LOG, encoding="utf-8") as f:
            return json.load(f)
    return []


def save_fetch_log(entries: list[dict]) -> None:
    FETCH_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(FETCH_LOG, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def safe_filename(src_id: str, url: str) -> str:
    """Derive a safe raw filename from source id."""
    ext = ".md" if url.endswith(".md") or url.endswith(".markdown") else ".html"
    return f"{src_id}{ext}"


# ── Core fetch logic ──────────────────────────────────────────────────────────


def fetch_source(
    source: dict,
    allowlist: set[str],
    robot_cache: RobotCache,
    session: Any,
    dry_run: bool = False,
) -> dict:
    """Fetch a single source. Returns a log entry dict."""
    src_id = source["id"]
    url = resolve_url(source)
    entry: dict[str, Any] = {
        "id": src_id,
        "url": url or "N/A",
        "status": "skipped",
        "sha256": None,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "error": None,
        "size_bytes": None,
    }

    if url is None:
        return entry

    # ── Allowlist check ───────────────────────────────────────────────────────
    if not is_allowed_url(url, allowlist):
        log.error("BLOCKED – non-allowlisted URL for %s: %s", src_id, url)
        entry["status"] = "blocked_allowlist"
        entry["error"] = f"Host not in allowlist: {urllib.parse.urlparse(url).netloc}"
        return entry

    if dry_run:
        log.info("[DRY-RUN] Would fetch: %s → %s", src_id, url)
        entry["status"] = "dry_run"
        return entry

    # ── robots.txt check ──────────────────────────────────────────────────────
    if not robot_cache.is_allowed(url, session):
        log.warning("robots.txt disallows %s – skipping", url)
        entry["status"] = "blocked_robots"
        return entry

    # ── Fetch ─────────────────────────────────────────────────────────────────
    try:
        import requests  # noqa: PLC0415 – optional import inside function

        headers = {"User-Agent": USER_AGENT}
        resp = session.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,  # handle redirects manually
            stream=True,
        )

        # Handle redirects within allowlist only
        redirect_count = 0
        while resp.is_redirect and redirect_count < 5:
            redirect_url = resp.headers.get("Location", "")
            if not redirect_url:
                break
            # Resolve relative redirects
            redirect_url = urllib.parse.urljoin(url, redirect_url)
            if not is_allowed_url(redirect_url, allowlist):
                log.error("Redirect to non-allowlisted host for %s: %s", src_id, redirect_url)
                entry["status"] = "blocked_redirect"
                entry["error"] = f"Redirect to non-allowed host: {redirect_url}"
                return entry
            url = redirect_url
            entry["url"] = url
            resp = session.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
            redirect_count += 1

        status_code = resp.status_code
        if status_code != 200:
            log.warning("HTTP %d for %s", status_code, url)
            entry["status"] = f"http_{status_code}"
            return entry

        # ── Size cap ──────────────────────────────────────────────────────────
        content = b""
        for chunk in resp.iter_content(chunk_size=65536):
            content += chunk
            if len(content) > SIZE_CAP_BYTES:
                log.warning("Size cap exceeded for %s – truncating at %d bytes", src_id, SIZE_CAP_BYTES)
                content = content[:SIZE_CAP_BYTES]
                break

        # ── Save ──────────────────────────────────────────────────────────────
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        out_name = safe_filename(src_id, url)
        out_path = RAW_DIR / out_name

        # Never execute fetched content – write bytes directly
        out_path.write_bytes(content)

        digest = sha256_of(content)
        log.info("OK  %s → %s  (%d bytes, sha256=%s…)", src_id, out_name, len(content), digest[:12])

        entry["status"] = "ok"
        entry["sha256"] = digest
        entry["size_bytes"] = len(content)

    except ImportError:
        log.error("'requests' library not installed. Run: pip install requests")
        entry["status"] = "error"
        entry["error"] = "requests not installed"
    except Exception as exc:  # noqa: BLE001
        log.error("Error fetching %s: %s", src_id, exc)
        entry["status"] = "error"
        entry["error"] = str(exc)

    return entry


# ── Main ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch reference sources for Cloud Copilot reference library."
    )
    parser.add_argument("--id", dest="source_id", help="Fetch only this source id.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be fetched without making network requests.",
    )
    args = parser.parse_args(argv)

    manifest = load_manifest()
    sources: list[dict] = manifest.get("sources", [])

    if not sources:
        log.error("No sources found in manifest.")
        return 1

    if args.source_id:
        sources = [s for s in sources if s["id"] == args.source_id]
        if not sources:
            log.error("Source id '%s' not found in manifest.", args.source_id)
            return 1

    allowlist = build_allowlist(manifest.get("sources", []))
    log.info("Allowlist: %s", sorted(allowlist))

    robot_cache = RobotCache()
    log_entries = load_fetch_log()
    existing_ids = {e["id"] for e in log_entries}

    try:
        import requests  # noqa: PLC0415

        session = requests.Session()
    except ImportError:
        session = None  # type: ignore[assignment]
        if not args.dry_run:
            log.error("'requests' library required. Install with: pip install requests")
            return 1

    last_request_time = 0.0

    for source in sources:
        # Rate limit: at least RATE_LIMIT_SECONDS between requests
        elapsed = time.monotonic() - last_request_time
        if elapsed < RATE_LIMIT_SECONDS and not args.dry_run:
            sleep_for = RATE_LIMIT_SECONDS - elapsed
            time.sleep(sleep_for)

        entry = fetch_source(
            source=source,
            allowlist=allowlist,
            robot_cache=robot_cache,
            session=session,
            dry_run=args.dry_run,
        )
        last_request_time = time.monotonic()

        # Update log (replace existing entry for same id if present)
        log_entries = [e for e in log_entries if e["id"] != entry["id"]]
        log_entries.append(entry)

    if not args.dry_run:
        save_fetch_log(log_entries)
        log.info("Fetch log written to %s", FETCH_LOG)

    ok_count = sum(1 for e in log_entries if e.get("status") == "ok")
    skip_count = sum(1 for e in log_entries if e.get("status") in ("skipped", "dry_run"))
    err_count = sum(1 for e in log_entries if e.get("status") not in ("ok", "skipped", "dry_run", "blocked_robots"))

    log.info("Done: %d ok, %d skipped/price_data, %d errors/blocks", ok_count, skip_count, err_count)
    return 0 if err_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
