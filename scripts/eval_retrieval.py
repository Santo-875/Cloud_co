#!/usr/bin/env python3
"""
eval_retrieval.py – Evaluate retrieval hit rates per doc_type.

Reads tests/retrieval_eval.yaml and reports hit@1 and hit@3 per doc_type
using the SecurityKnowledgeRetriever loaded with the fixture-based corpus.

Usage (from repo root, venv active):
    python scripts/eval_retrieval.py [--fixture-dir tests/fixtures]

The script loads fixture files from tests/fixtures/ alongside the standard corpus.
"""

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

EVAL_FILE = REPO_ROOT / "tests" / "retrieval_eval.yaml"
DEFAULT_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures"


def load_fixtures_as_chunks(fixture_dir: Path) -> list[Any]:
    """Load fixture markdown files into DocumentChunk objects via the per-type parsers."""
    from app.rag.ingest import (
        parse_cli_guide,
        parse_pricing_concept,
        parse_terraform_provider,
    )

    chunks = []

    cli_fixture = fixture_dir / "cli_guide_ec2_fixture.md"
    if cli_fixture.exists():
        text = cli_fixture.read_text(encoding="utf-8")
        chunks.extend(
            parse_cli_guide(
                text=text,
                source_id="cli_guide_ec2_fixture",
                source_url="https://docs.aws.amazon.com/cli/latest/userguide/cli-services-ec2-instances.html",
                pinned_version="2024-01-15",
                fetched_at="2024-01-15",
                license_note="AWS",
                service="ec2",
            )
        )

    tf_fixture = fixture_dir / "terraform_s3_bucket_fixture.md"
    if tf_fixture.exists():
        text = tf_fixture.read_text(encoding="utf-8")
        chunks.extend(
            parse_terraform_provider(
                text=text,
                source_id="tf_aws_s3_bucket_fixture",
                source_url="https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/v5.82.2/website/docs/r/s3_bucket.html.markdown",
                pinned_version="v5.82.2",
                fetched_at="2024-01-15",
                license_note="MPL-2.0",
                resource_name="aws_s3_bucket",
            )
        )

    pricing_fixture = fixture_dir / "pricing_concept_fixture.md"
    if pricing_fixture.exists():
        text = pricing_fixture.read_text(encoding="utf-8")
        chunks.extend(
            parse_pricing_concept(
                text=text,
                source_id="aws_calc_fixture",
                source_url="https://docs.aws.amazon.com/pricing-calculator/latest/userguide/getting-started.html",
                pinned_version="2024-01-15",
                fetched_at="2024-01-15",
                license_note="AWS",
            )
        )

    return chunks


def evaluate(fixture_dir: Path) -> None:
    from app.rag.retriever import SecurityKnowledgeRetriever, route_intent

    # Load retriever with corpus + fixtures
    retriever = SecurityKnowledgeRetriever()
    fixture_chunks = load_fixtures_as_chunks(fixture_dir)
    retriever.add_chunks(fixture_chunks)

    print(f"Total chunks loaded: {len(retriever.chunks)}")

    with open(EVAL_FILE, encoding="utf-8") as f:
        eval_data = yaml.safe_load(f)

    questions = eval_data.get("questions", [])
    print(f"Evaluating {len(questions)} questions...\n")

    # Collect per doc_type stats
    stats: dict[str, dict[str, int]] = {}
    for q in questions:
        expected_type = q["expected_type"]
        if expected_type not in stats:
            stats[expected_type] = {"total": 0, "hit1": 0, "hit3": 0, "routed_correct": 0}
        stats[expected_type]["total"] += 1

    results = []
    for q in questions:
        question = q["question"]
        expected_type = q["expected_type"]
        expected_kw = q.get("expected_keyword", "").lower()

        # Test routing
        routed = route_intent(question)
        routed_correct = routed == expected_type or routed is None  # None = no strong signal, acceptable

        # Retrieve top 3
        top3 = retriever.retrieve(question, top_k=3)

        # hit@1: does top-1 chunk contain expected_keyword or have correct doc_type?
        hit1 = False
        hit3 = False
        if top3:
            top1 = top3[0]
            hit1 = (
                expected_kw in top1.content.lower()
                or expected_kw in top1.resource_or_command.lower()
                or expected_kw in top1.section.lower()
                or top1.doc_type == expected_type
            )
            for chunk in top3:
                if (
                    expected_kw in chunk.content.lower()
                    or expected_kw in chunk.resource_or_command.lower()
                    or expected_kw in chunk.section.lower()
                    or chunk.doc_type == expected_type
                ):
                    hit3 = True
                    break

        stats[expected_type]["hit1"] += int(hit1)
        stats[expected_type]["hit3"] += int(hit3)
        if routed_correct:
            stats[expected_type]["routed_correct"] += 1

        status = "✓" if hit1 else ("~" if hit3 else "✗")
        results.append(
            f"  [{status}] [{expected_type:10s}] routed={routed or 'None':12s} | {question[:70]}"
        )

    print("\n".join(results))

    # Summary table
    print("\n" + "=" * 72)
    print(f"{'doc_type':<15} {'total':>6} {'hit@1':>8} {'hit@3':>8} {'route%':>8}")
    print("-" * 72)
    overall_total = overall_h1 = overall_h3 = 0
    for dt, s in sorted(stats.items()):
        t = s["total"]
        h1 = s["hit1"]
        h3 = s["hit3"]
        rc = s["routed_correct"]
        print(
            f"{dt:<15} {t:>6} {h1/t*100:>7.0f}% {h3/t*100:>7.0f}% {rc/t*100:>7.0f}%"
        )
        overall_total += t
        overall_h1 += h1
        overall_h3 += h3
    print("=" * 72)
    print(
        f"{'OVERALL':<15} {overall_total:>6} {overall_h1/overall_total*100:>7.0f}% "
        f"{overall_h3/overall_total*100:>7.0f}%"
    )
    print()
    print("Legend: ✓ hit@1  ~ hit@3 only  ✗ miss  route% = correct intent routing")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate retrieval hit rates.")
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        default=DEFAULT_FIXTURE_DIR,
        help="Directory containing fixture .md files",
    )
    args = parser.parse_args()
    evaluate(args.fixture_dir)


if __name__ == "__main__":
    main()
