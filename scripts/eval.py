import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path
REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.parser import parse_architecture
from app.rules import evaluate_graph_rules

DEFAULT_ARCH_DIR = Path(__file__).parent.parent / "tests" / "architectures"


def evaluate_architectures(arch_dir: Path) -> tuple[int, int, int]:
    """Run detection accuracy evaluation against *.expected.json fixtures.

    Returns:
        (total_expected, total_detected, total_false_positives)
    """
    total_expected = 0
    total_detected = 0
    total_false_positives = 0

    yaml_files = sorted(arch_dir.glob("*.yaml"))
    if not yaml_files:
        print(f"No architecture YAML files found in {arch_dir}")
        return 0, 0, 0

    print(
        f"Evaluating {len(yaml_files)} architecture ground truth samples from {arch_dir.resolve()}...\n"
    )
    print(
        f"{'Sample':<25} {'Expected':<12} {'Detected':<12} {'False Positives':<16} {'Status'}"
    )
    print("-" * 75)

    for y_file in yaml_files:
        exp_file = y_file.with_name(f"{y_file.stem}.expected.json")
        if not exp_file.exists():
            print(f"{y_file.name:<25} [MISSING EXPECTATION FILE {exp_file.name}]")
            continue

        raw_yaml = y_file.read_text(encoding="utf-8")
        arch = parse_architecture(raw_yaml)
        findings = evaluate_graph_rules(arch)
        actual_ids = {f.id for f in findings}

        expected_data = json.loads(exp_file.read_text(encoding="utf-8"))
        expected_ids = set(expected_data.get("finding_ids", []))

        # True positives: in both expected and actual
        tp = expected_ids.intersection(actual_ids)
        # False negatives: expected but not actual
        fn = expected_ids - actual_ids
        # False positives: actual but not expected
        fp = actual_ids - expected_ids

        total_expected += len(expected_ids)
        total_detected += len(tp)
        total_false_positives += len(fp)

        status = "PASS" if len(fn) == 0 and len(fp) == 0 else "FAIL"
        print(
            f"{y_file.stem:<25} {len(expected_ids):<12} {len(tp):<12} {len(fp):<16} {status}"
        )
        if status == "FAIL":
            if fn:
                print(f"   Missing expected: {sorted(fn)}")
            if fp:
                print(f"   Unexpected findings: {sorted(fp)}")

    print("-" * 75)
    det_rate = (total_detected / total_expected * 100) if total_expected > 0 else 100.0
    print(
        f"Summary: Total Expected: {total_expected} | Detected: {total_detected} ({det_rate:.1f}%) | False Positives: {total_false_positives}"
    )
    return total_expected, total_detected, total_false_positives


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Cloud Copilot detection accuracy against ground truth."
    )
    parser.add_argument(
        "--dir",
        dest="arch_dir",
        default=str(DEFAULT_ARCH_DIR),
        help="Directory containing *.yaml and *.expected.json files",
    )
    args = parser.parse_args()

    total_expected, total_detected, total_fps = evaluate_architectures(
        Path(args.arch_dir)
    )
    if total_expected > total_detected or total_fps > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
