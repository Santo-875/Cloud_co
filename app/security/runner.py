"""External tool runner for terraform validate, Checkov, and Trivy."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.models import Architecture, Finding
from app.rules import evaluate_graph_rules
from app.security.normalizer import (
    deduplicate_and_merge_findings,
    normalize_checkov_finding,
    normalize_trivy_finding,
)
from app.terraform.generator import TerraformGenerator

COMMAND_TIMEOUT_SECONDS = 45


def run_command_safely(args: list[str], cwd: Path) -> tuple[int, str, str]:
    """Execute command with argument lists, timeout, isolated directory, and no shell=True.

    INVARIANT: Command must never contain 'apply'.
    """
    for token in args:
        if token.lower() == "apply":
            raise ValueError(
                "CRITICAL INVARIANT VIOLATION: Execution of 'apply' is strictly forbidden!"
            )

    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


class SecurityScannerRunner:
    """Orchestrates graph rules and external CLI tools (terraform validate, checkov, trivy)."""

    def __init__(self, architecture: Architecture) -> None:
        self.architecture = architecture
        self.scanners_run: list[str] = ["graph_rule"]

    def run_scans(self) -> tuple[list[Finding], list[str]]:
        """Run all available scanning mechanisms and merge normalized results."""
        all_findings: list[Finding] = []

        # 1. Deterministic graph security rules
        graph_findings = evaluate_graph_rules(self.architecture)
        all_findings.extend(graph_findings)

        # 2. External scanners (require generated Terraform files)
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            generator = TerraformGenerator(self.architecture)
            generator.write_to_directory(tmp_dir)

            # Terraform validate
            tf_bin = shutil.which("terraform")
            if tf_bin:
                self.scanners_run.append("terraform_validate")
                # init without backend
                run_command_safely([tf_bin, "init", "-backend=false"], cwd=tmp_dir)
                rc, out, _ = run_command_safely(
                    [tf_bin, "validate", "-json"], cwd=tmp_dir
                )
                if rc != 0 and out:
                    try:
                        val_json = json.loads(out)
                        for diag in val_json.get("diagnostics", []):
                            if diag.get("severity") == "error":
                                all_findings.append(
                                    Finding(
                                        id="TF_VALIDATE_ERROR",
                                        ids=["TF_VALIDATE_ERROR"],
                                        severity="high",
                                        resource=diag.get("address", "terraform"),
                                        title=diag.get(
                                            "summary", "Terraform validation error"
                                        ),
                                        source="validate",
                                        sources=["validate"],
                                        fix_hint=diag.get("detail"),
                                    )
                                )
                    except (json.JSONDecodeError, KeyError):
                        pass

            # Checkov
            checkov_bin = shutil.which("checkov")
            if checkov_bin:
                self.scanners_run.append("checkov")
                rc, out, _ = run_command_safely(
                    [
                        checkov_bin,
                        "-d",
                        str(tmp_dir),
                        "-o",
                        "json",
                        "--quiet",
                        "--compact",
                    ],
                    cwd=tmp_dir,
                )
                if out:
                    try:
                        checkov_data = json.loads(out)
                        # Checkov can return list of reports or single dict
                        reports = (
                            checkov_data
                            if isinstance(checkov_data, list)
                            else [checkov_data]
                        )
                        for rep in reports:
                            failed = rep.get("results", {}).get("failed_checks", [])
                            for f in failed:
                                all_findings.append(normalize_checkov_finding(f))
                    except (json.JSONDecodeError, KeyError):
                        pass

            # Trivy
            trivy_bin = shutil.which("trivy")
            if trivy_bin:
                self.scanners_run.append("trivy")
                rc, out, _ = run_command_safely(
                    [trivy_bin, "config", str(tmp_dir), "--format", "json", "--quiet"],
                    cwd=tmp_dir,
                )
                if out:
                    try:
                        trivy_data = json.loads(out)
                        results = trivy_data.get("Results", [])
                        for target in results:
                            for m in target.get("Misconfigurations", []):
                                all_findings.append(normalize_trivy_finding(m))
                    except (json.JSONDecodeError, KeyError):
                        pass

        # Deduplicate and merge all findings
        merged = deduplicate_and_merge_findings(all_findings)
        return merged, sorted(set(self.scanners_run))
