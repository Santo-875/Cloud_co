"""Cloud infrastructure cost estimator based on reference pricing table."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from app.models import Architecture

PRICES_FILE = Path(__file__).parent / "prices.yaml"


@dataclass
class CostLineItem:
    resource_id: str
    resource_type: str
    description: str
    monthly_cost_usd: float
    details: dict[str, Any]


@dataclass
class CostEstimateReport:
    line_items: list[dict[str, Any]]
    total_monthly_usd: float
    assumptions: dict[str, Any]
    disclaimer: str
    last_updated: str


class CostEstimator:
    """Calculates deterministic monthly cost estimations from Architecture resources."""

    def __init__(self, prices_path: Path | None = None) -> None:
        self.prices_path = prices_path or PRICES_FILE
        self.prices = self._load_prices()

    def _load_prices(self) -> dict[str, Any]:
        if not self.prices_path.exists():
            raise FileNotFoundError(f"Pricing file missing: {self.prices_path}")
        with open(self.prices_path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def estimate(self, architecture: Architecture) -> CostEstimateReport:
        """Estimate monthly infrastructure expenses for given architecture."""
        hours = self.prices.get("assumptions", {}).get("hours_per_month", 730)
        line_items: list[CostLineItem] = []

        for node in architecture.nodes:
            if node.type == "ec2":
                inst_type = node.props.get("instance_type", "t3.micro")
                rates = self.prices.get("ec2_instances", {})
                rate_per_hr = rates.get(inst_type, rates.get("default", 0.0104))
                compute_cost = round(rate_per_hr * hours, 2)

                # Include root volume cost (default 8 GB gp3 if ebs_encrypted)
                ebs_rates = self.prices.get("ebs_storage_per_gb_month", {})
                root_vol_rate = ebs_rates.get("gp3", 0.08)
                root_vol_cost = round(8 * root_vol_rate, 2)
                total_ec2 = round(compute_cost + root_vol_cost, 2)

                line_items.append(
                    CostLineItem(
                        resource_id=node.id,
                        resource_type="ec2",
                        description=f"EC2 Instance ({inst_type}, 24/7) + 8GB gp3 root EBS",
                        monthly_cost_usd=total_ec2,
                        details={
                            "hourly_rate": rate_per_hr,
                            "hours": hours,
                            "compute_cost": compute_cost,
                            "root_ebs_cost": root_vol_cost,
                        },
                    )
                )

            elif node.type == "rds":
                inst_class = node.props.get("instance_class", "db.t3.micro")
                rates = self.prices.get("rds_instances", {})
                rate_per_hr = rates.get(inst_class, rates.get("default", 0.0170))
                db_compute = round(rate_per_hr * hours, 2)

                storage_gb = node.props.get("allocated_storage", 20)
                ebs_rates = self.prices.get("ebs_storage_per_gb_month", {})
                storage_cost = round(storage_gb * ebs_rates.get("gp3", 0.08), 2)
                total_rds = round(db_compute + storage_cost, 2)

                line_items.append(
                    CostLineItem(
                        resource_id=node.id,
                        resource_type="rds",
                        description=f"RDS Instance ({inst_class}, {storage_gb}GB storage)",
                        monthly_cost_usd=total_rds,
                        details={
                            "hourly_rate": rate_per_hr,
                            "compute_cost": db_compute,
                            "storage_gb": storage_gb,
                            "storage_cost": storage_cost,
                        },
                    )
                )

            elif node.type == "ebs":
                size_gb = node.props.get("size_gb", 20)
                vol_type = node.props.get("volume_type", "gp3")
                rates = self.prices.get("ebs_storage_per_gb_month", {})
                rate_per_gb = rates.get(vol_type, rates.get("default", 0.08))
                vol_cost = round(size_gb * rate_per_gb, 2)

                line_items.append(
                    CostLineItem(
                        resource_id=node.id,
                        resource_type="ebs",
                        description=f"EBS Volume ({size_gb}GB {vol_type})",
                        monthly_cost_usd=vol_cost,
                        details={"size_gb": size_gb, "rate_per_gb": rate_per_gb},
                    )
                )

            elif node.type == "s3":
                s3_info = self.prices.get("s3_storage_per_gb_month", {})
                rate_per_gb = s3_info.get("standard", 0.023)
                baseline_gb = s3_info.get("assumed_baseline_gb", 50)
                s3_cost = round(baseline_gb * rate_per_gb, 2)

                line_items.append(
                    CostLineItem(
                        resource_id=node.id,
                        resource_type="s3",
                        description=f"S3 Standard Storage (baseline {baseline_gb}GB)",
                        monthly_cost_usd=s3_cost,
                        details={
                            "baseline_gb": baseline_gb,
                            "rate_per_gb": rate_per_gb,
                        },
                    )
                )

            elif node.type == "cloudwatch":
                rate = self.prices.get("cloudwatch_log_per_gb", 0.50)
                baseline_gb = self.prices.get("cloudwatch_assumed_gb_month", 5)
                cw_cost = round(baseline_gb * rate, 2)

                line_items.append(
                    CostLineItem(
                        resource_id=node.id,
                        resource_type="cloudwatch",
                        description=f"CloudWatch Logs Ingestion ({baseline_gb}GB)",
                        monthly_cost_usd=cw_cost,
                        details={"baseline_gb": baseline_gb, "rate_per_gb": rate},
                    )
                )

        total_cost = round(sum(item.monthly_cost_usd for item in line_items), 2)
        disclaimer = (
            "NOTICE: Cost estimations are calculated from baseline reference tables for directional guidance. "
            "Actual AWS bills depend on data transfer, request volumes, dynamic auto-scaling, and active region pricing."
        )

        return CostEstimateReport(
            line_items=[asdict(item) for item in line_items],
            total_monthly_usd=total_cost,
            assumptions=self.prices.get("assumptions", {}),
            disclaimer=disclaimer,
            last_updated=self.prices.get("last_updated", "unknown"),
        )
