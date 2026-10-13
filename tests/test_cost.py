"""Tests for app/cost/estimator.py."""

from app.cost.estimator import CostEstimator
from app.models import Architecture, Node


def test_cost_estimator_line_items_and_total() -> None:
    arch = Architecture(
        name="cost_sample",
        region="us-east-1",
        nodes=[
            Node(
                id="ec2_app",
                type="ec2",
                props={"instance_type": "t3.micro", "ebs_encrypted": True},
            ),
            Node(
                id="rds_db",
                type="rds",
                props={
                    "instance_class": "db.t3.micro",
                    "allocated_storage": 20,
                    "engine": "postgres",
                },
            ),
            Node(
                id="ebs_data", type="ebs", props={"size_gb": 50, "volume_type": "gp3"}
            ),
            Node(id="s3_assets", type="s3", props={"public": False}),
        ],
    )

    estimator = CostEstimator()
    report = estimator.estimate(arch)

    assert len(report.line_items) == 4
    assert report.total_monthly_usd > 0
    assert report.assumptions["hours_per_month"] == 730
    assert "NOTICE:" in report.disclaimer
    assert report.last_updated == "2026-10-13"

    types = {item["resource_type"] for item in report.line_items}
    assert types == {"ec2", "rds", "ebs", "s3"}


def test_cost_estimator_empty_architecture() -> None:
    arch = Architecture(
        name="empty",
        region="us-east-1",
        nodes=[],
    )
    estimator = CostEstimator()
    report = estimator.estimate(arch)
    assert len(report.line_items) == 0
    assert report.total_monthly_usd == 0.0
