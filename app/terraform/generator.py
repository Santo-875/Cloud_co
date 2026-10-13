"""Deterministic Terraform HCL generator for Cloud Copilot."""

import argparse
from pathlib import Path
from typing import Any

import jinja2

from app.models import Architecture, Node
from app.parser import parse_architecture

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Explicit deterministic resource ordering for clean terraform diffs
RESOURCE_TYPE_ORDER: dict[str, int] = {
    "vpc": 10,
    "internet_gateway": 20,
    "route_table": 30,
    "subnet": 40,
    "security_group": 50,
    "iam_role": 60,
    "s3": 70,
    "ebs": 80,
    "ec2": 90,
    "rds": 100,
    "sns": 110,
    "cloudwatch": 120,
}


def hcl_string(value: Any) -> str:
    r"""Safely escape any input into an HCL string literal.

    Neutralizes:
    - Backslashes `\` -> `\\`
    - Double quotes `"` -> `\"`
    - HCL string interpolation `${` -> `$${`
    - HCL directive interpolation `%{` -> `%%{`
    - Newlines and carriage returns -> `\n`, `\r`
    """
    if value is None:
        return ""
    val_str = str(value)
    # First escape backslashes
    val_str = val_str.replace("\\", "\\\\")
    # Escape quotes
    val_str = val_str.replace('"', '\\"')
    # Escape interpolation sequences
    val_str = val_str.replace("${", "$${")
    val_str = val_str.replace("%{", "%%{")
    # Escape newlines
    val_str = val_str.replace("\r", "\\r")
    val_str = val_str.replace("\n", "\\n")
    return val_str


class TerraformGenerator:
    """Generates deterministic Terraform HCL files from an Architecture."""

    def __init__(self, architecture: Architecture) -> None:
        self.architecture = architecture
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["hcl_string"] = hcl_string

    def _prepare_nodes(self) -> list[dict[str, Any]]:
        """Pre-process nodes, synthesize public subnet routes if needed, and sort deterministically."""
        existing_nodes = list(self.architecture.nodes)
        node_map = {n.id: n for n in existing_nodes}

        synthesized_nodes: list[Node] = []
        synth_rt_map: dict[str, str] = {}

        # Detect if any public subnet exists without explicit IGW/RT
        has_explicit_igw = any(n.type == "internet_gateway" for n in existing_nodes)
        has_explicit_rt = any(n.type == "route_table" for n in existing_nodes)

        for n in existing_nodes:
            if n.type == "subnet" and n.props.get("public") is True:
                parent_vpc = n.parent
                if parent_vpc and not (has_explicit_igw or has_explicit_rt):
                    igw_id = f"{parent_vpc}_igw"
                    rt_id = f"{parent_vpc}_public_rt"

                    if not any(x.id == igw_id for x in synthesized_nodes):
                        synthesized_nodes.append(
                            Node(
                                id=igw_id,
                                type="internet_gateway",
                                parent=parent_vpc,
                                props={},
                            )
                        )
                    if not any(x.id == rt_id for x in synthesized_nodes):
                        synthesized_nodes.append(
                            Node(
                                id=rt_id,
                                type="route_table",
                                parent=parent_vpc,
                                props={
                                    "routes": [
                                        {
                                            "cidr_block": "0.0.0.0/0",
                                            "gateway_id": igw_id,
                                        }
                                    ]
                                },
                            )
                        )
                    synth_rt_map[n.id] = rt_id

        all_nodes = existing_nodes + synthesized_nodes

        # Deterministic sort: by resource type order, then by node id
        all_nodes.sort(key=lambda x: (RESOURCE_TYPE_ORDER.get(x.type, 999), x.id))

        prepared: list[dict[str, Any]] = []
        for item in all_nodes:
            node_dict: dict[str, Any] = {
                "id": item.id,
                "type": item.type,
                "props": item.props,
                "parent": item.parent,
                "uses": item.uses,
                "security_groups": [
                    u
                    for u in item.uses
                    if u in node_map and node_map[u].type == "security_group"
                ],
            }
            if item.id in synth_rt_map:
                node_dict["synth_route_table_id"] = synth_rt_map[item.id]
            prepared.append(node_dict)

        return prepared

    def generate(self) -> dict[str, str]:
        """Render all Terraform configuration files deterministically."""
        prepared_nodes = self._prepare_nodes()
        context = {
            "name": self.architecture.name,
            "region": self.architecture.region,
            "nodes": prepared_nodes,
        }

        providers_tmpl = self.env.get_template("providers.tf.j2")
        variables_tmpl = self.env.get_template("variables.tf.j2")
        outputs_tmpl = self.env.get_template("outputs.tf.j2")
        main_tmpl = self.env.get_template("main.tf.j2")

        return {
            "providers.tf": providers_tmpl.render(context),
            "variables.tf": variables_tmpl.render(context),
            "outputs.tf": outputs_tmpl.render(context),
            "main.tf": main_tmpl.render(context),
        }

    def write_to_directory(self, target_dir: Path) -> dict[str, Path]:
        """Render and write files to target directory."""
        target_dir.mkdir(parents=True, exist_ok=True)
        rendered = self.generate()
        result: dict[str, Path] = {}
        for filename, content in rendered.items():
            file_path = target_dir / filename
            file_path.write_text(content, encoding="utf-8")
            result[filename] = file_path
        return result


def main() -> None:
    """CLI entrypoint: python -m app.terraform.generator <arch.yaml> --out <dir>"""
    parser = argparse.ArgumentParser(
        description="Generate deterministic Terraform configuration from Cloud Copilot YAML architecture."
    )
    parser.add_argument(
        "architecture_file", help="Path to input YAML architecture file"
    )
    parser.add_argument(
        "--out",
        dest="out_dir",
        default="generated_tf",
        help="Target directory to write Terraform files",
    )
    args = parser.parse_args()

    arch_path = Path(args.architecture_file)
    if not arch_path.exists():
        raise SystemExit(f"File not found: {arch_path}")

    raw_content = arch_path.read_text(encoding="utf-8")
    arch = parse_architecture(raw_content)

    generator = TerraformGenerator(arch)
    out_path = Path(args.out_dir)
    generator.write_to_directory(out_path)
    print(f"Terraform successfully written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
