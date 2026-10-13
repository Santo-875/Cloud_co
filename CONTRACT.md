# Cloud Copilot System Contract

> **Status:** FROZEN  
> This document is the single source of truth for schemas, API specifications, input validation rules, finding formats, and repository structure. Any proposed modification must be approved before implementation.

---

## 1. Domain Models and Schema

### 1.1 Core Pydantic Models (`app/models.py`)

```python
from typing import Literal
from pydantic import BaseModel, Field

ResourceType = Literal[
    "vpc",
    "subnet",
    "security_group",
    "ec2",
    "ebs",
    "s3",
    "cloudwatch",
    "sns",
    "iam_role",
    "rds",
    "internet_gateway",
    "route_table",
]


class Node(BaseModel):
    id: str  # Must match ^[a-z][a-z0-9_]{0,40}$
    type: ResourceType
    props: dict = Field(default_factory=dict)  # Validated against per-type prop schemas
    parent: str | None = None  # containment: e.g. subnet in vpc
    uses: list[str] = Field(default_factory=list)  # attachment: e.g. ec2 uses security group


class Edge(BaseModel):
    source: str
    target: str
    kind: Literal["data", "network", "iam", "monitoring"]
    label: str | None = None


class Architecture(BaseModel):
    name: str
    region: str
    nodes: list[Node]
    edges: list[Edge] = Field(default_factory=list)


class Finding(BaseModel):
    id: str  # Canonical or primary check id for display (e.g. CKV_AWS_24 or RULE_SSH_OPEN)
    ids: list[str] = Field(default_factory=list)  # All merged check ids across sources
    severity: Literal["low", "medium", "high", "critical"]
    resource: str  # node id
    title: str
    source: Literal["checkov", "trivy", "validate", "graph_rule"]  # Primary detection source
    sources: list[Literal["checkov", "trivy", "validate", "graph_rule"]] = Field(
        default_factory=list
    )  # Preserved list of all detection sources
    fix_hint: str | None = None
```

---

## 2. Input Specification & Parser Contract

### 2.1 Canonical Input YAML Format

```yaml
name: web-app-demo
region: ap-south-1
resources:
  - id: vpc1
    type: vpc
    props:
      cidr: 10.0.0.0/16
  - id: sub1
    type: subnet
    in: vpc1
    props:
      cidr: 10.0.1.0/24
      public: true
  - id: sg1
    type: security_group
    in: vpc1
    props:
      ingress:
        - port: 22
          cidr: 0.0.0.0/0
  - id: ec2a
    type: ec2
    in: sub1
    uses:
      - sg1
    props:
      instance_type: t3.micro
      ebs_encrypted: false
  - id: bucket1
    type: s3
    props:
      versioning: false
      public: false
connections:
  - from: ec2a
    to: bucket1
    kind: data
    label: uploads
```

### 2.2 Parser Normalization Rules
1. `resources` maps to `nodes`.
2. `connections` maps to `edges`.
3. In resources: `in` maps to `parent`.
4. In connections: `from` maps to `source`, and `to` maps to `target`.
5. Direct `nodes` and `edges` in input are also accepted if already normalized.

### 2.3 Strict Rejection Criteria (Security & Limits)
The parser (`app/parser.py`) must raise a structured `ParserError` on:
- Input size exceeding **100 KB** (102,400 bytes).
- Node count exceeding **200** nodes.
- Duplicate resource `id`.
- Resource `id` not matching regex `^[a-z][a-z0-9_]{0,40}$`.
- Unknown `type` (not in `ResourceType`).
- Invalid resource properties (unknown keys rejected via `extra='forbid'`, invalid CIDRs, ports out of 0-65535, invalid instance types or types).
- Dangling references:
  - `parent` refers to non-existent node ID.
  - `uses` contains non-existent node ID.
  - `source` or `target` in connection refers to non-existent node ID.
- Cycles in containment (`parent`) or attachment (`uses`).
- Invalid YAML syntax or non-dictionary root structures.
- Unsafe YAML loading (must exclusively use `yaml.safe_load`).

---

## 3. Security Findings & Normalization Contract

### 3.1 Severity Levels
- `critical`: Extreme risk (e.g., exposed admin interfaces, unrestricted data leakage).
- `high`: Major security violations (e.g., open SSH/RDP to world, public S3 bucket, public RDS).
- `medium`: Insecure defaults (e.g., unencrypted EBS volumes or unencrypted RDS storage, public subnet without internet gateway route).
- `low`: Best practice omissions (e.g., S3 versioning disabled).

### 3.2 Finding Sources
- `graph_rule`: Evaluated deterministically on the parsed `Architecture` graph.
- `validate`: Derived from `terraform validate` errors/warnings.
- `checkov`: Scanned from generated Terraform files using Checkov CLI (`-o json`).
- `trivy`: Scanned from generated Terraform files using Trivy config scan (`--format json`).

### 3.3 Normalizer Deduplication Rule
When both graph rules and external scanners report findings for the same `(resource, category)`:
- Merge into a single `Finding`.
- Set severity to the highest severity among all matching findings.
- Retain the most specific title and fix hint.
- Preserve list of all detection sources in `sources` and all check identifiers in `ids`.
- Maintain canonical display `id` and primary `source`.

---

## 4. REST API Specification

| Method | Endpoint | Description | Request Body | Response Status & Body |
|---|---|---|---|---|
| `GET` | `/health` | Service health probe | None | `200 { "status": "ok", "version": "0.1.0" }` |
| `POST` | `/architecture` | Parse, validate, and store architecture | Raw YAML/JSON string or JSON architecture | `201 { "id": str, "name": str, "region": str, "nodes_count": int, "edges_count": int }` |
| `GET` | `/architecture/{id}` | Retrieve stored architecture | None | `200 Architecture` |
| `GET` | `/architecture/{id}/graph` | Graph topology for visualization | None | `200 { "nodes": [...], "edges": [...], "clusters": [...] }` |
| `POST` | `/architecture/{id}/terraform` | Generate Terraform module files | None | `200 { "files": { "main.tf": str, "variables.tf": str, "outputs.tf": str, "providers.tf": str } }` |
| `POST` | `/architecture/{id}/scan` | Run graph rules and scanners | None | `200 { "findings": list[Finding], "scanners_run": list[str] }` |
| `GET` | `/architecture/{id}/cost` | Calculate estimated monthly cost | None | `200 { "line_items": [...], "total_monthly_usd": float, "assumptions": dict, "disclaimer": str, "last_updated": str }` |
| `POST` | `/chat` | Grounded explainer Q&A | `{ "architecture_id": str, "message": str, "mode": "explain_architecture" \| "explain_findings" \| "answer_question" }` | `200 { "response": str, "sources": list[str] }` |

Rate limit on `/chat`: 10 requests per minute per client IP (derived directly from `request.client.host`; `X-Forwarded-For` is ignored unless `TRUSTED_PROXY_HEADERS=true` is explicitly configured).
In-memory architecture store assigns random UUIDs (`uuid.uuid4()`), enforces an LRU capacity of 100 entries, and a 1-hour TTL.

---

## 5. Directory Structure

```
cloud-copilot/
├── CONTRACT.md
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── models.py
│   ├── parser.py
│   ├── graph.py
│   ├── rules.py
│   ├── store.py
│   ├── terraform/
│   │   ├── __init__.py
│   │   ├── generator.py
│   │   └── templates/
│   │       ├── providers.tf.j2
│   │       ├── variables.tf.j2
│   │       ├── outputs.tf.j2
│   │       └── main.tf.j2
│   ├── security/
│   │   ├── __init__.py
│   │   ├── runner.py
│   │   └── normalizer.py
│   ├── cost/
│   │   ├── __init__.py
│   │   ├── prices.yaml
│   │   └── estimator.py
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── ingest.py
│   │   ├── retriever.py
│   │   └── corpus/
│   └── llm/
│       ├── __init__.py
│       ├── client.py
│       ├── prompts.py
│       └── explainer.py
├── ui/
│   └── streamlit_app.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_parser.py
│   ├── test_graph.py
│   ├── test_rules.py
│   ├── test_terraform.py
│   ├── test_security.py
│   ├── test_cost.py
│   ├── test_rag.py
│   ├── test_llm.py
│   ├── test_api.py
│   ├── architectures/
│   │   ├── secure.yaml
│   │   ├── secure.expected.json
│   │   ├── insecure_ssh.yaml
│   │   ├── insecure_ssh.expected.json
│   │   ├── public_rds.yaml
│   │   └── public_rds.expected.json
│   └── fixtures/
│       ├── checkov_sample.json
│       └── trivy_sample.json
├── scripts/
│   └── eval.py
├── docs/
│   ├── README.md
│   └── THREAT_MODEL.md
├── .github/
│   └── workflows/
│       └── ci.yml
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## 6. Safety and Operational Invariants

1. **Zero Execution of Infrastructure**: Cloud Copilot only validates, plans, generates, and scans. It **must never execute `terraform apply`** or contact AWS credentials/APIs.
2. **Subprocess Isolation**: External tool execution (`terraform`, `checkov`, `trivy`) must exclusively pass argument lists into `subprocess.run(args, ...)` with timeouts and isolated temporary working directories. `shell=True` is strictly prohibited.
3. **No Hardcoded Secrets**: Zero secrets stored in git or files. API keys must only be read from environment variables (`GEMINI_API_KEY`).
4. **Offline Resilience**: All tests must execute offline with 100% pass rate using `MockLLMClient` and sample scanner fixtures. Missing CLI tools must degrade gracefully.
5. **Demo-Grade Architecture**: Cloud Copilot is designed as a single-user, demo-grade DevSecOps tool. Long-term state persistence and multi-tenant isolation are explicitly decoupled into advancement stages.
