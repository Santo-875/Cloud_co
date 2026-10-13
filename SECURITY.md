# Security Policy

## Reporting Security Issues

We take the security of **Cloud Copilot** seriously. If you identify a security vulnerability, please report it responsibly rather than opening a public issue.

- **Email**: `security@cloudcopilot.dev` (or open a private security advisory on GitHub).
- Include detailed replication steps, relevant architecture YAML payloads, and affected versions.
- We acknowledge reports within 48 hours and provide a remediation plan within 5 business days.

## Core Security Invariants

Cloud Copilot enforces strict architectural invariants:

1. **The Zero-Apply Invariant**:
   - The application strictly synthesizes and analyzes Terraform configurations but **never executes `terraform apply`**.
   - Subprocess invocations validate against forbidden tokens (`apply`), preventing any unexpected state execution against real cloud providers.

2. **Isolated Offline Execution**:
   - Automated unit and integration tests execute entirely offline.
   - External scanners (`checkov`, `trivy`, `terraform validate`) run in ephemeral, isolated temporary workspaces without network access to cloud credentials.

3. **Untrusted Input Boundaries**:
   - All architecture specifications (YAML/JSON) are treated as untrusted data subject to:
     - 100 KB payload size limit.
     - Maximum 200 node count.
     - Strict YAML safe parsing (`yaml.safe_load`).
     - Strict Pydantic models with `extra="forbid"`.
     - Strict regex validation on identifiers and AWS region format.
     - Referential integrity and cycle detection across containment and attachment edges.

4. **IaC & Prompt Injection Defenses**:
   - Universal string sanitization (`hcl_string()`) prevents Terraform HCL interpolation or block breakouts.
   - LLM prompts utilize XML-delimited boundaries separating system instructions from untrusted architecture content and user questions.
   - API keys are injected exclusively via environment variables and never logged or exposed in client responses.

For full architectural threat modeling, review [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
