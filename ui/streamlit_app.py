import json
import os
from pathlib import Path

import httpx
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")

st.set_page_config(
    page_title="Cloud Copilot | DevSecOps & Architecture",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Cloud Copilot")
st.caption(
    "Automated Cloud Security Analysis, Deterministic IaC Generation, Cost Estimation, and Grounded LLM Q&A"
)

# Sidebar: Architecture Definition & Upload
with st.sidebar:
    st.header("Upload Architecture")
    sample_choice = st.selectbox(
        "Load Sample Architecture",
        [
            "(Select Sample)",
            "Secure Sample",
            "Insecure SSH Sample",
            "Public RDS Sample",
        ],
    )

    sample_code = ""
    sample_dir = Path(__file__).parent.parent / "tests" / "architectures"
    if sample_choice == "Secure Sample" and (sample_dir / "secure.yaml").exists():
        sample_code = (sample_dir / "secure.yaml").read_text(encoding="utf-8")
    elif (
        sample_choice == "Insecure SSH Sample"
        and (sample_dir / "insecure_ssh.yaml").exists()
    ):
        sample_code = (sample_dir / "insecure_ssh.yaml").read_text(encoding="utf-8")
    elif (
        sample_choice == "Public RDS Sample"
        and (sample_dir / "public_rds.yaml").exists()
    ):
        sample_code = (sample_dir / "public_rds.yaml").read_text(encoding="utf-8")

    arch_input = st.text_area(
        "Architecture YAML Specification",
        value=sample_code,
        height=320,
        placeholder="name: my-app\nregion: us-east-1\nresources:\n  - id: vpc_1\n    type: vpc\n...",
    )

    if st.button("Parse & Load Architecture", type="primary"):
        if not arch_input.strip():
            st.error("Please enter or select architecture YAML.")
        else:
            try:
                with httpx.Client(base_url=API_BASE_URL, timeout=10.0) as client:
                    resp = client.post(
                        "/architecture",
                        content=arch_input.encode("utf-8"),
                        headers={"Content-Type": "text/yaml"},
                    )
                    if resp.status_code == 201:
                        data = resp.json()
                        st.session_state["active_arch_id"] = data["id"]
                        st.session_state["active_arch_name"] = data["name"]
                        st.success(f"Loaded: {data['name']} (ID: {data['id'][:8]}...)")
                    else:
                        st.error(f"Error {resp.status_code}: {resp.text}")
            except (httpx.HTTPError, json.JSONDecodeError, OSError) as exc:
                st.error(f"Failed to connect to API ({API_BASE_URL}): {exc}")

    active_id = st.session_state.get("active_arch_id")
    if active_id:
        st.info(
            f"Active Architecture: `{st.session_state.get('active_arch_name')}`\nID: `{active_id}`"
        )

# Main Content Tabs
tab_topology, tab_findings, tab_terraform, tab_cost, tab_chat = st.tabs(
    [
        "Topology & Graph",
        "Security Findings",
        "Terraform IaC",
        "Cost Estimator",
        "Chat Copilot",
    ]
)

if not active_id:
    st.info(
        "👈 Please enter YAML or select a sample in the sidebar and click **'Parse & Load Architecture'**."
    )
else:
    # Tab 1: Topology
    with tab_topology:
        st.subheader("Architecture Topology")
        try:
            with httpx.Client(base_url=API_BASE_URL, timeout=10.0) as client:
                graph_resp = client.get(f"/architecture/{active_id}/graph")
                if graph_resp.status_code == 200:
                    graph_data = graph_resp.json()
                    col1, col2 = st.columns([1, 1])
                    with col1:
                        st.write("**Nodes**", len(graph_data.get("nodes", [])))
                        for n in graph_data.get("nodes", []):
                            st.code(
                                f"[{n['type']}] {n['id']} (parent: {n.get('parent')})",
                                language="text",
                            )
                    with col2:
                        st.write(
                            "**Connections & Edges**", len(graph_data.get("edges", []))
                        )
                        for e in graph_data.get("edges", []):
                            st.code(
                                f"{e['source']} --({e['kind']}:{e.get('label')})--> {e['target']}",
                                language="text",
                            )
                    st.write("**Clusters**")
                    st.json(graph_data.get("clusters", []))
        except (httpx.HTTPError, json.JSONDecodeError, OSError) as e:
            st.error(f"Graph query failed: {e}")

    # Tab 2: Findings
    with tab_findings:
        st.subheader("Security Scanner Results")
        try:
            with httpx.Client(base_url=API_BASE_URL, timeout=20.0) as client:
                scan_resp = client.post(f"/architecture/{active_id}/scan")
                if scan_resp.status_code == 200:
                    scan_data = scan_resp.json()
                    findings = scan_data.get("findings", [])
                    st.write(
                        f"Scanners executed: `{', '.join(scan_data.get('scanners_run', []))}`"
                    )

                    if not findings:
                        st.success(
                            "✅ Zero security violations detected. Architecture complies with baseline policies!"
                        )
                    else:
                        for f in findings:
                            sev = f.get("severity", "medium").upper()
                            color = (
                                "red"
                                if sev in ("HIGH", "CRITICAL")
                                else ("orange" if sev == "MEDIUM" else "blue")
                            )
                            st.markdown(
                                f"### :{color}[[{sev}]] {f['title']}\n"
                                f"- **Resource**: `{f['resource']}`\n"
                                f"- **Detection Sources**: `{', '.join(f.get('sources', []))}`\n"
                                f"- **Check IDs**: `{', '.join(f.get('ids', []))}`\n"
                                f"- **Remediation Hint**: {f.get('fix_hint')}"
                            )
                            st.divider()
        except (httpx.HTTPError, json.JSONDecodeError, OSError) as e:
            st.error(f"Scan failed: {e}")

    # Tab 3: Terraform
    with tab_terraform:
        st.subheader("Deterministic Terraform Module")
        try:
            with httpx.Client(base_url=API_BASE_URL, timeout=10.0) as client:
                tf_resp = client.post(f"/architecture/{active_id}/terraform")
                if tf_resp.status_code == 200:
                    tf_files = tf_resp.json().get("files", {})
                    for filename, code in tf_files.items():
                        with st.expander(
                            f"📄 {filename}", expanded=(filename == "main.tf")
                        ):
                            st.code(code, language="hcl")
        except (httpx.HTTPError, json.JSONDecodeError, OSError) as e:
            st.error(f"Terraform generation failed: {e}")

    # Tab 4: Cost
    with tab_cost:
        st.subheader("Monthly Infrastructure Cost Estimate")
        try:
            with httpx.Client(base_url=API_BASE_URL, timeout=10.0) as client:
                cost_resp = client.get(f"/architecture/{active_id}/cost")
                if cost_resp.status_code == 200:
                    cost_data = cost_resp.json()
                    st.metric(
                        "Total Monthly Estimate",
                        f"${cost_data.get('total_monthly_usd', 0.0):,.2f} USD",
                    )
                    st.caption(
                        f"Pricing reference date: {cost_data.get('last_updated')}"
                    )
                    st.warning(cost_data.get("disclaimer"))

                    st.write("**Line Items**")
                    for item in cost_data.get("line_items", []):
                        st.write(
                            f"- **{item['resource_id']}** ({item['description']}): **${item['monthly_cost_usd']:.2f}/mo**"
                        )
        except (httpx.HTTPError, json.JSONDecodeError, OSError) as e:
            st.error(f"Cost estimation failed: {e}")

    # Tab 5: Chat
    with tab_chat:
        st.subheader("Grounded Explainer Chat")
        mode = st.radio(
            "Mode",
            ["explain_architecture", "explain_findings", "answer_question"],
            horizontal=True,
        )
        user_msg = st.text_input(
            "Your inquiry", placeholder="Why is SSH exposed on sg_1? How do I fix it?"
        )

        if st.button("Send Inquiry"):
            if not user_msg.strip() and mode == "answer_question":
                st.warning("Please type a message.")
            else:
                try:
                    with httpx.Client(base_url=API_BASE_URL, timeout=25.0) as client:
                        chat_resp = client.post(
                            "/chat",
                            json={
                                "architecture_id": active_id,
                                "message": user_msg or "Explain this setup",
                                "mode": mode,
                            },
                        )
                        if chat_resp.status_code == 200:
                            c_data = chat_resp.json()
                            st.markdown(
                                f"**Copilot Response:**\n\n{c_data['response']}"
                            )
                            st.caption(
                                f"Sources consulted: {', '.join(c_data.get('sources', []))}"
                            )
                        elif chat_resp.status_code == 429:
                            st.error(
                                "Rate limit reached (10 requests/min). Please pause briefly."
                            )
                        else:
                            st.error(f"Chat error: {chat_resp.text}")
                except (httpx.HTTPError, json.JSONDecodeError, OSError) as e:
                    st.error(f"Chat request failed: {e}")
