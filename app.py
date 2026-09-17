import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List

import streamlit as st
from openai import OpenAI

st.set_page_config(
    page_title="AI Cyber Incident Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# App configuration / constants
# -----------------------------

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

MITRE_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1059.009": "Cloud API",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.002": "Bypass User Account Control",
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: RDP",
    "T1021.004": "Remote Services: SSH",
    "T1021.005": "VNC",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1105": "Ingress Tool Transfer",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1071.002": "File Transfer Protocols",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1057": "Process Discovery",
    "T1087": "Account Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1555": "Credentials from Password Stores",
    "T1555.003": "Credentials from Web Browsers",
    "T1548.003": "Sudo and Sudo Caching",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1210": "Exploitation of Remote Services",
    "T1055": "Process Injection",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1046": "Network Service Scanning",
    "T1595": "Active Scanning",
}

DEFAULT_LOG = """2026-09-17 09:31:02 host=WS-104 user=ali src=185.44.21.17 event=login_failed
2026-09-17 09:31:08 host=WS-104 user=ali src=185.44.21.17 event=login_failed
2026-09-17 09:31:17 host=WS-104 user=ali src=185.44.21.17 event=login_failed
2026-09-17 09:31:29 host=WS-104 user=ali src=185.44.21.17 event=login_success
2026-09-17 09:32:04 host=WS-104 user=ali process=powershell.exe event=process_start
2026-09-17 09:32:09 host=WS-104 user=ali process=powershell.exe command="powershell -enc SQBtAHAAbwByAHQ..."
2026-09-17 09:33:44 host=WS-104 user=ali dst=198.51.100.23 port=443 event=outbound_connection
"""

SYSTEM_PROMPT = """
You are a defensive cybersecurity incident-response assistant.

Your job is to analyze security logs supplied by the user and produce a cautious,
evidence-based incident assessment. This is for defensive investigation.

Rules:
1. Do not claim certainty when the logs do not prove it.
2. Separate OBSERVATIONS from HYPOTHESES.
3. Quote short exact evidence snippets from the supplied logs when useful.
4. Reconstruct a chronological attack/event timeline.
5. Map behavior to MITRE ATT&CK techniques only when reasonably supported.
6. Give confidence per major finding: High, Medium, or Low.
7. Include plausible benign/alternative explanations.
8. Identify missing evidence that would materially change the assessment.
9. Recommend defensive containment, preservation, eradication, and follow-up steps.
10. Do not provide instructions for attacking systems, credential theft, evasion,
    malware creation, or unauthorized access.
11. Never invent an IP reputation, CVE, user identity, geolocation, or threat actor.
12. Return valid JSON only, matching the requested schema.

JSON schema:
{
  "incident_title": "string",
  "severity": "Critical|High|Medium|Low|Informational",
  "overall_confidence": "High|Medium|Low",
  "executive_summary": "string",
  "observations": [
    {
      "finding": "string",
      "confidence": "High|Medium|Low",
      "evidence": ["short exact log snippets"]
    }
  ],
  "timeline": [
    {
      "time": "string",
      "event": "string",
      "significance": "string"
    }
  ],
  "mitre_attack": [
    {
      "technique_id": "string",
      "technique_name": "string",
      "reason": "string",
      "confidence": "High|Medium|Low"
    }
  ],
  "attack_story": "string",
  "alternative_explanations": ["string"],
  "missing_evidence": ["string"],
  "recommended_actions": [
    {
      "priority": "Immediate|High|Medium|Low",
      "action": "string",
      "reason": "string"
    }
  ],
  "ioc_candidates": [
    {
      "type": "IP|Domain|Hash|User|Host|Process|Command|Other",
      "value": "string",
      "why_relevant": "string"
    }
  ],
  "limitations": ["string"]
}
"""

REVIEW_PROMPT = """
You are a defensive cybersecurity peer reviewer.

Review the investigator's JSON assessment against the original logs.

Do not create a new attack procedure. Look specifically for:
- unsupported conclusions,
- hallucinated facts,
- overconfident severity,
- MITRE ATT&CK mappings that are not sufficiently supported,
- evidence that contradicts the conclusion,
- plausible benign explanations that were missed,
- missing telemetry needed for confirmation.

Return valid JSON only:
{
  "review_verdict": "Supported|Partially Supported|Insufficient Evidence",
  "confidence": "High|Medium|Low",
  "strengths": ["string"],
  "concerns": ["string"],
  "alternative_hypotheses": ["string"],
  "evidence_gaps": ["string"],
  "suggested_revisions": ["string"]
}
"""


# -----------------------------
# Styling
# -----------------------------

st.markdown(
    """
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 3rem;}
.hero {
    padding: 1.3rem 1.5rem;
    border: 1px solid rgba(128,128,128,.25);
    border-radius: 16px;
    margin-bottom: 1rem;
}
.metric-card {
    padding: 1rem;
    border: 1px solid rgba(128,128,128,.25);
    border-radius: 12px;
    min-height: 100px;
}
.small-muted {opacity:.7; font-size:.9rem;}
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="hero">
<h1>🛡️ AI Cyber Incident Investigator</h1>
<p class="small-muted">
Evidence-first GenAI assistance for SOC investigation, incident reconstruction,
MITRE ATT&CK mapping, and peer review.
</p>
</div>
""",
    unsafe_allow_html=True,
)

# -----------------------------
# Helpers
# -----------------------------

def get_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        try:
            api_key = st.secrets["OPENAI_API_KEY"]
        except Exception:
            api_key = None
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured. Add it to Streamlit Secrets "
            "or set it as an environment variable."
        )
    return OpenAI(api_key=api_key)


def extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError("The model did not return valid JSON.")
        return json.loads(match.group(0))


def call_json(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    client = get_client()

    response = client.chat.completions.create(
        model=MODEL,
        temperature=0.1,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    content = response.choices[0].message.content or "{}"
    return extract_json(content)


def basic_log_stats(logs: str) -> Dict[str, Any]:
    lines = [x for x in logs.splitlines() if x.strip()]
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", logs)))
    domains = sorted(
        set(
            re.findall(
                r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|pk|co|dev)\b",
                logs,
            )
        )
    )

    keyword_hits = {}
    for keyword in [
        "failed",
        "login",
        "powershell",
        "encoded",
        "command",
        "sudo",
        "ssh",
        "rdp",
        "download",
        "upload",
        "outbound",
        "process",
        "admin",
        "root",
    ]:
        count = len(re.findall(re.escape(keyword), logs, flags=re.IGNORECASE))
        if count:
            keyword_hits[keyword] = count

    return {
        "line_count": len(lines),
        "ip_candidates": ips,
        "domain_candidates": domains,
        "keyword_hits": keyword_hits,
    }


def render_severity(severity: str):
    labels = {
        "Critical": "🔴 Critical",
        "High": "🟠 High",
        "Medium": "🟡 Medium",
        "Low": "🟢 Low",
        "Informational": "🔵 Informational",
    }
    st.metric("Severity", labels.get(severity, severity))


def safe_text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def generate_markdown_report(analysis: Dict[str, Any], review: Dict[str, Any]) -> str:
    lines = [
        "# AI Cyber Incident Investigation Report",
        "",
        f"**Generated:** {datetime.now().isoformat(timespec='seconds')}",
        f"**Model:** {MODEL}",
        "",
        f"## {safe_text(analysis.get('incident_title', 'Incident Assessment'))}",
        "",
        f"**Severity:** {safe_text(analysis.get('severity'))}",
        f"**Overall confidence:** {safe_text(analysis.get('overall_confidence'))}",
        "",
        "## Executive Summary",
        safe_text(analysis.get("executive_summary")),
        "",
        "## Observations",
    ]

    for item in analysis.get("observations", []):
        lines.append(
            f"- **{safe_text(item.get('finding'))}** "
            f"({safe_text(item.get('confidence'))} confidence)"
        )
        for ev in item.get("evidence", []):
            lines.append(f"  - Evidence: `{safe_text(ev)}`")

    lines += ["", "## Timeline"]
    for item in analysis.get("timeline", []):
        lines.append(
            f"- **{safe_text(item.get('time'))}** — "
            f"{safe_text(item.get('event'))} — {safe_text(item.get('significance'))}"
        )

    lines += ["", "## MITRE ATT&CK Mapping"]
    for item in analysis.get("mitre_attack", []):
        lines.append(
            f"- **{safe_text(item.get('technique_id'))} — "
            f"{safe_text(item.get('technique_name'))}** "
            f"({safe_text(item.get('confidence'))}) — {safe_text(item.get('reason'))}"
        )

    lines += [
        "",
        "## Attack / Event Story",
        safe_text(analysis.get("attack_story")),
        "",
        "## Alternative Explanations",
    ]
    lines += [f"- {safe_text(x)}" for x in analysis.get("alternative_explanations", [])]

    lines += ["", "## Missing Evidence"]
    lines += [f"- {safe_text(x)}" for x in analysis.get("missing_evidence", [])]

    lines += ["", "## Recommended Defensive Actions"]
    for item in analysis.get("recommended_actions", []):
        lines.append(
            f"- **{safe_text(item.get('priority'))}:** "
            f"{safe_text(item.get('action'))} — {safe_text(item.get('reason'))}"
        )

    lines += ["", "## IOC Candidates"]
    for item in analysis.get("ioc_candidates", []):
        lines.append(
            f"- `{safe_text(item.get('type'))}` — `{safe_text(item.get('value'))}`: "
            f"{safe_text(item.get('why_relevant'))}"
        )

    lines += ["", "## AI Peer Review"]
    lines += [
        f"**Verdict:** {safe_text(review.get('review_verdict'))}",
        f"**Confidence:** {safe_text(review.get('confidence'))}",
        "",
        "### Strengths",
    ]
    lines += [f"- {safe_text(x)}" for x in review.get("strengths", [])]
    lines += ["", "### Concerns"]
    lines += [f"- {safe_text(x)}" for x in review.get("concerns", [])]
    lines += ["", "### Alternative Hypotheses"]
    lines += [f"- {safe_text(x)}" for x in review.get("alternative_hypotheses", [])]
    lines += ["", "### Evidence Gaps"]
    lines += [f"- {safe_text(x)}" for x in review.get("evidence_gaps", [])]
    lines += ["", "### Suggested Revisions"]
    lines += [f"- {safe_text(x)}" for x in review.get("suggested_revisions", [])]

    lines += ["", "## Limitations"]
    lines += [f"- {safe_text(x)}" for x in analysis.get("limitations", [])]

    return "\n".join(lines)


# -----------------------------
# Sidebar
# -----------------------------

with st.sidebar:
    st.header("⚙️ Investigation Settings")

    model_input = st.text_input(
        "OpenAI model",
        value=MODEL,
        help="Use a model available to your OpenAI API account.",
    )
    MODEL = model_input.strip() or MODEL

    st.divider()

    st.subheader("Input")
    input_mode = st.radio(
        "Log source",
        ["Paste logs", "Upload .txt/.log/.csv"],
        index=0,
    )

    st.divider()

    st.caption(
        "Privacy: logs are sent to the configured model provider for analysis. "
        "Do not upload secrets, passwords, private keys, tokens, or unnecessary PII."
    )

# -----------------------------
# Input
# -----------------------------

logs = ""

if input_mode == "Paste logs":
    use_demo = st.checkbox("Load safe demo incident", value=True)
    default_value = DEFAULT_LOG if use_demo else ""
    logs = st.text_area(
        "Security logs / events",
        value=default_value,
        height=300,
        placeholder="Paste SIEM, EDR, firewall, authentication, or endpoint events here...",
    )
else:
    uploaded = st.file_uploader(
        "Upload log file",
        type=["txt", "log", "csv"],
        accept_multiple_files=False,
    )
    if uploaded:
        raw = uploaded.read()
        logs = raw.decode("utf-8", errors="replace")
        st.success(f"Loaded {uploaded.name} ({len(raw):,} bytes).")

if logs:
    stats = basic_log_stats(logs)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Log lines", stats["line_count"])
    with c2:
        st.metric("IP candidates", len(stats["ip_candidates"]))
    with c3:
        st.metric("Domain candidates", len(stats["domain_candidates"]))
    with c4:
        st.metric("Keyword signals", len(stats["keyword_hits"]))

st.divider()

# -----------------------------
# Analyze
# -----------------------------

analyze = st.button(
    "🔎 Investigate Incident",
    type="primary",
    use_container_width=True,
    disabled=not bool(logs.strip()),
)

if analyze:
    if len(logs) > 60000:
        st.warning(
            "The log input is large. Only the first 60,000 characters will be analyzed "
            "to keep the demo predictable."
        )
        logs_for_model = logs[:60000]
    else:
        logs_for_model = logs

    stats = basic_log_stats(logs_for_model)

    investigator_prompt = f"""
Analyze the following security telemetry.

Local preprocessing (do not treat this as authoritative threat intelligence):
{json.dumps(stats, indent=2)}

Available MITRE ATT&CK technique names:
{json.dumps(MITRE_TECHNIQUES, indent=2)}

Return the JSON schema specified in your system instructions.

SECURITY LOGS:
---BEGIN LOGS---
{logs_for_model}
---END LOGS---
"""

    with st.spinner("🧠 Investigator agent is reconstructing the incident..."):
        try:
            analysis = call_json(SYSTEM_PROMPT, investigator_prompt)
        except Exception as exc:
            st.error(f"Investigation failed: {exc}")
            st.stop()

    review_prompt = f"""
Review this investigation against the original logs.

ORIGINAL LOGS:
---BEGIN LOGS---
{logs_for_model}
---END LOGS---

INVESTIGATOR ASSESSMENT:
---BEGIN JSON---
{json.dumps(analysis, indent=2)}
---END JSON---
"""

    with st.spinner("🧪 Security reviewer is challenging the assessment..."):
        try:
            review = call_json(REVIEW_PROMPT, review_prompt)
        except Exception as exc:
            st.warning(f"Peer review failed: {exc}")
            review = {
                "review_verdict": "Unavailable",
                "confidence": "Low",
                "strengths": [],
                "concerns": [str(exc)],
                "alternative_hypotheses": [],
                "evidence_gaps": [],
                "suggested_revisions": [],
            }

    st.session_state["analysis"] = analysis
    st.session_state["review"] = review
    st.session_state["source_logs"] = logs_for_model

# -----------------------------
# Results
# -----------------------------

analysis = st.session_state.get("analysis")
review = st.session_state.get("review")

if analysis:
    st.subheader("🚨 Incident Assessment")

    a, b, c = st.columns(3)
    with a:
        render_severity(safe_text(analysis.get("severity")))
    with b:
        st.metric(
            "Overall confidence",
            safe_text(analysis.get("overall_confidence")),
        )
    with c:
        st.metric(
            "MITRE mappings",
            len(analysis.get("mitre_attack", [])),
        )

    st.info(safe_text(analysis.get("executive_summary")))

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        [
            "🧩 Investigation",
            "🕒 Timeline",
            "🎯 MITRE ATT&CK",
            "🧪 Peer Review",
            "🛡️ Response",
            "📄 Report",
        ]
    )

    with tab1:
        st.markdown("### Observations")
        for item in analysis.get("observations", []):
            st.markdown(
                f"**{safe_text(item.get('finding'))}**  \n"
                f"Confidence: `{safe_text(item.get('confidence'))}`"
            )
            evidence = item.get("evidence", [])
            if evidence:
                for ev in evidence:
                    st.code(safe_text(ev), language="text")
            st.divider()

        st.markdown("### Attack / Event Story")
        st.write(safe_text(analysis.get("attack_story")))

        st.markdown("### Alternative Explanations")
        for x in analysis.get("alternative_explanations", []):
            st.markdown(f"- {safe_text(x)}")

        st.markdown("### Missing Evidence")
        for x in analysis.get("missing_evidence", []):
            st.markdown(f"- {safe_text(x)}")

    with tab2:
        timeline = analysis.get("timeline", [])
        if timeline:
            for item in timeline:
                with st.container(border=True):
                    st.markdown(
                        f"**{safe_text(item.get('time'))} — "
                        f"{safe_text(item.get('event'))}**"
                    )
                    st.caption(safe_text(item.get("significance")))
        else:
            st.info("No timeline events were returned.")

    with tab3:
        mappings = analysis.get("mitre_attack", [])
        if mappings:
            for item in mappings:
                technique_id = safe_text(item.get("technique_id"))
                technique_name = safe_text(item.get("technique_name"))
                with st.container(border=True):
                    st.markdown(
                        f"### `{technique_id}` — {technique_name}"
                    )
                    st.write(safe_text(item.get("reason")))
                    st.caption(
                        f"Confidence: {safe_text(item.get('confidence'))}"
                    )
        else:
            st.info("No MITRE ATT&CK mapping was sufficiently supported.")

    with tab4:
        st.markdown(
            f"### {safe_text(review.get('review_verdict'))} "
            f"({safe_text(review.get('confidence'))} confidence)"
        )

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Strengths")
            for x in review.get("strengths", []):
                st.markdown(f"- {safe_text(x)}")

            st.markdown("#### Concerns")
            for x in review.get("concerns", []):
                st.markdown(f"- {safe_text(x)}")

        with col2:
            st.markdown("#### Alternative Hypotheses")
            for x in review.get("alternative_hypotheses", []):
                st.markdown(f"- {safe_text(x)}")

            st.markdown("#### Evidence Gaps")
            for x in review.get("evidence_gaps", []):
                st.markdown(f"- {safe_text(x)}")

        st.markdown("#### Suggested Revisions")
        for x in review.get("suggested_revisions", []):
            st.markdown(f"- {safe_text(x)}")

    with tab5:
        st.markdown("### Recommended Defensive Actions")
        for item in analysis.get("recommended_actions", []):
            priority = safe_text(item.get("priority"))
            with st.container(border=True):
                st.markdown(
                    f"**{priority}: {safe_text(item.get('action'))}**"
                )
                st.write(safe_text(item.get("reason")))

        st.markdown("### IOC Candidates")
        iocs = analysis.get("ioc_candidates", [])
        if iocs:
            st.dataframe(
                [
                    {
                        "Type": safe_text(x.get("type")),
                        "Value": safe_text(x.get("value")),
                        "Why relevant": safe_text(x.get("why_relevant")),
                    }
                    for x in iocs
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No IOC candidates returned.")

    with tab6:
        report = generate_markdown_report(analysis, review)
        st.download_button(
            "⬇️ Download Markdown Report",
            data=report,
            file_name="cyber_incident_investigation.md",
            mime="text/markdown",
            use_container_width=True,
        )
        st.markdown(report)

st.divider()
st.caption(
    "Defensive-use demo. AI output is an analyst aid, not proof of compromise. "
    "Validate findings against authoritative telemetry before taking disruptive actions."
)
