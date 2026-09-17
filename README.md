🛡️ AI Cyber Incident Investigator

Evidence-first Generative AI for Security Operations, Incident Reconstruction & MITRE ATT&CK Mapping

AI Cyber Incident Investigator is a Streamlit-based cybersecurity analysis application that uses Generative AI to transform raw security telemetry into a structured, explainable incident investigation.

Instead of acting like a generic cybersecurity chatbot, the system follows an AI Investigator → AI Peer Reviewer workflow to reconstruct events, identify suspicious behavior, map supported activity to MITRE ATT&CK, highlight evidence gaps, and produce defensive response recommendations.

✨ Why This Project?

Security logs are often fragmented, noisy, and difficult to interpret quickly.

A SOC analyst may need to connect:

Authentication Events
        ↓
Process Execution
        ↓
Command-Line Activity
        ↓
Network Connections
        ↓
Privilege Changes
        ↓
Possible Attack Chain

This project uses GenAI to connect those fragmented signals while explicitly separating:

Evidence

Observations

Hypotheses

Confidence

Alternative explanations

Missing evidence

Recommended defensive actions

The goal is not to let AI blindly declare that an attack occurred. The goal is to make AI behave more like a cautious security investigation assistant.

🚀 Core Features

🔎 AI Incident Investigation

Paste security logs or upload .txt, .log, or .csv files and receive a structured investigation.

🕒 Incident Timeline Reconstruction

Fragmented events are converted into a chronological narrative:

09:31:02  Failed Authentication
09:31:08  Failed Authentication
09:31:17  Failed Authentication
09:31:29  Successful Authentication
09:32:04  PowerShell Execution
09:32:09  Encoded Command
09:33:44  Outbound Network Connection

🎯 MITRE ATT&CK Mapping

Potentially supported behaviors are mapped to relevant MITRE ATT&CK techniques with reasoning and confidence.

Example:

T1110       Brute Force
T1078       Valid Accounts
T1059.001   PowerShell

🧪 AI Security Peer Reviewer

A key feature is the Investigator → Reviewer workflow:

                 RAW LOGS
                    │
                    ▼
            ┌───────────────┐
            │ AI Investigator│
            └───────┬───────┘
                    │
                    ▼
             Investigation
                    │
                    ▼
            ┌───────────────┐
            │ AI Peer Review │
            └───────┬───────┘
                    │
                    ▼
          Evidence-Based Assessment

The reviewer challenges:

Unsupported conclusions

Hallucinated facts

Overconfident severity

Weak MITRE mappings

Contradictory evidence

Missing alternative explanations

Evidence gaps

🧠 Confidence-Aware Analysis

Findings are categorized as High, Medium, or Low confidence.

🔬 Evidence & IOC Extraction

Candidate IPs, domains, users, hosts, processes, commands, and other indicators are extracted from the investigation.

🛡️ Defensive Response Recommendations

The system suggests defensive investigation and response actions such as evidence preservation, account validation, endpoint investigation, and telemetry collection.

📄 Investigation Report

Download a complete Markdown report containing the investigation, timeline, MITRE mappings, evidence gaps, IOC candidates, response actions, and peer review.

🏗️ Architecture

The application is intentionally lightweight:

AI-Cyber-Incident-Investigator/
│
├── app.py
├── requirements.txt
└── README.md

Application Flow

                  ┌──────────────────┐
                  │   Security Logs  │
                  │  Paste / Upload  │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Local Preprocess │
                  │ IPs / Keywords   │
                  │ Basic Statistics │
                  └────────┬─────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │   GenAI Investigator │
                │ • Observations       │
                │ • Timeline           │
                │ • MITRE ATT&CK       │
                │ • Attack Story       │
                │ • IOC Candidates     │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │   GenAI Peer Review  │
                │ • Challenge Claims   │
                │ • Find Gaps          │
                │ • Alternative Ideas  │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │ Investigation Report │
                └──────────────────────┘

🧩 Technology Stack

Component

Technology

Frontend

Streamlit

Backend

Python

Generative AI

OpenAI API

LLM Interaction

OpenAI Python SDK

Threat Framework

MITRE ATT&CK

Report Format

Markdown

Deployment

Streamlit Community Cloud

The project intentionally avoids unnecessary infrastructure such as React, Node.js, Docker, databases, and vector databases.

⚙️ Installation

1. Clone the repository

git clone https://github.com/YOUR_USERNAME/AI-Cyber-Incident-Investigator.git
cd AI-Cyber-Incident-Investigator

2. Create a virtual environment

Windows

python -m venv venv
venv\Scripts\activate

Linux / macOS

python3 -m venv venv
source venv/bin/activate

3. Install dependencies

pip install -r requirements.txt

4. Configure the OpenAI API key

Create an OpenAI API key and configure it as an environment variable:

Windows PowerShell

$env:OPENAI_API_KEY="your_api_key_here"

Linux / macOS

export OPENAI_API_KEY="your_api_key_here"

For Streamlit, you can alternatively create:

.streamlit/
└── secrets.toml

with:

OPENAI_API_KEY = "your_api_key_here"

⚠️ Never commit API keys to GitHub.

▶️ Run Locally

streamlit run app.py

Then open the local Streamlit URL shown in the terminal.

☁️ Streamlit Deployment

Push these files to GitHub:

app.py
requirements.txt
README.md

Create a Streamlit Community Cloud application and select:

Main file: app.py

Then add the API key under Streamlit Secrets:

OPENAI_API_KEY = "your_api_key_here"

Deploy the application.

🧪 Demo

The application includes a safe demonstration dataset representing suspicious authentication and endpoint activity:

2026-09-17 09:31:02 host=WS-104 user=ali src=185.44.21.17 event=login_failed
2026-09-17 09:31:08 host=WS-104 user=ali src=185.44.21.17 event=login_failed
2026-09-17 09:31:17 host=WS-104 user=ali src=185.44.21.17 event=login_failed
2026-09-17 09:31:29 host=WS-104 user=ali src=185.44.21.17 event=login_success
2026-09-17 09:32:04 host=WS-104 user=ali process=powershell.exe event=process_start
2026-09-17 09:32:09 host=WS-104 user=ali process=powershell.exe command="powershell -enc ..."
2026-09-17 09:33:44 host=WS-104 user=ali dst=198.51.100.23 port=443 event=outbound_connection

This allows the project to be demonstrated without connecting to a production environment.

🔬 Example Investigation

A typical investigation can produce:

INCIDENT
Possible Credential Compromise / Suspicious Endpoint Activity

SEVERITY
High

CONFIDENCE
Medium

OBSERVATIONS
• Multiple failed authentication attempts
• Successful authentication from the same source
• PowerShell execution
• Encoded command-line activity
• Outbound network connection

MITRE ATT&CK
T1110       Brute Force
T1059.001   PowerShell
T1078       Valid Accounts

ALTERNATIVE EXPLANATIONS
• Authorized administrative activity
• Automated testing
• Security-tool generated telemetry

MISSING EVIDENCE
• Authentication source context
• MFA events
• Endpoint process tree
• Network/DNS telemetry

The exact output depends on the supplied telemetry and model response.

🧠 Design Philosophy

The project follows an:

Evidence → Hypothesis → Validation

approach.

Instead of:

Log → AI → "This is definitely an attack"

the intended workflow is:

Log
 ↓
Evidence
 ↓
Observation
 ↓
Hypothesis
 ↓
Confidence
 ↓
Alternative Explanation
 ↓
Evidence Gap
 ↓
Defensive Investigation

This is important because LLMs can produce plausible but unsupported conclusions.

The second reviewer provides an additional reasoning layer designed to expose those weaknesses.

🔐 Security & Privacy

This application is intended for defensive cybersecurity analysis.

Do not upload:

Passwords

API keys

Private keys

Authentication tokens

Session cookies

Secrets

Unnecessary personally identifiable information

Confidential production logs unless your organization permits external processing

Logs are sent to the configured model provider for analysis.

Before using organizational telemetry, review your organization's data-handling and privacy requirements.

⚠️ Limitations

This is an AI-assisted investigation tool, not a replacement for a SIEM, EDR, IDS, forensic platform, or human incident-response team.

Important limitations:

AI-generated findings can be incorrect.

MITRE ATT&CK mappings are suggestions based on available evidence.

IOC candidates are not automatically reputation-verified.

An IP appearing in logs does not by itself establish maliciousness.

Severity is an AI assessment and requires analyst validation.

Missing telemetry can significantly change conclusions.

The application does not perform autonomous containment or remediation.

Always validate important findings against authoritative telemetry before taking disruptive actions.

🛡️ Defensive Use Cases

SOC Operations

Quick first-pass analysis of alerts and logs.

Incident Response

Reconstructing a possible sequence of events.

Threat Hunting

Highlighting suspicious patterns that deserve investigation.

Security Education

Demonstrating how authentication, process, and network events can form an attack narrative.

DFIR Learning

Teaching evidence-based incident investigation.

Cybersecurity Research

Experimenting with GenAI-assisted security analysis and AI reviewer architectures.

🔮 Future Improvements

Potential future versions could include:

🔗 SIEM integrations

📡 Streaming log analysis

🌐 Threat-intelligence enrichment

🧬 Attack graph visualization

📊 Configurable risk rules

🗂️ Case management

🔍 Sigma rule generation

🧪 Automated detection-rule testing

🕸️ Entity relationship graphs

🤖 More specialized security agents

📚 RAG over internal security documentation

🧾 STIX/TAXII integration

🔐 Local/private LLM support

📈 Historical incident comparison

🧠 Analyst feedback loops

🎓 Academic / FYP Potential

The project can be extended into a research-oriented cybersecurity project.

Possible Research Question

How effectively can a Generative AI multi-agent architecture reconstruct cybersecurity incidents from fragmented security telemetry while reducing unsupported conclusions through AI-based peer review?

Possible Experimental Comparison

Rule-Based Analysis
        vs
Single LLM Investigator
        vs
LLM Investigator + Peer Reviewer

Possible evaluation dimensions:

Timeline reconstruction accuracy

Evidence extraction accuracy

MITRE ATT&CK mapping accuracy

False-positive rate

Unsupported-claim rate

Evidence-gap identification

Analyst usefulness

This creates a stronger research direction than a conventional cybersecurity chatbot.

📁 Project Structure

AI-Cyber-Incident-Investigator/
│
├── app.py                 # Complete Streamlit application
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation

🤝 Contributing

Contributions are welcome.

Possible contribution areas:

Additional log formats

Expanded MITRE ATT&CK coverage

Better timeline extraction

Security-focused evaluation datasets

Additional peer-review strategies

Threat-intelligence integrations

UI/UX improvements

📜 License

Add the license appropriate for your repository.

For example:

MIT License

👨‍💻 Author

Kumail abbas

Cybersecurity | Generative AI | Security Automation | Threat Analysis

⭐ Project Summary

AI Cyber Incident Investigator demonstrates how Generative AI can be used beyond conventional chatbots and summarizers.

It combines:

Cybersecurity Logs
      +
Generative AI
      +
Incident Reconstruction
      +
MITRE ATT&CK
      +
Evidence-Based Reasoning
      +
AI Peer Review
      +
Defensive Response

Investigate with AI. Challenge the conclusion. Validate with evidence.
