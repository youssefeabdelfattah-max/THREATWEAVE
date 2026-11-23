# THREATWEAVE

**Attack Correlation & Incident Response Platform**
*Weaving endpoint telemetry into actionable attack intelligence.*

---

## Overview

**THREATWEAVE** is an Elastic-integrated cybersecurity platform designed to correlate endpoint telemetry into structured attack stories and multi-stage campaigns, evaluate risk, and support analyst-driven incident investigation and management workflows.

By retrieving Windows endpoint telemetry from Elasticsearch and applying deterministic event correlation, THREATWEAVE bridges the gap between raw endpoint events and structured attack intelligence.

The platform exposes investigation-focused and incident-management REST APIs to support security analysts during triage, attack reconstruction, and case tracking.

---

## Core Capabilities

- **Endpoint Event Correlation:** Links related Windows endpoint telemetry events using correlation logic and available evidence.
- **Attack Story Reconstruction:** Organizes correlated events into chronological attack stories.
- **Process Chain Analysis:** Provides process relationship visibility based on available endpoint telemetry.
- **Campaign Correlation:** Groups related attack stories into broader operational campaigns.
- **Risk and Severity Assessment:** Evaluates correlated activity to assign contextual risk and severity levels.
- **MITRE ATT&CK Context:** Provides tactic and technique context for observed behaviors.
- **IOC Exploration:** Extracts and exposes Indicators of Compromise (IOCs) associated with correlated activity.
- **Incident Management:** Supports incident lifecycle tracking, status updates, analyst notes, and story/analysis ingestion.
- **Analyst-Facing REST APIs:** Provides FastAPI-powered services for querying correlation outputs and managing incidents.

---

## Architecture

THREATWEAVE follows a pipeline that transforms endpoint telemetry into structured investigation data and incident-management workflows.

```mermaid
flowchart TD
    A["Windows Endpoint Telemetry"] --> B["Elasticsearch"]
    B --> C["FastAPI Data Collection Layer"]
    C --> D["ECS Normalization"]
    D --> E["Event Analysis & Correlation Engine"]
    E --> F["Attack Stories & Campaign Graph"]
    F --> G["Risk Assessment & MITRE ATT&CK Mapping"]
    G --> H["Analyst Interface"]
    H --> I["Incident Investigation & Management"]
```
```

### Workflow Stages
1. Telemetry Retrieval: Windows endpoint telemetry stored in Elasticsearch is queried through the Elastic REST Client (collector/elastic_client.py).
2. Event Analysis and Correlation: Available events are analyzed and linked by the correlation engine into structured attack stories.
3. Campaign Correlation: Related stories are grouped into broader campaign-level representations.
4. Risk Assessment: Correlated activity receives risk and severity context alongside MITRE ATT&CK information.
5. Analyst Investigation: Generated intelligence is exposed through the analyst view and Analyst API.
6. Incident Management: Stories and analysis results can be ingested into the incident-management layer for investigation and lifecycle tracking.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| API Framework | FastAPI |
| ASGI Server | Uvicorn |
| Data Validation | Pydantic |
| Telemetry Search and Storage | Elasticsearch |
| Elasticsearch Integration | Elasticsearch Python Client |
| Data Source | Windows Endpoint Telemetry |
| Evaluation | JSON-based evaluation pipeline |


## Project Structure

```text
THREATWEAVE/
├── analyst_api.py
├── analyst_view.html
├── collector/
│   └── elastic_client.py
├── documentation/
│   ├── evaluation/
│   └── system_state/
├── evaluation/
│   ├── attack_analysis.md
│   ├── evaluation_dataset.json
│   ├── ground_truth.json
│   ├── engine_output.json
│   ├── evaluation_report.json
│   ├── evaluate_engine.py
│   ├── run_engine_evaluation.py
│   └── render_screenshot_reports.py
├── incident_api.py
├── incident_manager_v4.py
├── requirements.txt
└── README.md

```

## Getting Started
### Prerequisites
- Python 3.x
- Access to an Elasticsearch instance containing Windows endpoint telemetry for full telemetry collection and engine evaluation workflows.
- The Incident API can run independently in demo mode using an in-memory incident store.
### Installation

Clone the repository:

```bash
git clone https://github.com/youssefeabdelfattah-max/THREATWEAVE.git
cd THREATWEAVE
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Running the Services

THREATWEAVE consists of two FastAPI services that can run independently in separate terminals.

#### 1. Analyst API

The Analyst API reads pre-generated presentation data from the `analyst_view/` directory.

Start the service:

```bash
ANALYST_VIEW_DIR=analyst_view uvicorn analyst_api:app --reload
```

- **Default Port:** `8000`
- **Data Source:** `analyst_view/`
- **Requirement:** The directory must contain the analyst-view data generated by the engine's `export_analyst_view()` function.

#### 2. Incident API

The Incident API supports an in-memory demonstration workflow through `DEMO_MODE`.

Start the service:

```bash
DEMO_MODE=true uvicorn incident_api:app --reload --port 8001
```

- **Default Port:** `8001`
- **Demo Storage:** In-memory incident store.
- **Elasticsearch:** Not required for this demo workflow.

#### API Documentation

After starting each service, access its interactive Swagger UI documentation:

- **Analyst API:** http://127.0.0.1:8000/docs
- **Incident API:** http://127.0.0.1:8001/docs

**Note:** Run each API in a separate terminal. The Analyst API requires its generated data directory, while the Incident API can run independently in demo mode.

## API Overview

THREATWEAVE exposes two FastAPI services with separate responsibilities.

### 1. Analyst API (`analyst_api.py`)

Provides investigation-oriented endpoints for retrieving and exploring correlated security data:

- Campaign listing and campaign details.
- Attack story retrieval.
- Related event inspection.
- Process-chain information derived from available telemetry.
- Indicators of Compromise (IOCs).
- Platform statistics.
- Service health monitoring.

### 2. Incident API (`incident_api.py`)

Provides incident-management functionality to support analyst workflows and case tracking:

- Incident listing and details.
- Incident summaries.
- Incident status updates.
- Analyst notes.
- Story ingestion.
- Analysis-result ingestion.
- Demo incident seeding.
- Service health monitoring.

**Operational Scope:** The incident-management layer supports analyst-driven investigation and case tracking. It does not autonomously execute containment or remediation actions.

## Evaluation & Benchmarks
### Independent Attack Analysis

An independent analysis of the LokiBot-related Sysmon dataset used in THREATWEAVE's evaluation. It documents the observed attack activity, execution timeline, network indicators, benign background activity, potential false-positive scenarios, and investigation limitations.

This analysis establishes the contextual understanding of the dataset and its ground truth, independently of the correlation engine's output.

See the full [Independent Attack Analysis](evaluation/attack_analysis.md).

### Dataset Composition
The correlation engine is currently evaluated against a structured benchmark dataset:
- Total Endpoint Events: 472
- Attack-Labelled Events: 56
- Scenario Scope: 1 attack scenario
Dataset files:
- evaluation/evaluation_dataset.json
- evaluation/ground_truth.json
### Evaluation Execution
Run the evaluation scoring script:
python evaluation/evaluate_engine.py


Render the evaluation results:
python evaluation/render_screenshot_reports.py


The engine evaluation workflow is separate from offline scoring and may require a configured Elasticsearch connection and the appropriate runtime environment.
### Benchmark Results
| Metric | Result |
|---|---:|
| Relationship Precision | 78.83% |
| Relationship Recall | 66.73% |
| Overall Relationship F1 | 72.28% |
| Core Attack Pair F1 | 54.82% |
| Campaign Purity | 100.00% |
| Campaign Cleanliness | 41.18% |
| Composite Evaluation Score | 59.68% |

### Interpretation & Evaluation Caveats
- Campaign Purity: A score of 100% does not mean the campaign is free of benign events. It indicates that the evaluated attack events captured in the largest relevant campaign belong to the same ground-truth attack campaign.
- Campaign Cleanliness: The score of 41.18% reflects campaign-level separation quality and the presence of benign events grouped alongside malicious activity.
- Composite Score: The score of 59.68% is a weighted aggregate of evaluable components. It does not represent overall classification accuracy.
- Limited Generalization: Current metrics are derived from one attack scenario across 472 events. They should not be extrapolated to claim generalization across diverse attack techniques, threat actors, or enterprise environments.

## Scope & Limitations

- **Not a SIEM or EDR Replacement:** THREATWEAVE operates as a correlation and incident-management layer on top of existing telemetry infrastructure. It does not replace endpoint protection or centralized log-management solutions.
- **No Autonomous Remediation:** The platform supports analyst-driven incident management and does not automatically isolate hosts, terminate processes, or execute containment actions.
- **Deterministic Correlation:** The current implementation relies on rule-based and heuristic correlation logic rather than machine-learning-based anomaly detection.
- **Telemetry Dependency:** Correlation quality depends on the completeness, consistency, and quality of the available endpoint telemetry.
- **False Positives and Missed Relationships:** Generated attack stories and campaigns may contain benign events or fail to capture genuine attack relationships, as demonstrated by the evaluation results.
- **Limited Validation Scope:** Current quantitative evaluation is based on a single attack scenario and does not establish generalization across different threat actors, attack techniques, or enterprise environments.
- **Process Relationship Limitations:** Process relationships are inferred from available telemetry and correlation evidence. They should not be interpreted as guaranteed reconstruction of every process execution relationship.

## Roadmap & Future Improvements

- **Dataset Expansion:** Incorporate additional attack scenarios, threat behaviors, and larger multi-source telemetry datasets to improve evaluation coverage.
- **Correlation Optimization:** Refine correlation rules and heuristics to improve relationship precision and recall while reducing false-positive correlations.
- **Campaign Separation:** Improve campaign clustering and reduce the inclusion of unrelated benign activity in attack campaigns.
- **Telemetry Coverage:** Expand support for additional endpoint event types and telemetry sources to improve investigation context.
- **Investigation Workflows:** Enhance analyst triage, campaign investigation, and incident-management capabilities.
- **Automated Testing:** Introduce comprehensive integration and regression tests to improve reliability and maintainability.

These items represent potential future development directions and are not claims of currently implemented functionality.
