# PROJECT INTERIM REPORT (MILESTONE 1 — 35% COMPLETION)

## PROJECT TITLE:
**Hospital SOC Protecting Medical Devices and Clinical Applications: False-Positive Reduction Assistant**

---

## 1. INTRODUCTION
In modern digital healthcare, hospitals rely extensively on interconnected medical equipment and clinical applications. Devices such as infusion pumps, mechanical ventilators, patient vital monitors, MRI systems, and central Picture Archiving and Communication Systems (PACS) are connected to local hospital networks to deliver real-time clinical care. To protect these mission-critical systems against ransomware, unauthorized tampering, and data theft, hospitals deploy a dedicated Security Operations Center (SOC).

A major operational bottleneck faced by hospital SOC teams is alert fatigue. Network intrusion detection systems and security monitors generate thousands of alerts every day. Over 70% of these alerts turn out to be repetitive, benign false positives caused by authorized routine vulnerability scans, device maintenance reboots, and high-volume clinical messaging. SOC analysts spend countless hours manually triaging these harmless alerts, which severely increases the risk that an actual, life-threatening cyberattack will be missed.

This report documents the completed **first milestone (35% completion)** of an intelligent, defensive **False-Positive Reduction Assistant**. The system uses machine learning, novelty detection, clinical safety rules, and human-in-the-loop validation to safely filter out repetitive false alarms while strictly ensuring that true attacks targeting critical medical devices are never missed.

---

## 2. PROBLEM STATEMENT
Hospital SOC analysts are overwhelmed by high volumes of repetitive false-positive security alerts. Manually investigating every harmless alert causes severe cognitive fatigue and operational delays. However, applying standard automatic alert-closing tools is dangerous in a healthcare setting: if an automated tool mistakenly suppresses an alert that is actually a cyberattack on a ventilator or infusion pump, patient safety and life can be directly compromised.

Therefore, the problem is to develop an assistant that:
1. Effectively learns from historical analyst decisions to suppress repetitive false positives.
2. Unconditionally detects and preserves novel, unusual, or unseen threats.
3. Implements strict safety guardrails so that alerts involving life-critical medical equipment cannot be automatically dismissed without human confirmation.
4. Explains its recommendations with clear evidence in simple terms.
5. Operates on realistic clinical telemetry while ensuring patient safety through synthetic data.

---

## 3. PROBLEM ANALYSIS
An analysis of healthcare cybersecurity operations highlights three critical factors:
* **The High Cost of Missed Threats (False Negatives):** In regular corporate IT, missing a security alert might result in temporary downtime. In a hospital, a missed incident involving patient monitors or anesthesia machines can lead to clinical disruption and patient harm. Therefore, model accuracy alone is misleading; the priority must be achieving maximum Threat Recall and zero missed threats.
* **Complex Clinical Network Behavior:** Medical Internet of Things (IoMT) devices communicate using specialized clinical protocols (e.g., DICOM for imaging, HL7 for lab records). These protocols often generate high-volume data bursts that conventional intrusion detectors misclassify as malicious floods.
* **Network Imperfections in Hospitals:** Clinical networks often experience packet jitter, transmission delays from roaming bedside equipment, and duplicate sensor events. A practical SOC assistant must maintain data integrity when events arrive late, duplicated, or out of order.

---

## 4. OBJECTIVES
The primary objectives for this 35% milestone prototype are:
1. Develop a realistic synthetic dataset of over 5,000 hospital security alerts incorporating authentic medical device profiles, clinical network segments, and analyst decisions.
2. Build a stream integrity layer that handles duplicate alert storms, delayed events, and out-of-order event arrivals.
3. Implement a traditional rule-based SOC baseline representing conventional hospital triage logic.
4. Train and evaluate supervised machine learning models, selecting the best model based on threat detection recall rather than simple accuracy.
5. Implement an Isolation Forest novelty detection layer to detect unseen threat patterns and protect novel attacks from being suppressed.
6. Enforce a clinical safety guardrail ensuring that critical medical devices exhibiting unusual behavior are always routed for human review.
7. Build an explainability engine that provides understandable evidence bullets for every triage decision.
8. Provide human-in-the-loop interactive controls with disposition and override logging.
9. Measure performance using actual computed metrics, calculating analyst hours saved and proving that the missed incident rate remains at zero.
10. Deliver a fully functioning, interactive Streamlit web dashboard and verify the prototype through automated test cases.

---

## 5. EXISTING SYSTEM
In most hospital security environments today, alert triage relies on:
1. **Static Correlation Rules:** Fixed rule engines built into SIEM (Security Information and Event Management) platforms that trigger alerts whenever a simple threshold is crossed (e.g., "more than 10 failed logins" or "any communication on a sensitive medical VLAN").
2. **Manual Tier-1 Analyst Queue:** Human analysts inspect alerts one by one in chronological order, manually looking up IP addresses, device names, and asset inventory spreadsheets.
3. **Crude Whitelists:** Static suppression lists that automatically mute certain IP addresses or rule IDs.

### Limitations of the Existing System:
* **High Alert Fatigue:** Up to 75% of alerts in the queue are harmless, repetitive noise, overwhelming analysts.
* **Vulnerability of Static Whitelists:** Attackers often hijack authorized scanner IP addresses or compromise whitelisted admin credentials to hide their activity.
* **Lack of Contextual Awareness:** Conventional SIEM rules treat a general nurse station workstation the same as an ICU mechanical ventilator, failing to prioritize clinical criticality.
* **No Learning Capability:** Even if an analyst marks an identical routine device diagnostic message as benign every morning for a month, the system does not learn or adapt.

---

## 6. PROPOSED SYSTEM
The proposed **False-Positive Reduction Assistant** introduces a multi-layered, human-centric architecture specifically designed for healthcare environments:
1. **Event Stream Integrity:** Automatically filters duplicate alert floods, measures arrival delays, and reconstructs scrambled event streams into correct chronological order.
2. **Clinical Context Enrichment:** Enriches each alert with clinical information such as device criticality (Critical, High, Medium, Low), hospital location, department, operating system, and maintenance window status.
3. **Supervised ML Classification:** Predicts the probability of an alert being an actionable threat based on historical analyst patterns.
4. **Novelty and Anomaly Protection:** Uses an unsupervised Isolation Forest model to evaluate whether an alert represents unfamiliar behavior, preventing novel attacks from being silenced.
5. **Clinical Safety Guardrails:** Implements a strict rule where alerts targeting life-critical devices (e.g., Ventilators, Infusion Pumps) with unusual behavior are never auto-suppressed.
6. **Explainable AI (XAI):** Gives analysts clear, plain-language reasons and evidence bullets behind every recommendation.
7. **Human-in-the-Loop Confirmation:** Keeps the human analyst in full command. Analysts can confirm recommendations or record overrides, which are saved to update and retrain the model periodically.

---

## 7. METHODOLOGY
The development methodology followed in this 35% milestone consists of:
1. **Synthetic Data Synthesis:** Designing realistic clinical scenarios and probabilistic alert distributions without connecting to real patient networks.
2. **Preprocessing Pipeline:** Performing missing value imputation, categorical encoding, and feature engineering under a strict zero-drop policy.
3. **Baseline Formulation:** Implementing the typical rules used by hospital SOCs to establish a quantitative performance benchmark.
4. **Comparative Machine Learning:** Training Logistic Regression, Decision Tree, and Random Forest models on stratified train/test splits.
5. **Safety and Novelty Integration:** Coupling the best classifier with an Isolation Forest anomaly detector and clinical safety logic.
6. **Empirical Benchmarking:** Running a controlled experiment comparing baseline and proposed systems on the same dataset, evaluating analyst hours saved and missed incident rates.
7. **Verification Testing:** Writing automated unit and adversarial test cases in Pytest to validate edge cases.
8. **Dashboard Development:** Creating a multi-page interactive web application in Streamlit for live demonstration.

---

## 8. SYSTEM WORKFLOW
The step-by-step workflow of an incoming alert through the completed prototype is as follows:

```
Incoming Security Alert
         │
         ▼
[1. Event Integrity Check]
    ├── Duplicate Check (Collapse repeated alert floods)
    ├── Latency Tracking (Calculate transmission delay)
    └── Resequencing (Sort out-of-order events by true timestamp)
         │
         ▼
[2. Data Preprocessing & Context Enrichment]
    ├── Impute missing values (Categorical -> "Unknown", Numerical -> Median)
    └── Extract temporal & clinical features (Hour, Weekend, Criticality)
         │
         ▼
[3. Multi-Model Inference]
    ├── Supervised Classifier -> Computes Threat Probability P(Threat)
    └── Isolation Forest -> Computes Anomaly Score & Novelty Flag
         │
         ▼
[4. Clinical Safety Guardrail Evaluation]
    ├── IF P(Threat) >= 0.50 -> INVESTIGATE or ESCALATE
    ├── IF Anomaly Score > 0.65 (Novel Threat) -> INVESTIGATE (Preserve)
    ├── IF Critical Medical Device + Unusual Activity -> REVIEW (Never Suppress)
    └── IF P(Threat) < 0.40 AND Normal Behavior -> LIKELY_FALSE_POSITIVE
         │
         ▼
[5. Explainability Synthesis]
    └── Generate plain-English evidence bullets explaining the recommendation
         │
         ▼
[6. Human Analyst Review via Streamlit Dashboard]
    └── Analyst chooses: Confirm FP | Confirm TP | Investigate | Escalate
         │
         ▼
[7. Feedback Capture & Periodic Retraining]
    └── Decision logged to audit CSV; model periodically retrains on overrides
```

---

## 9. DATASET USED
To ensure full patient safety and ethical compliance, all data used in the project is **100% synthetic**. The dataset was produced using our clinical data generator (`src/data_generator.py`) and models real hospital conditions.

### Dataset Profile:
* **Total Alert Records:** 5,330 alerts
* **Number of Attributes:** 43 fields per record
* **Class Distribution:**
  * False Positive / Benign alerts: 3,758 records (70.5%)
  * Confirmed True Positive threats: 1,047 records (19.6%)
  * Alerts Requiring Investigation: 525 records (9.8%)
  * Total Verified Threats: 1,231 records (23.1%)
* **Clinical Medical Assets Represented:**
  * Critical: Infusion Pumps (Baxter Sigma Spectrum), Mechanical Ventilators (Dräger Evita Infinity), Patient Monitors (Philips IntelliVue MX800)
  * High Priority: CT Scanners (GE Healthcare Optima), MRI Scanners (Siemens Magnetom Vida), PACS Servers (Agfa Enterprise Imaging)
  * Medium/Low Priority: Laboratory Analyzers (Roche Cobas), Nurse Station Workstations
* **Realistic Imperfections Included:**
  * 2.5% duplicate records (simulating network sensor loops)
  * 7.0% delayed arrivals (5 to 45 minutes delay)
  * Out-of-order event sequence chunks
  * 618 missing values across optional fields (e.g., missing patch status or antivirus info)

---

## 10. TECHNOLOGIES USED
The prototype was built using standard, reliable, and locally runnable open-source technologies:
* **Programming Language:** Python 3.10
* **Data Processing:** Pandas (version 2.3) and NumPy (version 1.26)
* **Machine Learning & Anomaly Detection:** Scikit-learn (version 1.7)
  * Logistic Regression (Class-Weighted Balanced)
  * Decision Tree Classifier
  * Random Forest Classifier
  * Isolation Forest (Novelty Detection)
* **Model Persistence:** Joblib (version 1.5)
* **User Interface:** Streamlit (version 1.55)
* **Visualizations:** Matplotlib (version 3.8) and Seaborn (version 0.12)
* **Testing Framework:** Pytest (version 9.1)
* **Data Storage:** Structured CSV files and JSON audit logs

---

## 11. 35% IMPLEMENTATION COMPLETED
The first project milestone (35% completion) is fully implemented, verified, and operational. The completed deliverables include:

1. **Synthetic Data Engine (`src/data_generator.py`):** Produces 5,330 realistic clinical security alerts.
2. **Preprocessing & Feature Engineering (`src/preprocessing.py`):** Imputes missing values without dropping events, extracts time features, and saves a JSON audit log.
3. **Event Integrity Processor (`src/event_processor.py`):** Filters alert storms, computes network latency, and re-sequences disordered streams.
4. **Baseline Rule Model (`src/baseline.py`):** Implements traditional four-rule hospital SOC triage logic.
5. **Machine Learning Model Engine (`src/train_model.py`):** Trains, compares, and serializes the triage classifier.
6. **Novelty & Safety Module (`src/anomaly_detection.py`):** Fits Isolation Forest and enforces clinical medical device guardrails.
7. **Explainability Engine (`src/explainability.py`):** Formulates understandable evidence bullets for triage decisions.
8. **Feedback Learning Module (`src/feedback_learning.py`):** Stores human analyst feedback and enables periodic retraining.
9. **Experimental Evaluation Module (`src/evaluation.py`):** Executes comparative benchmarking, computes analyst hours saved, and generates 8 publication charts.
10. **Automated Testing Suite (`tests/`):** 8 test cases validating both normal operations and adversarial bypass attacks.
11. **Interactive Streamlit Web App (`app.py`):** 5-tab application featuring an Executive Dashboard, Alert Investigation Workbench, Event Integrity Monitor, Model Evaluation, and Feedback Tracking.

---

## 12. FALSE POSITIVE DETECTION
The assistant identifies false positives using a machine learning model trained on historical alert features, asset criticality, and past device false-positive rates.

During model selection, three candidate algorithms were trained on 4,264 records and evaluated on 1,066 unseen test alerts (containing 246 confirmed incidents):
* **Logistic Regression (Class-Weighted Balanced):**
  * Threat Recall: **1.0000 (100.0%)**
  * Missed Incidents: **0**
  * Threat Precision: **80.13%**
  * F1 Score: **0.8897**
  * Overall Accuracy: **94.28%**
* **Decision Tree:**
  * Threat Recall: 0.9512
  * Missed Incidents: 12
  * Threat Precision: 82.11%
  * F1 Score: 0.8814
* **Random Forest:**
  * Threat Recall: 0.9837
  * Missed Incidents: 4
  * Threat Precision: 81.48%
  * F1 Score: 0.8913

**Model Selection Decision:** Logistic Regression was selected as the core classifier. In a hospital setting, avoiding missed threats is paramount. Logistic Regression achieved a **perfect 100% recall with zero missed threats**, outperforming Decision Trees and Random Forests which missed 12 and 4 true incidents, respectively.

---

## 13. NOVEL THREAT PROTECTION
A major limitation of standard machine learning classifiers is that they cannot recognize attacks they have never seen before. If an attacker uses a novel technique, a standard model might misclassify it as a false positive.

To prevent this, the project incorporates an **Isolation Forest** model:
* The Isolation Forest is trained on benign operational telemetry to learn normal device communications.
* It computes an **Anomaly Score** between 0.00 and 1.00.
* **Safety Condition:** If an alert produces an anomaly score above **0.65** or triggers a novelty flag, the assistant immediately overrides any false-positive classification and labels the alert **INVESTIGATE**.
* **Clinical Guardrail:** If an alert targets a **Critical Medical Device** (such as a Ventilator or Infusion Pump) and involves an unusual destination IP or unusual off-hours timing, automatic suppression is completely blocked, forcing human analyst review.

---

## 14. ANALYST RECOMMENDATION AND HUMAN CONFIRMATION
The assistant never closes high-impact alerts autonomously. Instead, it serves as a decision assistant.

### Evidence Generation:
For every alert, the system generates evidence bullets such as:
* *"Critical medical asset involved: Ventilator (Dräger Evita Infinity V500)"*
* *"Source IP 10.0.10.50 matches authorized internal vulnerability scanner"*
* *"Historical device profile: 45 previous alerts recorded; 42 (95%) marked False Positive"*
* *"Event occurred during approved maintenance window"*
* *"No indicators of lateral movement, payload delivery, or credential abuse detected"*

### Human-in-the-Loop Controls:
Within the Streamlit dashboard, analysts can review the evidence and click:
* `[Confirm False Positive]`
* `[Confirm True Threat]`
* `[Mark for Investigation]`
* `[Escalate]`

If the analyst disagrees with the assistant's recommendation, the system prompts for an **Override Reason** (e.g., "New threat pattern", "Medical device involved", "Insufficient evidence", "Model incorrect"). This feedback is appended to an audit CSV file, which feeds the periodic retraining pipeline.

---

## 15. TESTING AND TEST CASES
To ensure reliability, the project includes an automated testing suite built with Pytest. All **8 test cases passed successfully**:

| Test ID | Test Name | Category | Scenario Tested | Outcome |
| :--- | :--- | :--- | :--- | :---: |
| **TEST-01** | Normal False Positive | Normal Operation | Known scanner running scheduled traffic during maintenance | **PASSED** (`LIKELY_FALSE_POSITIVE`) |
| **TEST-02** | Real Suspicious Alert | Threat Detection | 35 failed SSH logins from external IP against PACS server | **PASSED** (`INVESTIGATE / ESCALATE`) |
| **TEST-03** | Novel Medical Threat | Novelty Defense | Infusion Pump communicating with unseen external IP on port 9001 | **PASSED** (Safety layer forces `INVESTIGATE`) |
| **TEST-04** | Duplicate Alert Flood | Event Integrity | Same event sent 10 times consecutively | **PASSED** (1 logical event emitted; 9 filtered) |
| **TEST-05** | Batch Deduplication | Event Integrity | Multi-alert batch deduplication integrity | **PASSED** (Unique events preserved) |
| **TEST-06** | Delayed Critical Event | Event Integrity | Ventilator beacon generated at 10:01 but received at 10:10 | **PASSED** (Processed with 540s latency tag) |
| **TEST-07** | Out-of-Order Delivery | Event Integrity | Events arriving in scrambled sequence (10:05, 10:01, 10:04, 10:02, 10:03) | **PASSED** (Chronological order restored) |
| **TEST-08** | Model Deception Attack | Adversarial Safety | Attacker mimics low-severity scanner traffic on a critical Ventilator | **PASSED** (Safety guardrail blocks suppression) |

---

## 16. RESULTS AND EVALUATION
A controlled experiment was conducted comparing the **Traditional Rule-Based Baseline** against the **Proposed ML + Guardrail Assistant** on the entire 5,330-alert dataset.

### Comparative Evaluation Results Table:

| Evaluation Metric | Baseline (Rule-Based SOC) | Proposed Assistant (ML + Guardrails) | Improvement / Clinical Impact |
| :--- | :---: | :---: | :---: |
| **Total Ingested Alerts** | 5,330 | 5,330 | Identical Dataset |
| **Alerts Requiring Analyst Review** | 3,565 | **1,996** | **1,569 fewer alerts to review (-44.01%)** |
| **Alerts Safely Suppressed** | 1,765 | **3,334** | **1,569 additional FPs suppressed (+88.89%)** |
| **Detected Incidents** | 1,231 | **1,231** | **100% Threat Capture** |
| **Missed Incidents** | 0 | **0** | **Zero Missed Threats (SAFE)** |
| **Missed Incident Rate** | **0.00%** | **0.00%** | **Maintained at Zero** |
| **Triage Precision** | 34.53% | **61.67%** | **+27.14% Higher Signal-to-Noise Ratio** |
| **Threat Recall** | 100.00% | **100.00%** | **100% Threat Capture Preserved** |
| **F1 Score** | 0.5133 | **0.7629** | **+0.2496 Improvement** |
| **Overall Accuracy** | 56.21% | **85.65%** | **+29.44% Accuracy Gain** |
| **Analyst Hours Required** | 475.33 hrs | **266.13 hrs** | **209.20 Hours Saved** |

### Analyst Hours Saved Calculation:
Based on the cybersecurity industry standard of **8 minutes of manual investigation per alert**:
* $\text{Baseline Hours} = \frac{3,565 \times 8}{60} = 475.33\text{ hours}$
* $\text{Proposed Hours} = \frac{1,996 \times 8}{60} = 266.13\text{ hours}$
* $\text{Hours Saved} = 475.33 - 266.13 = \mathbf{209.20\text{ hours}}$
* $\text{Percentage Workload Saved} = \frac{209.20}{475.33} \times 100\% = \mathbf{44.01\%}$

Across the 5,330 alerts, the assistant safely saves **over 26 full eight-hour analyst shifts** while ensuring that not a single confirmed threat is missed.

---

## 17. ADVANTAGES
1. **Significant Workload Relief:** Reduces repetitive alert investigations by 44.01%, alleviating analyst fatigue.
2. **Zero-Compromise Clinical Safety:** Maintains a 0.00% missed incident rate, ensuring patient-critical equipment is never endangered by automated mistakes.
3. **Defense Against Novel Attacks:** The Isolation Forest detects unusual patterns that standard machine learning models would overlook.
4. **Transparent Explainability:** Analysts receive plain-language evidence bullets explaining why an alert is safe or suspicious.
5. **Stream Fault Tolerance:** Resilient against duplicate alert storms, delayed device transmissions, and out-of-order logs.
6. **Continuous Learning:** Captures human decisions and periodically retrains without destabilizing baseline knowledge.

---

## 18. LIMITATIONS (CURRENT 35% PHASE)
1. **Synthetic Telemetry:** The current prototype has been validated exclusively on synthetic data. Real hospital devices exhibit vendor-specific firmware bugs and legacy protocol quirks that require live validation.
2. **Static Asset Catalog:** The medical asset inventory is currently managed via a local data pool rather than an active hospital Configuration Management Database (CMDB).
3. **Local Architecture:** The prototype runs locally on Streamlit and CSV files rather than as a distributed cloud microservice.
4. **Passive Triage Only:** The assistant currently recommends dispositions and does not actively isolate network switch ports or execute firewall blocks.

---

## 19. FUTURE WORK (REMAINING 65%)
The remaining 65% of the project will be completed in subsequent milestones:
* **Milestone 2 (50% Completion) — Deep Clinical Protocol Parsing:**
  * Implement deep-packet inspection (PCAP) decoders for medical protocols including DICOM (imaging) and HL7 v2/v3 (clinical observations).
* **Milestone 3 (70% Completion) — Live SIEM and EDR Connectors:**
  * Build bidirectional REST API connectors to open-source SIEM platforms (Wazuh, Elastic Security) to ingest live network feeds.
* **Milestone 4 (85% Completion) — Dynamic Asset Discovery & Multi-Agent Architecture:**
  * Integrate dynamic medical device discovery (DHCP fingerprinting, passive mDNS sniffing) and deploy specialized sub-models for distinct hospital wings (Radiology, ICU, Outpatient).
* **Milestone 5 (100% Completion) — Automated Clinical Containment & Multi-Hospital Federated Learning:**
  * Implement safe network quarantine playbooks that isolate infected clinical workstations without disrupting active patient therapy on life-support machines.
  * Enable privacy-preserving federated learning across multiple hospital sites.

---

## 20. CONCLUSION
This interim project report demonstrates the successful completion of the **35% milestone** for the **Hospital SOC False-Positive Reduction Assistant**. 

The prototype delivers a functional, locally executable system that effectively solves the primary problem: **safely reducing repetitive false-positive alerts while preserving novel and critical threats in a hospital setting**. By combining balanced machine learning, unsupervised novelty detection, deterministic clinical guardrails, and explainable AI, the system achieved a **44.01% workload reduction (saving 209.20 analyst hours)** with a **0.00% missed incident rate** across 5,330 alerts. All 8 automated test cases passed, and an interactive Streamlit application is operational. This establishes a strong foundation for the remaining 65% of the project.
