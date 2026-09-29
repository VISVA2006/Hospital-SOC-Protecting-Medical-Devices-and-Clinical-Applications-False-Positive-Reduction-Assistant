# Advanced Adversarial Testing Suite (ADV-01 through ADV-12)

## 1. Threat Model & Adversarial Evasion

Medical device networks present unique adversarial vectors:
- Attackers craft network telemetry to mimic benign medical scanner or vendor maintenance behavior.
- Threat actors lower alert severity or throttle connection rates to evade SIEM thresholds.
- Malware on medical endpoints uses legitimate clinical protocols (e.g. DICOM, HL7) or internal nurse workstation IPs as proxies.

---

## 2. Test Case Catalog & Defense Mechanics

The 12 specialized adversarial test cases in `experiments/adversarial_tests.py` evaluate the multi-layered defense architecture:

| ID | Scenario Name | Target Asset | Adversarial Technique | Defense Layer Intercepting | Result |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **ADV-01** | Low-Severity Ventilator Deception | ICU Ventilator | Tags C2 beacon as `LOW` severity on port 4444 | Guardrail Invariant 1 (Critical Asset Defense) | **PASSED** |
| **ADV-02** | High-Rate Scanner Masquerade | Infusion Pump | Spoofs scanner IP `10.0.10.50` with high connection velocity | Sequence Detector + Anomaly Isolation Forest | **PASSED** |
| **ADV-03** | Low-and-Slow Multi-Hour Recon | Nurse Station | Spreads port sweep over 4 hours at low rate | Temporal Sequence Accumulator | **PASSED** |
| **ADV-04** | Novel Attack on Patient Monitor | Patient Monitor | Unseen zero-day protocol telemetry | Isolation Forest Novelty Detector | **PASSED** |
| **ADV-05** | Distributed Multi-Source Attack | Clinical Server | 5 distinct source IPs targeting same server port | Multi-Alert Sliding Window Accumulator | **PASSED** |
| **ADV-06** | Maintenance Window Disguise | Infusion Pump | Active credential brute force disguised during maintenance | Guardrail Invariant 1 (Brute force override) | **PASSED** |
| **ADV-07** | Boundary Threat Prob Manipulation | PACS Server | Attacker crafts packet sizes to hover threat prob at 0.38 | Guardrail Invariant 5 (Borderline Review Gate) | **PASSED** |
| **ADV-08** | Rapid Deduplication Storm Flood | Telemetry Hub | Injects 20 identical alerts within 1 second to overwhelm queue | EventProcessor Stream Deduplication | **PASSED** |
| **ADV-09** | Extreme Out-of-Order Delay Injection | Smart Bed Hub | Injects events delayed by 25 minutes | EventProcessor Chronological Sorting | **PASSED** |
| **ADV-10** | Clinical Criticality Downgrade Attempt| Anesthesia Unit | Injects header spoofing device criticality as `LOW` | Critical Device Name Dictionary Match | **PASSED** |
| **ADV-11** | High Failure Rate Evasion Throttling | Nurse Station | Throttles failed logins to 2 per hour to avoid threshold | ML Feature `high_failure_rate` + Sequence Risk | **PASSED** |
| **ADV-12** | Corrupted Payload & Malformed Telemetry| ICU Monitor | Sends malformed non-UTF8 payload causing parsing exception | Fail-Safe Fallback Handler (Fails Open) | **PASSED** |

---

## 3. Defense Verification

All 12 scenarios were evaluated programmatically in both the Pytest automated test suite (`tests/test_advanced_adversarial.py`) and the master experiment orchestrator (`run_all_experiments.py`), achieving a verified **100% defense pass rate**.
