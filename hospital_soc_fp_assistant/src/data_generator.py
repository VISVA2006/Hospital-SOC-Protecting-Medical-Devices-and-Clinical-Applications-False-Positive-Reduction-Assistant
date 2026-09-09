"""
Synthetic Security Alert Data Generator for Hospital SOC.
Generates realistic alerts for medical devices, clinical endpoints,
and IT infrastructure with realistic clinical workflows and security telemetry.
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# Set random seed for reproducibility
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

DEVICE_CATALOG = [
    {
        "device_type": "Infusion Pump",
        "device_vendor": "Baxter",
        "device_model": "Sigma Spectrum",
        "firmware_version": "v3.2.1",
        "device_criticality": "CRITICAL",
        "network_segment": "Medical-Device-VLAN",
        "os": "VxWorks",
        "av_status": "Not Supported (Embedded)",
        "owner": "Biomedical Engineering"
    },
    {
        "device_type": "Ventilator",
        "device_vendor": "Dräger",
        "device_model": "Evita Infinity V500",
        "firmware_version": "v4.0.5",
        "device_criticality": "CRITICAL",
        "network_segment": "Medical-Device-VLAN",
        "os": "Custom RTOS",
        "av_status": "Not Supported (Embedded)",
        "owner": "Biomedical Engineering"
    },
    {
        "device_type": "Patient Monitor",
        "device_vendor": "Philips",
        "device_model": "IntelliVue MX800",
        "firmware_version": "v5.1.0",
        "device_criticality": "CRITICAL",
        "network_segment": "Medical-Device-VLAN",
        "os": "Embedded Linux",
        "av_status": "Not Supported (Embedded)",
        "owner": "Biomedical Engineering"
    },
    {
        "device_type": "CT Scanner",
        "device_vendor": "GE Healthcare",
        "device_model": "Optima CT660",
        "firmware_version": "v8.3.2",
        "device_criticality": "HIGH",
        "network_segment": "Imaging-PACS-VLAN",
        "os": "Windows 10 IoT Enterprise",
        "av_status": "Active",
        "owner": "Radiology IT"
    },
    {
        "device_type": "MRI Scanner",
        "device_vendor": "Siemens Healthineers",
        "device_model": "Magnetom Vida",
        "firmware_version": "v7.1.4",
        "device_criticality": "HIGH",
        "network_segment": "Imaging-PACS-VLAN",
        "os": "Windows 10 IoT Enterprise",
        "av_status": "Active",
        "owner": "Radiology IT"
    },
    {
        "device_type": "ECG Machine",
        "device_vendor": "GE Healthcare",
        "device_model": "MAC 5500 HD",
        "firmware_version": "v2.4.0",
        "device_criticality": "HIGH",
        "network_segment": "IoT-Telemetry-VLAN",
        "os": "Embedded Linux",
        "av_status": "Not Supported (Embedded)",
        "owner": "Cardiology Ward"
    },
    {
        "device_type": "Laboratory Analyzer",
        "device_vendor": "Roche",
        "device_model": "Cobas 6000",
        "firmware_version": "v3.1.8",
        "device_criticality": "MEDIUM",
        "network_segment": "Medical-Device-VLAN",
        "os": "Windows Server 2019",
        "av_status": "Active",
        "owner": "Clinical IT Ops"
    },
    {
        "device_type": "PACS Server",
        "device_vendor": "Agfa HealthCare",
        "device_model": "Enterprise Imaging",
        "firmware_version": "v9.0.2",
        "device_criticality": "HIGH",
        "network_segment": "Imaging-PACS-VLAN",
        "os": "Windows Server 2019",
        "av_status": "Active",
        "owner": "Radiology IT"
    },
    {
        "device_type": "Nurse Station Workstation",
        "device_vendor": "Dell",
        "device_model": "OptiPlex 7090",
        "firmware_version": "v1.14.0",
        "device_criticality": "LOW",
        "network_segment": "Clinical-Workstation-VLAN",
        "os": "Windows 11 Enterprise",
        "av_status": "Active",
        "owner": "Clinical IT Ops"
    }
]

DEPARTMENTS = [
    "Intensive Care Unit (ICU)",
    "Emergency Department",
    "Operating Room Complex",
    "Radiology & Imaging",
    "Cardiology Care Unit",
    "Central Pathology Lab",
    "Pediatrics Ward",
    "Oncology Wing"
]

LOCATIONS = [
    "ICU-Pod-A", "ICU-Pod-B", "ED-Trauma-1", "ED-Triage-Desk",
    "OR-Suite-03", "Radiology-G02", "Cath-Lab-01", "Lab-Hematology",
    "Ward-3-NurseStation", "Ward-4-NurseStation"
]

USER_ROLES = [
    "Clinical Nurse", "Attending Physician", "Biomedical Tech",
    "Radiologic Technologist", "System Service Account", "Clinical IT Specialist"
]

KNOWN_SCANNER_IPS = ["10.0.10.50", "10.0.10.51", "10.0.10.52"]
INTERNAL_GATEWAYS = ["10.0.1.1", "10.0.2.1", "10.0.3.1"]
MALICIOUS_EXTERNAL_IPS = [
    "185.220.101.5", "194.26.29.112", "45.154.255.89",
    "193.142.146.35", "91.240.118.172", "198.51.100.42"
]
SAFE_EXTERNAL_PACS_CLOUD = ["52.142.88.9", "13.91.44.12"]

ANALYSTS = ["ANL-101", "ANL-102", "ANL-103", "ANL-104", "ANL-105"]

ALERT_TEMPLATES = [
    # Common False Positive Patterns (~70%)
    {
        "alert_type": "Scheduled Vulnerability Scan",
        "severity": "LOW",
        "category": "FP_SCANNER",
        "protocol": "TCP",
        "rule_id": "RULE-SCAN-01",
        "detection_source": "Network NIDS",
        "prob": 0.28
    },
    {
        "alert_type": "Routine Telemetry Beacon",
        "severity": "LOW",
        "category": "FP_TELEMETRY",
        "protocol": "UDP",
        "rule_id": "RULE-BEACON-02",
        "detection_source": "Medical Device Gateway",
        "prob": 0.18
    },
    {
        "alert_type": "HL7 Burst Message Volume",
        "severity": "MEDIUM",
        "category": "FP_BURST",
        "protocol": "TCP",
        "rule_id": "RULE-HL7-05",
        "detection_source": "SIEM Correlation",
        "prob": 0.14
    },
    {
        "alert_type": "Nurse Station Session Re-Auth",
        "severity": "LOW",
        "category": "FP_AUTH",
        "protocol": "HTTPS",
        "rule_id": "RULE-AUTH-03",
        "detection_source": "Host EDR",
        "prob": 0.10
    },
    # True Positives / Threat Patterns (~20%)
    {
        "alert_type": "Brute Force Authentication",
        "severity": "HIGH",
        "category": "TP_CREDENTIAL",
        "protocol": "SSH",
        "rule_id": "RULE-AUTH-BRUTE",
        "detection_source": "Host EDR",
        "prob": 0.06
    },
    {
        "alert_type": "Ransomware File Encryption Activity",
        "severity": "CRITICAL",
        "category": "TP_RANSOMWARE",
        "protocol": "TCP",
        "rule_id": "RULE-EDR-ENCRYPT",
        "detection_source": "Host EDR",
        "prob": 0.03
    },
    {
        "alert_type": "Unauthorized Lateral SMB Traffic",
        "severity": "HIGH",
        "category": "TP_LATERAL",
        "protocol": "TCP",
        "rule_id": "RULE-NET-SMB",
        "detection_source": "Firewall",
        "prob": 0.04
    },
    {
        "alert_type": "Suspicious DICOM Bulk Download",
        "severity": "HIGH",
        "category": "TP_EXFIL",
        "protocol": "DICOM",
        "rule_id": "RULE-MED-DICOM",
        "detection_source": "Network NIDS",
        "prob": 0.04
    },
    {
        "alert_type": "Medical Device Reverse Shell Beacon",
        "severity": "CRITICAL",
        "category": "TP_COMPROMISE",
        "protocol": "TCP",
        "rule_id": "RULE-MED-SHELL",
        "detection_source": "Network NIDS",
        "prob": 0.03
    },
    # Ambiguous / Investigation Required (~10%)
    {
        "alert_type": "Unusual Off-Hours Admin Login",
        "severity": "MEDIUM",
        "category": "INV_OFFHOURS",
        "protocol": "HTTPS",
        "rule_id": "RULE-SEC-OFFHR",
        "detection_source": "SIEM Correlation",
        "prob": 0.05
    },
    {
        "alert_type": "Unverified Firmware Modification Attempt",
        "severity": "HIGH",
        "category": "INV_FIRMWARE",
        "protocol": "TCP",
        "rule_id": "RULE-MED-FW",
        "detection_source": "Medical Device Gateway",
        "prob": 0.05
    }
]

def generate_dataset(num_records=5200, output_dir="data"):
    """Generates synthetic alert records with realistic clinical and security context."""
    os.makedirs(output_dir, exist_ok=True)
    
    start_time = datetime(2026, 8, 1, 0, 0, 0)
    records = []
    
    # Pre-select alert template choices based on probabilities
    template_probs = [t["prob"] for t in ALERT_TEMPLATES]
    norm_probs = [p / sum(template_probs) for p in template_probs]
    
    # Device pool of 80 distinct medical assets
    devices_pool = []
    for i in range(80):
        catalog_item = random.choice(DEVICE_CATALOG).copy()
        dev_id = f"DEV-{catalog_item['device_type'][:3].upper()}-{100 + i}"
        catalog_item["device_id"] = dev_id
        catalog_item["endpoint_id"] = f"EP-{2000 + i}"
        catalog_item["hostname"] = f"{catalog_item['device_type'].lower().replace(' ', '-')}-{100 + i}.hospital.local"
        catalog_item["department"] = random.choice(DEPARTMENTS)
        catalog_item["device_location"] = random.choice(LOCATIONS)
        catalog_item["patch_status"] = random.choices(
            ["Up to date", "Pending reboot", "Missing critical patches", "Legacy unpatchable"],
            weights=[0.60, 0.15, 0.15, 0.10]
        )[0]
        # Historical stats
        if catalog_item["device_criticality"] in ["CRITICAL", "HIGH"]:
            catalog_item["hist_alerts"] = random.randint(15, 80)
            catalog_item["hist_fp_rate"] = round(random.uniform(0.70, 0.95), 3)
        else:
            catalog_item["hist_alerts"] = random.randint(5, 40)
            catalog_item["hist_fp_rate"] = round(random.uniform(0.60, 0.88), 3)
        devices_pool.append(catalog_item)
    
    # Time progression tracker
    curr_time = start_time
    
    for idx in range(num_records):
        tmpl = np.random.choice(ALERT_TEMPLATES, p=norm_probs)
        dev = random.choice(devices_pool)
        
        # Increment timestamp gradually (average 4-8 minutes between alerts)
        curr_time += timedelta(seconds=random.randint(120, 480))
        timestamp = curr_time
        
        # 5-8% delayed events where received_timestamp is 5-45 minutes after event timestamp
        is_delayed = random.random() < 0.07
        if is_delayed:
            delay_seconds = random.randint(300, 2700)
            received_timestamp = timestamp + timedelta(seconds=delay_seconds)
        else:
            received_timestamp = timestamp + timedelta(seconds=random.randint(1, 15))
            
        hour = timestamp.hour
        unusual_time = 1 if (hour < 6 or hour > 21) else 0
        
        # Default scenario-based generation
        category = tmpl["category"]
        
        if category == "FP_SCANNER":
            source_ip = random.choice(KNOWN_SCANNER_IPS)
            destination_ip = f"10.0.12.{random.randint(10, 250)}"
            dest_port = random.choice([80, 443, 104, 2575, 8080, 22])
            source_port = random.randint(40000, 65000)
            auth_status = "NONE"
            login_attempts = 0
            failed_logins = 0
            event_count = random.randint(20, 150)
            known_scanner = 1
            maintenance_window = 1 if (hour < 5 or hour > 23 or random.random() < 0.3) else 0
            unusual_dest = 0
            analyst_disposition = "FALSE_POSITIVE"
            confirmed_incident = 0
            incident_type = "Network Scanning"
            incident_severity = "NONE"
            incident_label = 0
            analyst_confidence = round(random.uniform(0.85, 0.99), 2)
            
        elif category == "FP_TELEMETRY":
            source_ip = f"10.0.12.{random.randint(10, 250)}"
            destination_ip = random.choice(INTERNAL_GATEWAYS)
            dest_port = random.choice([2575, 443, 8443])
            source_port = random.randint(49152, 65535)
            auth_status = "SUCCESS"
            login_attempts = 1
            failed_logins = 0
            event_count = random.randint(1, 5)
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 0
            analyst_disposition = "BENIGN"
            confirmed_incident = 0
            incident_type = "Benign Activity"
            incident_severity = "NONE"
            incident_label = 0
            analyst_confidence = round(random.uniform(0.88, 0.98), 2)
            
        elif category == "FP_BURST":
            source_ip = f"10.0.12.{random.randint(10, 250)}"
            destination_ip = "10.0.2.15"  # Central PACS/EHR
            dest_port = 2575  # Standard HL7
            source_port = random.randint(40000, 60000)
            auth_status = "SUCCESS"
            login_attempts = 1
            failed_logins = 0
            event_count = random.randint(80, 300)
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 0
            analyst_disposition = "FALSE_POSITIVE"
            confirmed_incident = 0
            incident_type = "Benign Activity"
            incident_severity = "NONE"
            incident_label = 0
            analyst_confidence = round(random.uniform(0.80, 0.95), 2)
            
        elif category == "FP_AUTH":
            source_ip = f"10.0.14.{random.randint(20, 100)}"
            destination_ip = "10.0.1.10"  # AD / Auth Server
            dest_port = 443
            source_port = random.randint(50000, 60000)
            auth_status = "FAILURE"
            login_attempts = random.randint(2, 4)
            failed_logins = random.randint(1, 3)
            event_count = failed_logins
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 0
            analyst_disposition = "FALSE_POSITIVE"
            confirmed_incident = 0
            incident_type = "Benign Activity"
            incident_severity = "NONE"
            incident_label = 0
            analyst_confidence = round(random.uniform(0.75, 0.92), 2)
            
        elif category == "TP_CREDENTIAL":
            source_ip = random.choice(MALICIOUS_EXTERNAL_IPS)
            destination_ip = f"10.0.12.{random.randint(10, 250)}"
            dest_port = 22
            source_port = random.randint(30000, 60000)
            auth_status = "FAILURE"
            login_attempts = random.randint(15, 60)
            failed_logins = random.randint(14, 58)
            event_count = login_attempts
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "TRUE_POSITIVE"
            confirmed_incident = 1
            incident_type = "Credential Attack"
            incident_severity = "HIGH"
            incident_label = 1
            analyst_confidence = round(random.uniform(0.90, 0.99), 2)
            
        elif category == "TP_RANSOMWARE":
            source_ip = f"10.0.14.{random.randint(20, 100)}"
            destination_ip = "10.0.2.15"
            dest_port = 445  # SMB
            source_port = random.randint(49000, 60000)
            auth_status = "SUCCESS"
            login_attempts = 1
            failed_logins = 0
            event_count = random.randint(500, 3000)
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "TRUE_POSITIVE"
            confirmed_incident = 1
            incident_type = "Ransomware"
            incident_severity = "CRITICAL"
            incident_label = 1
            analyst_confidence = round(random.uniform(0.95, 1.0), 2)
            
        elif category == "TP_LATERAL":
            source_ip = f"10.0.14.{random.randint(20, 100)}"
            destination_ip = f"10.0.12.{random.randint(10, 250)}"  # Medical VLAN
            dest_port = 445
            source_port = random.randint(40000, 55000)
            auth_status = "FAILURE"
            login_attempts = random.randint(8, 25)
            failed_logins = random.randint(7, 24)
            event_count = login_attempts
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "TRUE_POSITIVE"
            confirmed_incident = 1
            incident_type = "Lateral Movement"
            incident_severity = "HIGH"
            incident_label = 1
            analyst_confidence = round(random.uniform(0.85, 0.98), 2)
            
        elif category == "TP_EXFIL":
            source_ip = "10.0.2.20"  # PACS Server
            destination_ip = random.choice(MALICIOUS_EXTERNAL_IPS)
            dest_port = 104  # DICOM
            source_port = random.randint(45000, 65000)
            auth_status = "SUCCESS"
            login_attempts = 1
            failed_logins = 0
            event_count = random.randint(300, 1500)
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "TRUE_POSITIVE"
            confirmed_incident = 1
            incident_type = "Data Exfiltration"
            incident_severity = "HIGH"
            incident_label = 1
            analyst_confidence = round(random.uniform(0.92, 0.99), 2)
            
        elif category == "TP_COMPROMISE":
            # Direct attack / reverse shell beaconing from medical device
            source_ip = f"10.0.12.{random.randint(10, 250)}"
            destination_ip = random.choice(MALICIOUS_EXTERNAL_IPS)
            dest_port = random.choice([4444, 1337, 8443])
            source_port = random.randint(40000, 60000)
            auth_status = "NONE"
            login_attempts = 0
            failed_logins = 0
            event_count = random.randint(10, 50)
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "TRUE_POSITIVE"
            confirmed_incident = 1
            incident_type = "Medical Device Compromise"
            incident_severity = "CRITICAL"
            incident_label = 1
            analyst_confidence = round(random.uniform(0.90, 0.99), 2)
            
        elif category == "INV_OFFHOURS":
            source_ip = f"10.0.14.{random.randint(20, 100)}"
            destination_ip = f"10.0.12.{random.randint(10, 250)}"
            dest_port = 443
            source_port = random.randint(45000, 60000)
            auth_status = "SUCCESS"
            login_attempts = random.randint(1, 3)
            failed_logins = 1
            event_count = 5
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "NEEDS_INVESTIGATION"
            confirmed_incident = 1 if random.random() < 0.35 else 0
            incident_type = "Unauthorized Access" if confirmed_incident == 1 else "Benign Activity"
            incident_severity = "MEDIUM" if confirmed_incident == 1 else "LOW"
            incident_label = confirmed_incident
            analyst_confidence = round(random.uniform(0.55, 0.75), 2)
            
        else: # INV_FIRMWARE
            source_ip = f"10.0.10.{random.randint(100, 200)}"
            destination_ip = f"10.0.12.{random.randint(10, 250)}"
            dest_port = 8080
            source_port = random.randint(40000, 60000)
            auth_status = "CHALLENGE_FAILED"
            login_attempts = 2
            failed_logins = 1
            event_count = 3
            known_scanner = 0
            maintenance_window = 0
            unusual_dest = 1
            analyst_disposition = "NEEDS_INVESTIGATION"
            confirmed_incident = 1 if random.random() < 0.40 else 0
            incident_type = "Unauthorized Access" if confirmed_incident == 1 else "Benign Activity"
            incident_severity = "HIGH" if confirmed_incident == 1 else "LOW"
            incident_label = confirmed_incident
            analyst_confidence = round(random.uniform(0.50, 0.70), 2)

        # Analyst override noise: in ~4% of alerts, human analyst overrode or made noisy decision
        override_flag = 0
        override_reason = ""
        if random.random() < 0.04:
            override_flag = 1
            if analyst_disposition == "FALSE_POSITIVE" and dev["device_criticality"] == "CRITICAL":
                analyst_disposition = "NEEDS_INVESTIGATION"
                override_reason = "Medical device involved - cautious manual escalation"
            elif analyst_disposition == "NEEDS_INVESTIGATION":
                analyst_disposition = "FALSE_POSITIVE"
                override_reason = "Verified clinical workflow with floor nurse"

        record = {
            "alert_id": f"ALT-{10000 + idx}",
            "event_id": f"EVT-{10000 + idx}",
            "timestamp": timestamp.isoformat(),
            "received_timestamp": received_timestamp.isoformat(),
            "alert_type": tmpl["alert_type"],
            "severity": tmpl["severity"],
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": tmpl["protocol"],
            "source_port": source_port,
            "destination_port": dest_port,
            "authentication_status": auth_status,
            "login_attempts": login_attempts,
            "failed_login_count": failed_logins,
            "event_count": event_count,
            "rule_id": tmpl["rule_id"],
            "detection_source": tmpl["detection_source"],
            "unusual_time": unusual_time,
            "unusual_destination": unusual_dest,
            # Medical Device Fields
            "device_id": dev["device_id"],
            "device_type": dev["device_type"],
            "device_vendor": dev["device_vendor"],
            "device_model": dev["device_model"],
            "firmware_version": dev["firmware_version"],
            "device_criticality": dev["device_criticality"],
            "device_location": dev["device_location"],
            "network_segment": dev["network_segment"],
            "device_owner": dev["owner"],
            # Endpoint context
            "endpoint_id": dev["endpoint_id"],
            "hostname": dev["hostname"],
            "operating_system": dev["os"],
            "department": dev["department"],
            "user_role": random.choice(USER_ROLES),
            "asset_criticality": dev["device_criticality"],
            "patch_status": dev["patch_status"],
            "antivirus_status": dev["av_status"],
            "historical_alert_count": dev["hist_alerts"],
            "historical_false_positive_rate": dev["hist_fp_rate"],
            "known_scanner": known_scanner,
            "maintenance_window": maintenance_window,
            # Analyst fields
            "analyst_id": random.choice(ANALYSTS),
            "analyst_disposition": analyst_disposition,
            "analyst_confidence": analyst_confidence,
            "override_flag": override_flag,
            "override_reason": override_reason,
            # Incident fields
            "confirmed_incident": confirmed_incident,
            "incident_type": incident_type,
            "incident_severity": incident_severity,
            "incident_label": incident_label
        }
        records.append(record)
        
    df = pd.DataFrame(records)
    
    # 1. Inject duplicate events (~2.5% duplicate records with exact same event_id)
    num_duplicates = int(num_records * 0.025)
    dup_indices = np.random.choice(df.index, size=num_duplicates, replace=False)
    dup_rows = df.loc[dup_indices].copy()
    # Change alert_id slightly or keep same event_id
    dup_rows["alert_id"] = [f"ALT-DUP-{i}" for i in range(num_duplicates)]
    dup_rows["received_timestamp"] = (pd.to_datetime(dup_rows["received_timestamp"]) + pd.Timedelta(seconds=random.randint(5, 30))).dt.strftime('%Y-%m-%dT%H:%M:%S')
    df = pd.concat([df, dup_rows], ignore_index=True)
    
    # 2. Inject out-of-order records by shuffling a slice of 100 alerts
    shuffle_start = 500
    shuffle_end = 650
    subset = df.iloc[shuffle_start:shuffle_end].sample(frac=1.0, random_state=RANDOM_SEED)
    df.iloc[shuffle_start:shuffle_end] = subset.values
    
    # 3. Inject 2-4% missing values in selected optional/endpoint fields
    for col in ["patch_status", "antivirus_status", "user_role", "firmware_version"]:
        mask = np.random.rand(len(df)) < 0.03
        df.loc[mask, col] = np.nan
        
    # Save raw alerts
    raw_alerts_path = os.path.join(output_dir, "raw_alerts.csv")
    df.to_csv(raw_alerts_path, index=False)
    print(f"Generated {len(df)} synthetic alert records -> {raw_alerts_path}")
    
    # Extract ground truth confirmed incidents for audit/incident tracking
    incidents_df = df[df["confirmed_incident"] == 1][[
        "alert_id", "event_id", "timestamp", "alert_type", "severity",
        "device_id", "device_type", "device_criticality", "incident_type",
        "incident_severity", "source_ip", "destination_ip"
    ]].copy()
    incidents_path = os.path.join(output_dir, "confirmed_incidents.csv")
    incidents_df.to_csv(incidents_path, index=False)
    print(f"Extracted {len(incidents_df)} confirmed incidents -> {incidents_path}")
    
    # Distribution statistics
    fp_count = (df["analyst_disposition"].isin(["FALSE_POSITIVE", "BENIGN"])).sum()
    tp_count = (df["analyst_disposition"] == "TRUE_POSITIVE").sum()
    inv_count = (df["analyst_disposition"] == "NEEDS_INVESTIGATION").sum()
    print(f"\nDataset Distribution:")
    print(f"  False Positive / Benign: {fp_count} ({fp_count/len(df)*100:.1f}%)")
    print(f"  True Positive:           {tp_count} ({tp_count/len(df)*100:.1f}%)")
    print(f"  Needs Investigation:     {inv_count} ({inv_count/len(df)*100:.1f}%)")
    print(f"  Total Confirmed Threats: {len(incidents_df)} ({len(incidents_df)/len(df)*100:.1f}%)")
    print(f"  Missing values count:    {df.isna().sum().sum()}")
    
    return df

if __name__ == "__main__":
    generate_dataset()
