# Network Log Anomaly Detector 🛡️📊

An R-based automated network telemetry processing engine designed to parse raw firewall/router syslog data and isolate security anomalies using statistical outlier detection frameworks.

## 📋 Project Overview
Traditional firewalls often rely on rigid, hardcoded rules to flag unauthorized activity. This project demonstrates a data-driven approach to infrastructure security. By treating network traffic as a statistical pipeline, this script establishes an operational baseline of normal network activity and automatically isolates anomalies (such as DDoS traffic spikes or brute-force port scans) using the mathematical **3-Sigma rule**.

## 🛠️ Technical Capabilities Demonstrated
*   **Data Wrangling (`dplyr`):** Ingesting, structural cleaning, and filtering simulated enterprise log data frames.
*   **Statistical Outlier Modeling:** Applying standard deviation thresholds to separate normal routing fluctuations from distinct infrastructure traffic anomalies.
*   **Infrastructure Diagnostics:** Targeting network-specific protocols (such as risky Telnet Port 23 traffic spikes) within raw packet logs.

## 🚀 How the Code Works
1.  **Data Generation:** Simulates a continuous 24-hour log file (144 data points sampled at 10-minute intervals) recording packet counts, target ports, and source IP addresses.
2.  **Baseline Calculation:** Calculates the population mean and standard deviation of packets transferred under normal operating parameters.
3.  **Threshold Isolation:** Establishes an upper control limit at Mean + (3 * SD). Any connection request breaking this threshold is automatically flagged as a high-risk security alert.

## 📈 Intended Business Impact
Implementing an automated statistical log parser across local edge devices (like Mikrotik or Cisco routing endpoints) drastically reduces manual log auditing hours for network administrators, transforming traditional infrastructure maintenance into a proactive threat isolation pipeline.
