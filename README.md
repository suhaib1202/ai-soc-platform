## 🛡️ AI-Powered SOC Analyst Assistant

> End-to-end SOC automation platform with ensemble ML detection,
> live threat intelligence enrichment, MITRE ATT&CK classification,
> and real-time Discord alerting.


## Description 

- Engineered an ML-powered anomaly detection pipeline using Isolation Forest + Random Forest + LSTM ensemble on 52,000+ security events/day from simulated Windows and Linux environments
- Implemented automated MITRE ATT&CK technique classification across 14 attack techniques including lateral movement, privilege escalation, and command & control
- Enriched every flagged IOC with live VirusTotal and AbuseIPDB threat intelligence APIs for real-time IP reputation validation
- Built a Streamlit analyst dashboard with one-click IOC lookup, MITRE ATT&CK heatmap, and severity-based alert feed
- Automated Discord alerting for CRITICAL threats, reducing simulated analyst triage time by 35%


## Architecture

    Raw Logs (52,000+ events/day)
              |
              v
    +----------------------------------+
    |      ENSEMBLE ML DETECTION       |
    |  Isolation Forest (unsupervised) |
    |  Random Forest (semi-supervised) |
    |  LSTM Autoencoder (time-series)  |
    +----------------------------------+
              |
              v  Anomalies Detected
    +----------------------------------+
    |    LIVE THREAT INTELLIGENCE      |
    |  VirusTotal API                  |
    |  AbuseIPDB API                   |
    +----------------------------------+
              |
              v  Enriched Alerts
    +----------------------------------+
    |  MITRE ATT&CK CLASSIFICATION     |
    |  14 techniques, 6 tactics        |
    |  Severity scoring + IOC flagging |
    +----------------------------------+
              |
         _____|_____
        |           |
        v           v
    [Discord]   [Streamlit]
     Alerts      Dashboard

## ML Models

| Model | Type | Precision |
|---|---|---|
| Isolation Forest | Unsupervised | ~82% |
| Random Forest | Semi-supervised | ~91% |
| LSTM Autoencoder | Deep Learning | ~88% |
| **Ensemble** | Voting | **~94%** |


## Quick Start
```bash
git clone https://github.com/suhaib1202/ai-soc-platform.git
cd ai-soc-platform
pip install -r requirements.txt
# Add your API keys to .env
python main_pipeline.py
streamlit run app.py
```

## Tech Stack

Python · scikit-learn · TensorFlow · Streamlit · Plotly · ELK Stack · MITRE ATT&CK · VirusTotal API · AbuseIPDB API · Discord · Docker


## Outputs

Can view outputs/results of this project in the output folder.
