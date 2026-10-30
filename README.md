# 🛡️ ZeroShield
### An Agentic AI-Driven Zero-Day Attack Detection & Autonomous Response System

Based on: *"From zero-shot machine learning to zero-day attack detection"*
(Sarhan, Layeghy, Gallagher, Portmann — International Journal of Information Security, 2023)

---

## What This Project Does

This project **reproduces** the paper's Zero-Shot Learning (ZSL) methodology,
then **extends** it with two original contributions:

1. **Deep Learning Layer (Autoencoder)** — catches attacks the paper's ZSL
   models struggle with (like *Fuzzers*, which the paper detects at only
   14-76% Z-DR).
2. **Agentic AI Layer (Cyber Agent)** — an autonomous reasoning-and-response
   system that combines all detection signals, explains its reasoning, and
   automatically takes protective action (block IP, freeze account, isolate
   host) — something the original paper does not do (it only evaluates
   detection, not response).

## Project Structure

```
zeroshield/
├── data/
│   └── generate_dataset.py      # Synthetic UNSW-NB15-style dataset
├── models/
│   ├── zsl_train.py             # Paper's ZSL methodology (RF + MLP)
│   ├── autoencoder_detector.py  # DL anomaly detection layer
│   └── cyber_agent.py           # Agentic AI: Perceive-Reason-Act-Learn
├── dashboard/
│   └── app.py                   # Streamlit live dashboard
├── requirements.txt
└── README.md
```

## How to Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate the dataset
python3 data/generate_dataset.py

# 3. Run the ZSL baseline (reproduces paper's Z-DR tables)
python3 models/zsl_train.py

# 4. Run the autoencoder comparison
python3 models/autoencoder_detector.py

# 5. Test the cyber agent directly (console demo)
python3 models/cyber_agent.py

# 6. Launch the full interactive dashboard
streamlit run dashboard/app.py
```

## ⚠️ About the Dataset

This project ships with a **synthetic dataset generator** so the full
pipeline runs immediately without any manual downloads. The synthetic
data is deliberately designed to mirror the paper's real finding: most
attacks are easy to separate from benign traffic, but one attack type
(here, "Fuzzers") is intentionally generated to overlap heavily with
benign traffic — reproducing the paper's core weakness.

**To use the real dataset** used in the paper:
1. Download UNSW-NB15 from: https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. Replace `load_data()` in `data/generate_dataset.py` to read the real CSV
   (keep the same column structure: feature columns + `label` + `is_attack`)
3. Everything downstream (ZSL training, autoencoder, agent) works unchanged.

## System Architecture

```
Traffic Event
     │
     ▼
┌─────────────────────┐
│  ZSL Model (RF/MLP)  │──► attack probability score
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  Autoencoder (DL)     │──► anomaly score (catches ZSL's blind spots)
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│   CYBER AGENT          │
│  Perceive → Reason      │──► Verdict: SAFE / SUSPICIOUS / MALICIOUS
│  → Act → Learn          │──► Autonomous actions (block/alert/isolate)
└─────────────────────┘
```

## Key Results (Synthetic Data Demo)

| Attack Type | ZSL Z-DR (RF) | Autoencoder Detection |
|---|---|---|
| Backdoor / Worms / Shellcode | ~100% | ~100% |
| **Fuzzers (hardest case)** | **~4-5%** | **~27%** (improved via DL layer) |

The Cyber Agent then combines both scores + contextual signals (unusual
login time, unfamiliar IP, file mismatch) to catch cases neither model
is fully confident about alone — exactly the MediCare Connect ransomware
scenario discussed in the project design.
