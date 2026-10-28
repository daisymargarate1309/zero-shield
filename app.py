"""
app.py -- ZeroShield Live Dashboard
------------------------------------
Run with:  streamlit run app.py

Shows:
  1. ZSL baseline results (reproducing paper's Tables 2-5)
  2. Autoencoder improvement on hard attacks (Fuzzers)
  3. Live Cyber Agent simulation -- feed events, see reasoning + actions
"""
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "models"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "data"))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from cyber_agent import CyberAgent, TrafficEvent

st.set_page_config(page_title="ZeroShield", layout="wide", page_icon="🛡️")

st.title("🛡️ ZeroShield — Zero-Day Detection & Autonomous Response")
st.caption("ZSL (paper baseline) + Deep Learning Anomaly Detection + Agentic AI response layer")

tab1, tab2, tab3 = st.tabs([
    "📊 ZSL Baseline (Paper Reproduction)",
    "🧠 DL Anomaly Detection Improvement",
    "🤖 Live Cyber Agent Simulator"
])

# ---------------- TAB 1: ZSL RESULTS ----------------
with tab1:
    st.subheader("Zero-Shot Learning Results (Reproducing the Paper's Methodology)")
    results_path = os.path.join(os.path.dirname(__file__), "..", "models", "zsl_results.csv")
    if os.path.exists(results_path):
        df = pd.read_csv(results_path)
        col1, col2 = st.columns([2, 1])
        with col1:
            fig = px.bar(
                df, x="Zero-Day Attack", y="Z-DR (%)", color="Model",
                barmode="group", title="Z-DR per Attack Class (RF vs MLP)",
                color_discrete_map={"RF": "#4C78A8", "MLP": "#F58518"}
            )
            fig.update_layout(yaxis_range=[0, 105])
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.metric("Avg Z-DR (RF)", f"{df[df.Model=='RF']['Z-DR (%)'].mean():.1f}%")
            st.metric("Avg Z-DR (MLP)", f"{df[df.Model=='MLP']['Z-DR (%)'].mean():.1f}%")
            worst = df.loc[df["Z-DR (%)"].idxmin()]
            st.metric("Weakest Attack", worst["Zero-Day Attack"],
                       f"{worst['Z-DR (%)']:.1f}% Z-DR", delta_color="inverse")
            st.info("Matches the paper's key finding: **Fuzzers** is the hardest "
                    "attack to detect as zero-day, while others reach ~100%.")
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("Run `python3 models/zsl_train.py` first to generate results.")

# ---------------- TAB 2: AUTOENCODER ----------------
with tab2:
    st.subheader("Deep Learning Layer: Catching What ZSL Misses")
    st.write(
        "An Autoencoder is trained **only on benign traffic**. It flags "
        "attacks purely by how different they look from 'normal' — "
        "without ever having seen that specific attack type."
    )
    if st.button("▶ Run Autoencoder Evaluation"):
        with st.spinner("Training autoencoder on benign traffic..."):
            from autoencoder_detector import evaluate_autoencoder_on_fuzzers
            ae, ae_results = evaluate_autoencoder_on_fuzzers()
            st.session_state["ae_results"] = ae_results

    if "ae_results" in st.session_state:
        ae_df = pd.DataFrame(
            list(st.session_state["ae_results"].items()),
            columns=["Attack", "AE Detection Rate (%)"]
        )
        zsl_df = pd.read_csv(results_path) if os.path.exists(results_path) else None

        fig2 = go.Figure()
        fig2.add_trace(go.Bar(name="Autoencoder", x=ae_df["Attack"],
                               y=ae_df["AE Detection Rate (%)"], marker_color="#54A24B"))
        if zsl_df is not None:
            rf_fuzz = zsl_df[zsl_df["Model"] == "RF"].set_index("Zero-Day Attack")["Z-DR (%)"]
            fig2.add_trace(go.Bar(name="ZSL (RF)", x=rf_fuzz.index, y=rf_fuzz.values,
                                   marker_color="#4C78A8"))
        fig2.update_layout(barmode="group", title="ZSL vs Autoencoder Detection Rate",
                            yaxis_range=[0, 105])
        st.plotly_chart(fig2, use_container_width=True)

        st.success(
            f"On **Fuzzers** (the paper's weak point): Autoencoder achieves "
            f"**{st.session_state['ae_results']['Fuzzers']}%** detection — "
            f"a meaningful improvement over ZSL alone."
        )

# ---------------- TAB 3: LIVE AGENT SIMULATOR ----------------
with tab3:
    st.subheader("🤖 Cyber Agent — Perceive → Reason → Act (Live)")
    st.write("Simulate an incoming traffic event and watch the agent reason through it in real time.")

    if "agent" not in st.session_state:
        st.session_state["agent"] = CyberAgent()
        st.session_state["events_log"] = []

    with st.form("event_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            user = st.text_input("User", "dr_sarah")
            src_ip = st.text_input("Source IP", "203.0.113.77")
            known_ip = st.checkbox("IP previously seen for this user?", value=False)
        with c2:
            hour = st.slider("Hour of event (0-23)", 0, 23, 2)
            zsl_prob = st.slider("ZSL attack probability", 0.0, 1.0, 0.42)
        with c3:
            ae_score = st.slider("Autoencoder anomaly score", 0.0, 1.0, 0.81)
            ae_anom = st.checkbox("Flagged as anomaly by Autoencoder?", value=True)
            mismatch = st.checkbox("File name/content mismatch?", value=True)

        submitted = st.form_submit_button("🚀 Send Event to Agent")

    if submitted:
        event = TrafficEvent(
            event_id=f"EVT-{len(st.session_state['events_log'])+1:03d}",
            src_ip=src_ip, user=user, hour_of_day=hour,
            zsl_attack_prob=zsl_prob, ae_anomaly_score=ae_score,
            ae_is_anomaly=ae_anom, known_ip=known_ip,
            file_name_content_mismatch=mismatch
        )
        decision = st.session_state["agent"].handle_event(event)
        st.session_state["events_log"].append((event, decision))

    if st.session_state["events_log"]:
        event, decision = st.session_state["events_log"][-1]

        color = {"SAFE": "green", "SUSPICIOUS": "orange", "MALICIOUS": "red"}[decision.verdict]
        st.markdown(f"### Verdict: :{color}[{decision.verdict}]  (confidence {decision.confidence*100:.0f}%)")

        colA, colB = st.columns(2)
        with colA:
            st.markdown("**🧠 Agent Reasoning:**")
            for r in decision.reasoning:
                st.markdown(f"- {r}")
        with colB:
            st.markdown("**⚡ Actions Taken:**")
            for a in decision.actions_taken:
                st.markdown(f"- {a}")

        st.markdown("---")
        st.markdown("**📜 Incident History**")
        hist = pd.DataFrame([
            {"Event": e.event_id, "User": e.user, "IP": e.src_ip,
             "Verdict": d.verdict, "Confidence": f"{d.confidence*100:.0f}%"}
            for e, d in st.session_state["events_log"]
        ])
        st.dataframe(hist, use_container_width=True)
