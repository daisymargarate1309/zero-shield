"""
cyber_agent.py
--------------
THE CYBER AGENT (Agentic AI Layer) -- YOUR MAIN CONTRIBUTION.

This is NOT a third-party AI product -- it is a Python class you build and
own, implementing the Perceive -> Detect -> Reason -> Act -> Learn cycle
discussed in your project.

It combines:
  - ZSL model score      (from zsl_train.py / RF+MLP)
  - Autoencoder score     (from autoencoder_detector.py)
  - Contextual metadata    (login time, IP reputation, request volume)

...and REASONS through them the way a human security analyst would, then
takes an autonomous ACTION (allow / alert / auto-block).
"""

import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class TrafficEvent:
    """One incoming network event the agent must judge."""
    event_id: str
    src_ip: str
    user: str
    hour_of_day: int              # 0-23
    zsl_attack_prob: float        # 0-1, from RF/MLP
    ae_anomaly_score: float       # reconstruction error (0-1 normalized)
    ae_is_anomaly: bool
    known_ip: bool = True         # has this IP been seen before for this user?
    file_name_content_mismatch: bool = False


@dataclass
class AgentDecision:
    event_id: str
    confidence: float
    verdict: str                  # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    reasoning: list = field(default_factory=list)
    actions_taken: list = field(default_factory=list)


class CyberAgent:
    """
    Perceive -> Detect -> Reason -> Act -> Learn
    """

    def __init__(self, block_threshold=0.75, alert_threshold=0.40):
        self.block_threshold = block_threshold
        self.alert_threshold = alert_threshold
        self.incident_log = []          # "Learn" phase memory
        self.blocked_ips = set()

    # ---------- PERCEIVE ----------
    def perceive(self, event: TrafficEvent):
        """In a real system: pull live packets/logs. Here: receive event."""
        return event

    # ---------- REASON ----------
    def reason(self, event: TrafficEvent) -> AgentDecision:
        reasoning = []
        confidence = 0.0

        # Signal 1: ZSL model output
        if event.zsl_attack_prob > 0.5:
            confidence += 0.35
            reasoning.append(
                f"ZSL model flags this traffic as attack-like "
                f"(score={event.zsl_attack_prob:.2f})."
            )

        # Signal 2: Autoencoder anomaly
        if event.ae_is_anomaly:
            confidence += 0.35
            reasoning.append(
                f"Autoencoder reconstruction error is abnormally high "
                f"(score={event.ae_anomaly_score:.2f}) -- pattern does not "
                f"match learned normal behavior."
            )

        # Signal 3: Unusual timing (outside 8am-8pm)
        if event.hour_of_day < 6 or event.hour_of_day > 22:
            confidence += 0.10
            reasoning.append(
                f"Event occurred at unusual hour ({event.hour_of_day}:00), "
                f"outside normal working hours."
            )

        # Signal 4: Unknown / unfamiliar IP
        if not event.known_ip:
            confidence += 0.10
            reasoning.append(
                f"Source IP {event.src_ip} has never been seen for user "
                f"'{event.user}' before."
            )

        # Signal 5: File-name vs content mismatch (loophole-style attack)
        if event.file_name_content_mismatch:
            confidence += 0.15
            reasoning.append(
                "File extension does not match actual file content "
                "(possible disguised malicious payload)."
            )

        confidence = min(confidence, 1.0)

        if confidence >= self.block_threshold:
            verdict = "MALICIOUS"
        elif confidence >= self.alert_threshold:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        if not reasoning:
            reasoning.append("No anomalous signals detected; traffic looks normal.")

        return AgentDecision(
            event_id=event.event_id,
            confidence=round(confidence, 2),
            verdict=verdict,
            reasoning=reasoning,
        )

    # ---------- ACT ----------
    def act(self, event: TrafficEvent, decision: AgentDecision) -> AgentDecision:
        if decision.verdict == "MALICIOUS":
            decision.actions_taken.append(f"BLOCK IP {event.src_ip}")
            decision.actions_taken.append(f"SUSPEND account '{event.user}'")
            decision.actions_taken.append("QUARANTINE associated file/session")
            decision.actions_taken.append("ISOLATE affected host from network")
            decision.actions_taken.append("ALERT security team with full report")
            self.blocked_ips.add(event.src_ip)

        elif decision.verdict == "SUSPICIOUS":
            decision.actions_taken.append("ALERT security team for manual review")
            decision.actions_taken.append(f"FLAG account '{event.user}' for monitoring")

        else:
            decision.actions_taken.append("ALLOW -- no action needed")

        return decision

    # ---------- LEARN ----------
    def learn(self, event: TrafficEvent, decision: AgentDecision,
              human_confirmed: Optional[bool] = None):
        """Log the incident; in a full system this would feed model retraining."""
        self.incident_log.append({
            "event_id": event.event_id,
            "timestamp": datetime.now().isoformat(),
            "verdict": decision.verdict,
            "confidence": decision.confidence,
            "human_confirmed": human_confirmed,
        })

    # ---------- FULL PIPELINE ----------
    def handle_event(self, event: TrafficEvent) -> AgentDecision:
        e = self.perceive(event)
        decision = self.reason(e)
        decision = self.act(e, decision)
        self.learn(e, decision)
        return decision


def demo():
    agent = CyberAgent()

    print("=" * 65)
    print("DEMO 1: Normal, benign login")
    print("=" * 65)
    normal_event = TrafficEvent(
        event_id="EVT-001", src_ip="10.0.0.15", user="dr_priya",
        hour_of_day=14, zsl_attack_prob=0.05, ae_anomaly_score=0.02,
        ae_is_anomaly=False, known_ip=True, file_name_content_mismatch=False
    )
    d1 = agent.handle_event(normal_event)
    print_decision(d1)

    print("\n" + "=" * 65)
    print("DEMO 2: MediCare-style zero-day ransomware upload (Fuzzers-like)")
    print("=" * 65)
    attack_event = TrafficEvent(
        event_id="EVT-002", src_ip="203.0.113.77", user="dr_sarah",
        hour_of_day=2, zsl_attack_prob=0.42,      # ZSL model is UNSURE (Fuzzers-like weak signal)
        ae_anomaly_score=0.81, ae_is_anomaly=True,  # but Autoencoder catches it!
        known_ip=False, file_name_content_mismatch=True
    )
    d2 = agent.handle_event(attack_event)
    print_decision(d2)


def print_decision(decision: AgentDecision):
    print(f"\nEvent: {decision.event_id}")
    print(f"Verdict: {decision.verdict}  |  Confidence: {decision.confidence*100:.0f}%")
    print("Reasoning:")
    for r in decision.reasoning:
        print(f"   - {r}")
    print("Actions Taken:")
    for a in decision.actions_taken:
        print(f"   -> {a}")


if __name__ == "__main__":
    demo()
