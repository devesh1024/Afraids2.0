"""Deterministic self-reflection (no LLM): is the evidence sufficient, corroborated, consistent, confident, and the response proportional?

If not, the incident is marked NEEDS_REVIEW instead of pretending certainty.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .config import Settings
from .guardrails import ACTION_POLICIES, risk_rank
from .risk import evidence_confidence, signal_families


@dataclass
class Check:
    name: str; passed: bool; detail: str; blocking: bool = True


@dataclass
class VerificationReport:
    checks: list = field(default_factory=list)
    contradictions: list = field(default_factory=list)
    confidence: float = 0.0

    @property
    def needs_review(self) -> bool: return any(not c.passed and c.blocking for c in self.checks)

    @property
    def needs_more_evidence(self) -> bool:
        return any(not c.passed and c.name in ("sufficient_evidence", "independent_signals", "confidence_threshold") for c in self.checks)

    @property
    def verdict(self) -> str: return "needs_review" if self.needs_review else "confirmed"

    def failed(self) -> list: return [c.name for c in self.checks if not c.passed]

    def to_dict(self) -> dict:
        return dict(verdict=self.verdict, needs_review=self.needs_review, needs_more_evidence=self.needs_more_evidence, confidence=self.confidence,
                    contradictions=self.contradictions, checks=[dict(name=c.name, passed=c.passed, detail=c.detail, blocking=c.blocking) for c in self.checks])


class Verifier:
    def __init__(self, settings: Settings | None = None): self.s = settings or Settings()

    def verify(self, case: dict, risk: dict | None = None, responses: list | None = None, degraded: int = 0) -> VerificationReport:
        """case: {alerts:[...], findings:[...], event_count:int}; risk: calculate_risk output; responses: planned actions (dicts with 'action')."""
        s, alerts, findings = self.s, case.get("alerts", []), case.get("findings", [])
        n_events = case.get("event_count", 0); r = VerificationReport()
        top_conf = max((a["confidence"] for a in alerts), default=0.0)
        strong = any(a["severity"] in ("high", "critical") and a["confidence"] >= s.strong_single_alert_confidence for a in alerts)
        r.checks.append(Check("sufficient_evidence", n_events >= s.min_correlated_events or strong,
                              f"{n_events} correlated event(s); strongest alert confidence {top_conf:.2f}"))
        fam = signal_families(alerts, findings)
        r.checks.append(Check("independent_signals", len(fam) >= s.min_independent_signals,
                              f"{len(fam)} independent signal famil{'y' if len(fam) == 1 else 'ies'} ({', '.join(sorted(fam)) or 'none'}); need {s.min_independent_signals}"))
        r.contradictions = [f["description"] for f in findings if f.get("contradicts")]
        r.checks.append(Check("no_contradictions", not r.contradictions, "no contradicting evidence" if not r.contradictions else f"{len(r.contradictions)} contradiction(s): " + "; ".join(r.contradictions)))
        if risk is not None: conf = risk["confidence"]
        else: conf = evidence_confidence([a["confidence"] for a in alerts], [f["confidence"] for f in findings if not f.get("contradicts")], fam, len(r.contradictions))
        conf = round(max(0.0, conf - 0.05 * degraded), 2); r.confidence = conf
        r.checks.append(Check("confidence_threshold", conf >= s.confidence_threshold, f"confidence {conf:.2f} vs threshold {s.confidence_threshold:.2f}"))
        if degraded: r.checks.append(Check("agents_healthy", False, f"{degraded} non-critical agent(s) failed; evidence may be incomplete", blocking=False))
        evidence_ok = not r.needs_review
        if responses is not None and risk is not None:
            lvl = risk["severity"]
            over = [x["action"] for x in responses if risk_rank(ACTION_POLICIES[x["action"]].min_risk) > risk_rank(lvl)]
            r.checks.append(Check("response_proportional", not over, f"all planned actions are proportionate to {lvl} risk" if not over else f"over-response for {lvl} risk: {', '.join(over)}"))
            if risk_rank(lvl) >= 2 and evidence_ok and not any(ACTION_POLICIES[x["action"]].destructive for x in responses):
                r.checks.append(Check("response_coverage", False, f"{lvl} risk but no containment action was proposed", blocking=False))
        return r
