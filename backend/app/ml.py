"""Isolation Forest anomaly detection over behavioural features. Trained on SYNTHETIC baselines only: a heuristic signal, not a proven detector."""
import os
from datetime import datetime, timedelta
import joblib, numpy as np
from sklearn.ensemble import IsolationForest
from .db import SecurityEvent

FEATURES = ["login_frequency", "failed_logins", "login_hour", "geo_change", "files_accessed", "privilege_changes",
            "outbound_connections", "connection_frequency", "unusual_processes"]
MODEL_PATH = os.getenv("MODEL_PATH", "models/anomaly.joblib")
ext = lambda ip: bool(ip) and not ip.startswith("10.")

def extract_features(db, e: SecurityEvent, window: int = 15) -> dict:
    """Behaviour of e.user over the last `window` minutes. geo_change is a proxy (new external IP login); no GeoIP DB is used."""
    evs = db.query(SecurityEvent).filter(SecurityEvent.user == e.user, SecurityEvent.timestamp >= e.timestamp - timedelta(minutes=window),
                                         SecurityEvent.timestamp <= e.timestamp).all()
    t = lambda *ts: [x for x in evs if x.event_type in ts]; logins = t("login_success")
    procs = [str(x.meta.get("process", "")).lower() for x in t("process_execution", "suspicious_process")]
    return dict(login_frequency=len(logins), failed_logins=len(t("login_failure")), login_hour=(logins[-1].timestamp.hour if logins else 13),
                geo_change=int(any(ext(x.src_ip) for x in logins)), files_accessed=sum(int(x.meta.get("files", 0)) for x in t("file_access")),
                privilege_changes=len(t("privilege_escalation")), outbound_connections=sum(1 for x in t("network_connection", "data_transfer") if ext(x.dst_ip)),
                connection_frequency=len(t("network_connection", "port_scan", "data_transfer")),
                unusual_processes=sum(1 for p in procs if any(k in p for k in ("whoami", "nc ", "powershell", "mimikatz"))) )

def synthetic_baseline(n: int = 3000, seed: int = 42) -> np.ndarray:
    r = np.random.default_rng(seed); hours = np.where(r.random(n) < 0.9, r.integers(8, 19, n), r.integers(0, 24, n))
    return np.column_stack([r.poisson(2, n), r.poisson(0.4, n), hours, r.random(n) < 0.01, r.poisson(10, n), r.random(n) < 0.01,
                            r.poisson(1.5, n), r.poisson(4, n), r.random(n) < 0.02]).astype(float)

class AnomalyDetectionService:
    """Train / predict / persist. Auto-loads a saved model, else trains on the synthetic baseline."""
    def __init__(self, path: str = MODEL_PATH):
        self.path, self.model, self.version = path, None, "untrained"
        if os.path.exists(path): self.load()
        else: self.train()
    def train(self, samples: int = 3000, seed: int = 42) -> dict:
        X = synthetic_baseline(samples, seed); self.model = IsolationForest(n_estimators=200, contamination=0.01, random_state=seed).fit(X)
        self.mean, self.std = X.mean(0), np.maximum(X.std(0), 0.5); at = datetime.utcnow()
        self.version = f"iforest-{at:%Y%m%d%H%M%S}-n{samples}"; os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        joblib.dump(dict(model=self.model, mean=self.mean, std=self.std, version=self.version), self.path)
        return {"model_version": self.version, "samples": samples, "trained_at": at.isoformat()}
    def load(self):
        d = joblib.load(self.path); self.model, self.mean, self.std, self.version = d["model"], d["mean"], d["std"], d["version"]
    def predict(self, feats: dict) -> dict:
        """anomaly_score: higher = more anomalous (-score_samples). is_anomaly additionally requires a feature >=3 baseline std ABOVE normal
        (suppresses false alarms on merely-quiet users). contributing_features are z-score heuristics, not exact attributions."""
        x = np.array([[float(feats.get(f, 0)) for f in FEATURES]]); raw = float(-self.model.score_samples(x)[0]); flagged = int(self.model.predict(x)[0]) == -1
        z = (x[0] - self.mean) / self.std
        contrib = sorted([dict(feature=f, value=float(v), z=round(float(s), 1)) for f, v, s in zip(FEATURES, x[0], z) if s >= 3], key=lambda c: -c["z"])
        return dict(anomaly_score=round(raw, 4), is_anomaly=flagged and bool(contrib), model_flagged=flagged, contributing_features=contrib, model_version=self.version)
