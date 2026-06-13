"""
AI-DTCTM | ML Model Manager (Phase 3)
Manages multiple model versions, A/B testing, and auto-retraining.
"""

import pickle
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple

from core.logger import get_logger

log = get_logger(__name__)

MODELS_DIR = Path(__file__).parent / "ml_models"
MODELS_DIR.mkdir(exist_ok=True)

# Default to v3_100k if available, else fall back to ultimate, then v2
DEFAULT_MODELS = [
    "phishing_classifier_v3_100k.pkl",  # Production (100K samples, 99%+ accuracy)
    "phishing_classifier_numpy_ultimate.pkl",  # Fallback (20K samples, 94% accuracy)
    "phishing_classifier_numpy_v2.pkl",  # Second fallback (15K samples, 86% accuracy)
    "phishing_classifier_numpy.pkl",  # Last resort (6K samples, 79% accuracy)
]


class MLModelManager:
    """Manages ML model lifecycle, versioning, and A/B testing."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize model manager with optional SQLite backend for tracking."""
        self.db_path = db_path or str(
            Path(__file__).parent.parent / "data" / "model_tracking.db"
        )
        self._ensure_db()
        self.active_model_id = self._get_active_model()
        self._model_cache = {}

    def _ensure_db(self):
        """Create model tracking tables if needed."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_id TEXT UNIQUE,
                version TEXT,
                model_type TEXT,
                training_date TIMESTAMP,
                accuracy REAL,
                precision REAL,
                recall REAL,
                roc_auc REAL,
                status TEXT,
                training_params TEXT,
                dataset_info TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ab_test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                model_a_id TEXT,
                model_b_id TEXT,
                model_a_verdict TEXT,
                model_b_verdict TEXT,
                ground_truth TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_id TEXT,
                metric_date DATE,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1_score REAL,
                scans_evaluated INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def _get_active_model(self) -> str:
        """Get currently active model ID from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            row = conn.execute(
                "SELECT model_id FROM ml_models WHERE status = 'active' LIMIT 1"
            ).fetchone()
            conn.close()
            return row[0] if row else None
        except Exception as e:
            log.error("get_active_model_failed", error=str(e))
            return None

    def register_model(self, model_path: str, metadata: Dict) -> str:
        """Register a new model version in the system."""
        try:
            model_id = metadata.get("model_id", Path(model_path).stem)

            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT OR REPLACE INTO ml_models
                (model_id, version, model_type, training_date, accuracy, precision,
                 recall, roc_auc, status, training_params, dataset_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                model_id,
                metadata.get("version", "1.0"),
                metadata.get("model_type", "NumPy Ensemble"),
                metadata.get("training_date", datetime.utcnow().isoformat()),
                metadata.get("accuracy", 0),
                metadata.get("precision", 0),
                metadata.get("recall", 0),
                metadata.get("roc_auc", 0),
                "archived",  # Start as archived, must be explicitly activated
                json.dumps(metadata.get("training_params", {})),
                json.dumps(metadata.get("dataset_info", {})),
            ))
            conn.commit()
            conn.close()

            log.info("model_registered", model_id=model_id, accuracy=metadata.get("accuracy"))
            return model_id
        except Exception as e:
            log.error("model_register_failed", error=str(e))
            return None

    def load_model(self, model_id: Optional[str] = None) -> Optional[Dict]:
        """Load a model by ID or fall back to default models."""
        # Use cached version if available
        if model_id and model_id in self._model_cache:
            return self._model_cache[model_id]

        # Try specified model ID first
        if model_id:
            model_files = list(MODELS_DIR.glob(f"{model_id}.pkl"))
            if model_files:
                try:
                    with open(model_files[0], "rb") as f:
                        model = pickle.load(f)
                        self._model_cache[model_id] = model
                        return model
                except Exception as e:
                    log.warning("model_load_failed", model_id=model_id, error=str(e))

        # Fall back to default models in order
        for model_name in DEFAULT_MODELS:
            model_path = MODELS_DIR / model_name
            if model_path.exists():
                try:
                    with open(model_path, "rb") as f:
                        model = pickle.load(f)
                        self._model_cache[model_name] = model
                        return model
                except Exception as e:
                    log.warning("default_model_load_failed", model=model_name, error=str(e))

        log.error("no_models_available")
        return None

    def set_active_model(self, model_id: str) -> bool:
        """Promote a model to active status."""
        try:
            conn = sqlite3.connect(self.db_path)

            # Deactivate current active model
            conn.execute(
                "UPDATE ml_models SET status = 'testing' WHERE status = 'active'"
            )

            # Activate new model
            conn.execute(
                "UPDATE ml_models SET status = 'active' WHERE model_id = ?",
                (model_id,)
            )

            conn.commit()
            conn.close()

            self.active_model_id = model_id
            log.info("model_activated", model_id=model_id)
            return True
        except Exception as e:
            log.error("set_active_model_failed", model_id=model_id, error=str(e))
            return False

    def get_active_model(self) -> Optional[Dict]:
        """Get the currently active model."""
        if self.active_model_id:
            return self.load_model(self.active_model_id)
        return self.load_model()

    def get_model_history(self) -> List[Dict]:
        """Get all registered model versions with their metrics."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT model_id, version, model_type, training_date, accuracy,
                       precision, recall, roc_auc, status
                FROM ml_models
                ORDER BY training_date DESC
            """).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            log.error("get_model_history_failed", error=str(e))
            return []

    def compare_models(self, model_id1: str, model_id2: str) -> Dict:
        """Compare performance metrics between two models."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row

            m1 = conn.execute(
                "SELECT * FROM ml_models WHERE model_id = ?", (model_id1,)
            ).fetchone()
            m2 = conn.execute(
                "SELECT * FROM ml_models WHERE model_id = ?", (model_id2,)
            ).fetchone()

            conn.close()

            if not m1 or not m2:
                return {"error": "Model(s) not found"}

            m1_dict = dict(m1)
            m2_dict = dict(m2)

            return {
                "model_1": m1_dict,
                "model_2": m2_dict,
                "winner": "model_1" if m1_dict["accuracy"] > m2_dict["accuracy"] else "model_2",
                "accuracy_diff": abs(m1_dict["accuracy"] - m2_dict["accuracy"]),
            }
        except Exception as e:
            log.error("compare_models_failed", error=str(e))
            return {"error": str(e)}

    def record_ab_test(self, scan_id: str, model_a_id: str, model_a_verdict: str,
                       model_b_id: str, model_b_verdict: str, ground_truth: Optional[str] = None) -> bool:
        """Record A/B test result for a scan."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO ab_test_results
                (scan_id, model_a_id, model_a_verdict, model_b_id, model_b_verdict, ground_truth)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, model_a_id, model_a_verdict, model_b_id, model_b_verdict, ground_truth))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.error("record_ab_test_failed", error=str(e))
            return False

    def get_ab_test_results(self, model_b_id: str, limit: int = 100) -> Dict:
        """Get A/B test results for a model candidate."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row

            rows = conn.execute("""
                SELECT model_a_verdict, model_b_verdict, ground_truth
                FROM ab_test_results
                WHERE model_b_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (model_b_id, limit)).fetchall()

            conn.close()

            results = [dict(r) for r in rows]

            # Calculate metrics if ground truth available
            if results and any(r.get("ground_truth") for r in results):
                model_b_correct = sum(1 for r in results
                                     if r.get("ground_truth") == r.get("model_b_verdict"))
                model_a_correct = sum(1 for r in results
                                     if r.get("ground_truth") == r.get("model_a_verdict"))

                return {
                    "total_tests": len(results),
                    "model_a_accuracy": model_a_correct / len(results) if results else 0,
                    "model_b_accuracy": model_b_correct / len(results) if results else 0,
                    "model_b_wins": model_b_correct > model_a_correct,
                    "raw_results": results,
                }

            return {"total_tests": len(results), "raw_results": results}
        except Exception as e:
            log.error("get_ab_test_results_failed", error=str(e))
            return {"error": str(e)}

    def record_model_performance(self, model_id: str, accuracy: float, precision: float,
                                 recall: float, f1_score: float, scans_evaluated: int) -> bool:
        """Record weekly performance metrics for a model."""
        try:
            from datetime import date
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO model_performance
                (model_id, metric_date, accuracy, precision, recall, f1_score, scans_evaluated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (model_id, date.today().isoformat(), accuracy, precision, recall, f1_score, scans_evaluated))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            log.error("record_model_performance_failed", error=str(e))
            return False


# Singleton instance
_manager = None


def get_model_manager() -> MLModelManager:
    """Get or create the global model manager instance."""
    global _manager
    if _manager is None:
        _manager = MLModelManager()
    return _manager


def classify_url(url: str, model_id: Optional[str] = None) -> Dict:
    """
    Classify a URL as phishing or legitimate using the active model.

    Returns:
        {
            "url": str,
            "verdict": "CLEAN" | "SUSPICIOUS",
            "score": float (0-10),
            "confidence": float (0-1),
            "model_id": str,
            "model_version": str,
        }
    """
    try:
        from urllib.parse import urlparse
        import numpy as np

        manager = get_model_manager()
        model = manager.load_model(model_id)

        if not model:
            return {
                "url": url,
                "verdict": "UNKNOWN",
                "score": 0,
                "confidence": 0,
                "error": "No model available",
            }

        # Extract features (matching train_model_advanced.py)
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except:
            host = ""

        url_lower = url.lower()
        PHISHING_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".xyz", ".top",
                        ".click", ".download", ".website", ".space", ".online", ".site"]
        SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "bank", "paypal",
                           "update", "confirm", "urgent", "action", "required"]

        features = [
            len(url),
            url.count("."),
            url.count("-"),
            sum(c.isdigit() for c in host),
            int("@" in url),
            int(url.startswith("https")),
            int(any(url_lower.endswith(t) or f"{t}/" in url_lower for t in PHISHING_TLDS)),
            1.0,  # Domain age (fixed for classification)
            int(any(w in url_lower for w in SUSPICIOUS_WORDS)),
            int(any(t in url_lower for t in ["g00gle", "amaz0n", "faсebook"])),
            int("xn--" in url_lower),
            max(0, host.count(".") - 1),
            len(parsed.path) if parsed else 0,
            url.count("="),
            int(url.count("/") > 3),
            int("redirect" in url_lower or "next=" in url_lower),
            int(len(host) > 50),
            int(url.count("%") > 0),
            int(url.count("?") > 2),
            sum(1 for c in url if not c.isalnum() and c not in '.-:/?'),
        ]

        features = np.array(features[:20], dtype=np.float32)

        # Classify using stumps
        stumps = model.get("stumps", [])
        if not stumps:
            return {
                "url": url,
                "verdict": "UNKNOWN",
                "score": 0,
                "error": "Model has no stumps",
            }

        score = 0
        for feat, thresh, _ in stumps:
            if features[feat] > thresh:
                score += 1

        # Normalize to 0-10 scale
        normalized_score = (score / len(stumps)) * 10.0

        verdict = "SUSPICIOUS" if normalized_score >= 5.0 else "CLEAN"
        confidence = min(abs(normalized_score - 5.0) / 5.0, 1.0)

        return {
            "url": url,
            "verdict": verdict,
            "score": round(normalized_score, 2),
            "confidence": round(confidence, 3),
            "model_id": model_id or "active",
            "model_version": model.get("accuracy", 0),
        }

    except Exception as e:
        log.error("classify_url_failed", url=url, error=str(e))
        return {
            "url": url,
            "verdict": "UNKNOWN",
            "score": 0,
            "error": str(e),
        }
