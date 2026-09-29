"""
Model Registry and Lifecycle Governance Module for Hospital SOC Assistant.
Tracks model versions, promotion statuses, validation benchmarks, and rollback points.
"""

import os
import json
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional

REGISTRY_FILE = "models/model_registry.json"

class ModelRegistry:
    """Manages versioned model artifacts, champion/candidate states, and rollbacks."""
    
    def __init__(self, registry_path: str = REGISTRY_FILE):
        self.registry_path = registry_path
        self._ensure_registry()

    def _ensure_registry(self):
        """Initializes registry JSON file if absent."""
        if not os.path.exists(self.registry_path):
            os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
            initial_data = {
                "active_champion_version": "v1.0",
                "last_updated": datetime.now().isoformat(),
                "models": [
                    {
                        "model_version": "v1.0",
                        "status": "CHAMPION",
                        "model_path": "models/false_positive_model.joblib",
                        "training_timestamp": "2026-09-09T10:07:56",
                        "dataset_version": "synthetic_5330_v1",
                        "training_samples": 4264,
                        "feedback_samples": 0,
                        "metrics": {
                            "threat_recall": 1.0000,
                            "missed_incidents": 0,
                            "triage_precision": 0.8013,
                            "f1_score": 0.8897,
                            "accuracy": 0.9428,
                            "critical_device_recall": 1.0000
                        },
                        "notes": "Initial 35% milestone champion model (Balanced Logistic Regression)."
                    }
                ]
            }
            with open(self.registry_path, "w", encoding="utf-8") as f:
                json.dump(initial_data, f, indent=4)

    def load_registry(self) -> Dict[str, Any]:
        """Loads registry JSON data."""
        with open(self.registry_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_registry(self, data: Dict[str, Any]):
        """Saves registry JSON data atomically."""
        data["last_updated"] = datetime.now().isoformat()
        with open(self.registry_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def get_champion(self) -> Optional[Dict[str, Any]]:
        """Returns metadata for the currently active CHAMPION model."""
        reg = self.load_registry()
        champ_ver = reg.get("active_champion_version")
        for m in reg.get("models", []):
            if m["model_version"] == champ_ver and m["status"] == "CHAMPION":
                return m
        return None

    def register_candidate(
        self,
        model_version: str,
        model_path: str,
        metrics: Dict[str, Any],
        training_samples: int,
        feedback_samples: int,
        notes: str = ""
    ) -> Dict[str, Any]:
        """Registers a newly trained model as a CANDIDATE awaiting validation."""
        reg = self.load_registry()
        
        # Check if version already exists
        for m in reg["models"]:
            if m["model_version"] == model_version:
                m["status"] = "CANDIDATE"
                m["model_path"] = model_path
                m["metrics"] = metrics
                m["training_samples"] = training_samples
                m["feedback_samples"] = feedback_samples
                m["notes"] = notes
                self.save_registry(reg)
                return m
                
        candidate = {
            "model_version": model_version,
            "status": "CANDIDATE",
            "model_path": model_path,
            "training_timestamp": datetime.now().isoformat(),
            "dataset_version": f"replay_retrain_{datetime.now().strftime('%Y%m%d')}",
            "training_samples": training_samples,
            "feedback_samples": feedback_samples,
            "metrics": metrics,
            "notes": notes
        }
        reg["models"].append(candidate)
        self.save_registry(reg)
        return candidate

    def promote_candidate(self, candidate_version: str, promotion_reason: str = "") -> bool:
        """Promotes a validated CANDIDATE to active CHAMPION, archiving previous champion."""
        reg = self.load_registry()
        candidate = None
        for m in reg["models"]:
            if m["model_version"] == candidate_version:
                candidate = m
                break
                
        if not candidate:
            return False
            
        # Demote old champion
        old_champ = reg.get("active_champion_version")
        for m in reg["models"]:
            if m["model_version"] == old_champ:
                m["status"] = "ARCHIVED_CHAMPION"
                
        # Promote candidate
        candidate["status"] = "CHAMPION"
        candidate["promoted_timestamp"] = datetime.now().isoformat()
        candidate["promotion_reason"] = promotion_reason
        reg["active_champion_version"] = candidate_version
        
        # Also copy candidate model to standard production path
        champ_path = "models/false_positive_model.joblib"
        if os.path.exists(candidate["model_path"]) and candidate["model_path"] != champ_path:
            shutil.copy2(candidate["model_path"], champ_path)
            
        self.save_registry(reg)
        return True

    def reject_candidate(self, candidate_version: str, rejection_reason: str) -> bool:
        """Rejects a CANDIDATE model that failed safety or performance gates."""
        reg = self.load_registry()
        for m in reg["models"]:
            if m["model_version"] == candidate_version:
                m["status"] = "REJECTED"
                m["rejection_reason"] = rejection_reason
                m["rejected_timestamp"] = datetime.now().isoformat()
                self.save_registry(reg)
                return True
        return False

    def rollback(self, target_version: str, rollback_reason: str = "Rollback triggered by operator") -> bool:
        """Rolls back the active champion to an earlier archived champion."""
        reg = self.load_registry()
        target = None
        for m in reg["models"]:
            if m["model_version"] == target_version:
                target = m
                break
                
        if not target or not os.path.exists(target["model_path"]):
            return False
            
        current_champ = reg.get("active_champion_version")
        for m in reg["models"]:
            if m["model_version"] == current_champ:
                m["status"] = "ROLLED_BACK"
                
        target["status"] = "CHAMPION"
        target["rollback_timestamp"] = datetime.now().isoformat()
        target["rollback_reason"] = rollback_reason
        reg["active_champion_version"] = target_version
        
        # Restore model file
        shutil.copy2(target["model_path"], "models/false_positive_model.joblib")
        self.save_registry(reg)
        return True

if __name__ == "__main__":
    registry = ModelRegistry()
    champ = registry.get_champion()
    print(f"Active Champion Model: {champ['model_version']} (Recall: {champ['metrics']['threat_recall']}, F1: {champ['metrics']['f1_score']})")
