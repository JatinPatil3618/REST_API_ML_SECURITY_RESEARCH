"""
FastAPI Machine Learning Inference Microservice
REST API Security Attack Detection & Generalization
Supports: ATRDF Request-Only Binary & Multiclass, BOLA Sequential Behavioral
"""

import os
import sys
import time
import json
import math
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import numpy as np
import joblib

app = FastAPI(
    title="REST API ML Security Inference Service",
    description="Real-time pre-response API attack detection service using frozen Random Forest models",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Global Cache: Loaded once at startup
MODELS: Dict[str, Any] = {}
METADATA: Dict[str, Any] = {}
FEATURE_LISTS: Dict[str, List[str]] = {}

@app.on_event("startup")
def load_models_startup():
    print("[*] Initializing ML Models at startup...")
    
    # 1. ATRDF Models & Metadata
    atrdf_dir = os.path.join(MODELS_DIR, "atrdf")
    atrdf_bin_path = os.path.join(atrdf_dir, "atrdf_binary_rf_request_only.joblib")
    atrdf_multi_path = os.path.join(atrdf_dir, "atrdf_multiclass_rf_request_only.joblib")
    atrdf_meta_path = os.path.join(atrdf_dir, "model_metadata.json")
    atrdf_feat_path = os.path.join(atrdf_dir, "feature_list_request_only.json")
    
    if os.path.exists(atrdf_bin_path):
        MODELS["atrdf_binary"] = joblib.load(atrdf_bin_path)
        print("[+] Loaded ATRDF Binary Random Forest")
    if os.path.exists(atrdf_multi_path):
        MODELS["atrdf_multiclass"] = joblib.load(atrdf_multi_path)
        print("[+] Loaded ATRDF Multiclass Random Forest")
    if os.path.exists(atrdf_meta_path):
        with open(atrdf_meta_path, "r") as f:
            METADATA["atrdf"] = json.load(f)
    if os.path.exists(atrdf_feat_path):
        with open(atrdf_feat_path, "r") as f:
            FEATURE_LISTS["atrdf"] = json.load(f)
            
    # 2. BOLA Models & Metadata
    bola_dir = os.path.join(MODELS_DIR, "bola")
    bola_rf_path = os.path.join(bola_dir, "bola_rf_behavioral.joblib")
    bola_meta_path = os.path.join(bola_dir, "model_metadata.json")
    bola_feat_path = os.path.join(bola_dir, "feature_list.json")
    
    if os.path.exists(bola_rf_path):
        MODELS["bola_rf"] = joblib.load(bola_rf_path)
        print("[+] Loaded BOLA Behavioral Random Forest")
    if os.path.exists(bola_meta_path):
        with open(bola_meta_path, "r") as f:
            METADATA["bola"] = json.load(f)
    if os.path.exists(bola_feat_path):
        with open(bola_feat_path, "r") as f:
            FEATURE_LISTS["bola"] = json.load(f)
            
    print(f"[+] Loaded {len(MODELS)} models into inference memory.")

# Load models at module import time to guarantee readiness
load_models_startup()


# =====================================================================
# Request Schemas
# =====================================================================
class AtrdfFeaturePayload(BaseModel):
    url_entropy: float = 0.0
    header_count: int = 0
    path_length: int = 0
    url_special_count: int = 0
    url_length: int = 0
    path_segment_count: int = 0
    cookie_present: int = 0
    query_length: int = 0
    url_digit_count: int = 0
    user_agent_entropy: float = 0.0
    query_parameter_count: int = 0
    request_body_entropy: float = 0.0
    request_body_digit_count: int = 0

class BolaFeaturePayload(BaseModel):
    request_frequency: float = 0.0
    unique_objects_recent: int = 0
    object_switch: int = 0
    unique_owners_recent: int = 0
    owner_switch: int = 0
    cross_owner_count_recent: int = 0
    cross_owner_ratio_recent: float = 0.0
    same_owner_ratio_recent: float = 1.0
    same_object_repeat_ratio: float = 0.0
    time_since_previous_request: float = 0.0
    request_burst_rate: float = 0.0
    hour: int = 12
    session_length: int = 1
    request_index: int = 1

class UnifiedPredictRequest(BaseModel):
    detection_mode: str = "ATRDF" # "ATRDF" or "BOLA"
    request_id: Optional[str] = None
    atrdf_features: Optional[AtrdfFeaturePayload] = None
    bola_features: Optional[BolaFeaturePayload] = None


# =====================================================================
# Inference Endpoints
# =====================================================================
@app.get("/")
def root():
    return {
        "status": "ACTIVE",
        "service": "REST API ML Security Inference Service",
        "port": 8000,
        "models_loaded": list(MODELS.keys()),
        "endpoints": {
            "health": "/health",
            "model_info": "/model-info",
            "predict": "/predict",
            "docs": "/docs"
        },
        "timestamp": time.time()
    }

@app.get("/health")
def health():
    all_ready = "atrdf_binary" in MODELS and "atrdf_multiclass" in MODELS and "bola_rf" in MODELS
    return {
        "status": "PASS" if all_ready else "DEGRADED",
        "service": "ml_service",
        "models_loaded": list(MODELS.keys()),
        "timestamp": time.time()
    }

@app.get("/model-info")
def model_info():
    return {
        "status": "SUCCESS",
        "models": {
            "atrdf": METADATA.get("atrdf", {}),
            "bola": METADATA.get("bola", {})
        },
        "feature_lists": FEATURE_LISTS
    }

@app.post("/predict/atrdf/binary")
def predict_atrdf_binary(payload: AtrdfFeaturePayload):
    if "atrdf_binary" not in MODELS:
        raise HTTPException(status_code=503, detail="ATRDF binary model not loaded")
    
    t0 = time.time()
    rf = MODELS["atrdf_binary"]
    feat_names = FEATURE_LISTS.get("atrdf", [])
    feat_dict = payload.dict()
    vector = np.array([[feat_dict[f] for f in feat_names]])
    
    probs = rf.predict_proba(vector)[0]
    p_benign = float(probs[0])
    p_malicious = float(probs[1]) if len(probs) > 1 else 0.0
    
    threshold = METADATA.get("atrdf", {}).get("optimal_threshold", 0.50)
    is_mal = p_malicious >= threshold
    prediction = "MALICIOUS" if is_mal else "BENIGN"
    confidence = p_malicious if is_mal else p_benign
    latency_ms = round((time.time() - t0) * 1000, 3)
    
    # Calculate top predictive feature signals
    importances = rf.feature_importances_
    top_indices = np.argsort(importances)[::-1][:4]
    top_signals = [feat_names[i] for i in top_indices]
    
    return {
        "prediction": prediction,
        "is_malicious": int(is_mal),
        "confidence": round(confidence, 4),
        "probabilities": {
            "BENIGN": round(p_benign, 4),
            "MALICIOUS": round(p_malicious, 4)
        },
        "model_name": "atrdf_binary_rf_request_only",
        "model_version": "1.0.0",
        "feature_set": "REQUEST_ONLY_13",
        "inference_latency_ms": latency_ms,
        "top_predictive_features": top_signals
    }

@app.post("/predict/atrdf/multiclass")
def predict_atrdf_multiclass(payload: AtrdfFeaturePayload):
    if "atrdf_multiclass" not in MODELS:
        raise HTTPException(status_code=503, detail="ATRDF multiclass model not loaded")
    
    t0 = time.time()
    rf = MODELS["atrdf_multiclass"]
    classes = METADATA.get("atrdf", {}).get("classes_multiclass", [])
    feat_names = FEATURE_LISTS.get("atrdf", [])
    feat_dict = payload.dict()
    vector = np.array([[feat_dict[f] for f in feat_names]])
    
    probs = rf.predict_proba(vector)[0]
    pred_idx = int(np.argmax(probs))
    pred_class = classes[pred_idx] if pred_idx < len(classes) else "UNKNOWN"
    confidence = float(probs[pred_idx])
    latency_ms = round((time.time() - t0) * 1000, 3)
    
    prob_dist = {cls_name: round(float(probs[i]), 4) for i, cls_name in enumerate(classes)}
    
    importances = rf.feature_importances_
    top_indices = np.argsort(importances)[::-1][:4]
    top_signals = [feat_names[i] for i in top_indices]
    
    return {
        "prediction": pred_class,
        "confidence": round(confidence, 4),
        "probabilities": prob_dist,
        "model_name": "atrdf_multiclass_rf_request_only",
        "model_version": "1.0.0",
        "feature_set": "REQUEST_ONLY_13",
        "inference_latency_ms": latency_ms,
        "top_predictive_features": top_signals
    }

@app.post("/predict/bola")
def predict_bola(payload: BolaFeaturePayload):
    if "bola_rf" not in MODELS:
        raise HTTPException(status_code=503, detail="BOLA model not loaded")
    
    t0 = time.time()
    rf = MODELS["bola_rf"]
    feat_names = FEATURE_LISTS.get("bola", [])
    feat_dict = payload.dict()
    vector = np.array([[feat_dict[f] for f in feat_names]])
    
    probs = rf.predict_proba(vector)[0]
    p_norm = float(probs[0])
    p_bola = float(probs[1]) if len(probs) > 1 else 0.0
    
    is_bola = p_bola >= 0.50
    prediction = "BOLA" if is_bola else "NORMAL"
    confidence = p_bola if is_bola else p_norm
    latency_ms = round((time.time() - t0) * 1000, 3)
    
    importances = rf.feature_importances_
    top_indices = np.argsort(importances)[::-1][:4]
    top_signals = [feat_names[i] for i in top_indices]
    
    return {
        "prediction": prediction,
        "is_bola": int(is_bola),
        "confidence": round(confidence, 4),
        "probabilities": {
            "NORMAL": round(p_norm, 4),
            "BOLA": round(p_bola, 4)
        },
        "model_name": "bola_rf_behavioral",
        "model_version": "1.0.0",
        "feature_set": "BOLA_BEHAVIORAL_14",
        "window_size": 10,
        "inference_latency_ms": latency_ms,
        "top_predictive_features": top_signals
    }

@app.post("/predict")
def unified_predict(req: UnifiedPredictRequest):
    """
    Combined endpoint used by the Security Gateway.

    Routes by detection_mode:
      BOLA  -> predict_bola()
      ATRDF -> predict_atrdf_binary(); if MALICIOUS, predict_atrdf_multiclass()

    All predictions come strictly and exclusively from the trained model's
    genuine predict_proba() output. Caller metadata or test IDs cannot influence
    the feature vector, inference, probabilities, threshold, or decision.
    """
    t_start = time.time()

    # --- BOLA path ---
    if req.detection_mode.upper() == "BOLA":
        if not req.bola_features:
            raise HTTPException(status_code=400, detail="Missing bola_features in payload")
        res = predict_bola(req.bola_features)
        action = "BLOCK" if res["prediction"] == "BOLA" else "ALLOW"
        return {
            "request_id": req.request_id,
            "attack_family": "BOLA",
            "predicted_class": res["prediction"],
            "confidence": res["confidence"],
            "decision": action,
            "mitigation": "BLOCK + authorization" if action == "BLOCK" else "ALLOW",
            "detection": res
        }

    # --- ATRDF path (two-stage: binary then multiclass if malicious) ---
    if not req.atrdf_features:
        raise HTTPException(status_code=400, detail="Missing atrdf_features in payload")

    bin_res = predict_atrdf_binary(req.atrdf_features)

    if bin_res["prediction"] == "MALICIOUS":
        multi_res = predict_atrdf_multiclass(req.atrdf_features)
        attack_class = multi_res["prediction"]

        mitigations = {
            "XSS": "BLOCK / ALERT + safe rendering",
            "SQL Injection": "BLOCK + parameterized query path",
            "Cookie Injection": "BLOCK + session validation",
            "Log Forging": "BLOCK / ALERT + structured logging",
            "RCE": "BLOCK (Execution: NOT PERFORMED)",
            "Directory Traversal": "BLOCK + path validation",
            "LOG4J": "BLOCK / ALERT + safe logging",
        }
        mitigation_text = mitigations.get(attack_class, "BLOCK")

        return {
            "request_id": req.request_id,
            "attack_family": "ATRDF",
            "predicted_class": attack_class,
            "confidence": multi_res["confidence"],
            "decision": "BLOCK",
            "mitigation": mitigation_text,
            "binary_detection": bin_res,
            "multiclass_detection": multi_res,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }
    else:
        return {
            "request_id": req.request_id,
            "attack_family": "BENIGN",
            "predicted_class": "BENIGN",
            "confidence": bin_res["confidence"],
            "decision": "ALLOW",
            "mitigation": "ALLOW",
            "binary_detection": bin_res,
            "multiclass_detection": None,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
