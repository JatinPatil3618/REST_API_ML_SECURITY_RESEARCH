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

from jndi_lookup import (
    ATTACK_CLASSES,
    EXPERIMENTAL_FEATURES,
    EXPERIMENTAL_THRESHOLD,
    PROFILE_EXPERIMENTAL,
    PROFILE_PRODUCTION,
)
from payload_features import (
    PAYLOAD_THRESHOLD,
    PROFILE_PAYLOAD,
    REQUEST_ONLY_10,
    REQUEST_ONLY_13,
    SCOPED_ATTACKS,
)
from mitigations import describe as mitigation_describe
from pattern_reinforcement import (
    ATRDF_FEATURES as SPR_ATRDF_FEATURES,
    BOLA_FEATURES as SPR_BOLA_FEATURES,
    PROFILE_SPR,
    load_spr,
    save_spr,
)

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

    experimental_dir = os.path.join(
        BASE_DIR, "research", "atrdf_header_count_ablation", "jndi_feature_experiment", "augmented"
    )
    experimental_bin_path = os.path.join(experimental_dir, "candidate_binary_rf_jndi_augmented.joblib")
    experimental_multi_path = os.path.join(experimental_dir, "candidate_multiclass_rf_jndi_augmented.joblib")
    try:
        if os.path.exists(experimental_bin_path) and os.path.exists(experimental_multi_path):
            experimental_binary = joblib.load(experimental_bin_path)
            experimental_multi = joblib.load(experimental_multi_path)
            binary_classes = [int(value) for value in experimental_binary.classes_]
            multi_classes = [int(value) for value in experimental_multi.classes_]
            if (
                binary_classes == [0, 1]
                and experimental_binary.n_features_in_ == 14
                and multi_classes == list(range(7))
                and experimental_multi.n_features_in_ == 14
            ):
                MODELS["atrdf_binary_experimental"] = experimental_binary
                MODELS["atrdf_multiclass_experimental"] = experimental_multi
                FEATURE_LISTS["atrdf_experimental"] = list(EXPERIMENTAL_FEATURES)
                print("[+] Loaded experimental 14-feature ATRDF candidate")
            else:
                print("[!] Experimental ATRDF candidate failed feature or class verification and was not installed")
    except Exception as exc:
        print(f"[!] Experimental ATRDF candidate was not loaded: {exc}")

    payload_candidates = [
        (
            os.path.join(MODELS_DIR, "atrdf_six"),
            "candidate_binary_rf_six_heldout.joblib",
            "candidate_multiclass_rf_six_heldout.joblib",
            list(REQUEST_ONLY_10),
            "held-out 10-feature six-family ATRDF candidate",
        ),
        (
            os.path.join(BASE_DIR, "research", "atrdf_payload_experiment", "heldout_six"),
            "candidate_binary_rf_six_heldout.joblib",
            "candidate_multiclass_rf_six_heldout.joblib",
            list(REQUEST_ONLY_10),
            "held-out 10-feature six-family ATRDF candidate (research copy)",
        ),
    ]
    for payload_dir, bin_name, multi_name, feature_names, label in payload_candidates:
        payload_bin_path = os.path.join(payload_dir, bin_name)
        payload_multi_path = os.path.join(payload_dir, multi_name)
        if "atrdf_binary_payload" in MODELS:
            break
        try:
            if os.path.exists(payload_bin_path) and os.path.exists(payload_multi_path):
                payload_binary = joblib.load(payload_bin_path)
                payload_multi = joblib.load(payload_multi_path)
                binary_classes = [int(value) for value in payload_binary.classes_]
                multi_classes = [int(value) for value in payload_multi.classes_]
                if (
                    binary_classes == [0, 1]
                    and payload_binary.n_features_in_ == len(feature_names)
                    and multi_classes == list(range(len(SCOPED_ATTACKS)))
                    and payload_multi.n_features_in_ == len(feature_names)
                ):
                    MODELS["atrdf_binary_payload"] = payload_binary
                    MODELS["atrdf_multiclass_payload"] = payload_multi
                    FEATURE_LISTS["atrdf_payload"] = list(feature_names)
                    print("[+] Loaded " + label)
                else:
                    print("[!] Payload ATRDF candidate failed feature or class verification: " + label)
        except Exception as exc:
            print(f"[!] Payload ATRDF candidate was not loaded ({label}): {exc}")
    if "atrdf_binary_payload" not in MODELS:
        raise RuntimeError(
            "Held-out six-family ATRDF models were not loaded. "
            "Expected models/atrdf_six/candidate_binary_rf_six_heldout.joblib"
        )

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
            
    spr_dir = os.path.join(MODELS_DIR, "spr")
    spr_atrdf_path = os.path.join(spr_dir, "atrdf_spr.joblib")
    spr_bola_path = os.path.join(spr_dir, "bola_spr.joblib")
    try:
        if os.path.exists(spr_atrdf_path):
            MODELS["atrdf_spr"] = load_spr(spr_atrdf_path)
            FEATURE_LISTS["atrdf_spr"] = list(SPR_ATRDF_FEATURES)
            print("[+] Loaded ATRDF Sequential Pattern Reinforcer")
        if os.path.exists(spr_bola_path):
            MODELS["bola_spr"] = load_spr(spr_bola_path)
            FEATURE_LISTS["bola_spr"] = list(SPR_BOLA_FEATURES)
            print("[+] Loaded BOLA Sequential Pattern Reinforcer")
        if os.path.exists(os.path.join(spr_dir, "model_metadata.json")):
            with open(os.path.join(spr_dir, "model_metadata.json"), "r") as f:
                METADATA["spr"] = json.load(f)
    except Exception as exc:
        print(f"[!] SPR models were not loaded: {exc}")

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
    jndi_lookup_marker: int = 0
    sql_structure: int = 0
    markup_script: int = 0
    path_traversal: int = 0
    command_chain: int = 0
    cookie_signal: int = 0
    log_control: int = 0
    jndi_lookup: int = 0

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
    model_profile: str = PROFILE_PRODUCTION
    request_id: Optional[str] = None
    atrdf_features: Optional[AtrdfFeaturePayload] = None
    bola_features: Optional[BolaFeaturePayload] = None

class FeedbackRequest(BaseModel):
    detection_mode: str = "ATRDF"
    label: str
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
            "bola": METADATA.get("bola", {}),
            "spr": METADATA.get("spr", {}),
        },
        "feature_lists": FEATURE_LISTS,
        "spr_memory": {
            "atrdf": MODELS["atrdf_spr"].prototype_summary() if "atrdf_spr" in MODELS else None,
            "bola": MODELS["bola_spr"].prototype_summary() if "bola_spr" in MODELS else None,
        },
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

    profile = (req.model_profile or PROFILE_PRODUCTION).strip().lower()

    # --- BOLA path ---
    if req.detection_mode.upper() == "BOLA":
        if not req.bola_features:
            raise HTTPException(status_code=400, detail="Missing bola_features in payload")
        if profile == PROFILE_SPR:
            return predict_spr_bola(req, t_start)
        res = predict_bola(req.bola_features)
        action = "BLOCK" if res["prediction"] == "BOLA" else "ALLOW"
        return with_mitigation({
            "request_id": req.request_id,
            "attack_family": "BOLA",
            "predicted_class": res["prediction"],
            "confidence": res["confidence"],
            "decision": action,
            "detection": res
        }, res["prediction"] if action == "BLOCK" else "BENIGN")

    # --- ATRDF path (two-stage: binary then multiclass if malicious) ---
    if not req.atrdf_features:
        raise HTTPException(status_code=400, detail="Missing atrdf_features in payload")

    if profile == PROFILE_EXPERIMENTAL:
        return predict_experimental_atrdf(req, t_start)
    if profile == PROFILE_PAYLOAD:
        return predict_payload_atrdf(req, t_start)
    if profile == PROFILE_SPR:
        return predict_spr_atrdf(req, t_start)
    if profile != PROFILE_PRODUCTION:
        raise HTTPException(status_code=400, detail="Unknown model_profile")

    bin_res = predict_atrdf_binary(req.atrdf_features)

    if bin_res["prediction"] == "MALICIOUS":
        multi_res = predict_atrdf_multiclass(req.atrdf_features)
        attack_class = multi_res["prediction"]

        return with_mitigation({
            "request_id": req.request_id,
            "attack_family": "ATRDF",
            "predicted_class": attack_class,
            "confidence": multi_res["confidence"],
            "decision": "BLOCK",
            "binary_detection": bin_res,
            "multiclass_detection": multi_res,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }, attack_class)
    else:
        return with_mitigation({
            "request_id": req.request_id,
            "attack_family": "BENIGN",
            "predicted_class": "BENIGN",
            "confidence": bin_res["confidence"],
            "decision": "ALLOW",
            "binary_detection": bin_res,
            "multiclass_detection": None,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }, "BENIGN")

def payload_vector(payload: AtrdfFeaturePayload):
    feat_dict = payload.dict() if hasattr(payload, "dict") else payload.model_dump()
    names = FEATURE_LISTS.get("atrdf_payload") or list(REQUEST_ONLY_10)
    missing = [name for name in names if name not in feat_dict]
    if missing:
        raise HTTPException(status_code=400, detail="Missing payload ATRDF features")
    return np.array([[feat_dict[name] for name in names]])


def predict_payload_atrdf(req: UnifiedPredictRequest, t_start: float):
    """Score the six-family review candidate. Threshold stays 0.50."""
    if "atrdf_binary_payload" not in MODELS or "atrdf_multiclass_payload" not in MODELS:
        raise HTTPException(status_code=503, detail="Payload ATRDF candidate is not loaded")

    vector = payload_vector(req.atrdf_features)
    binary_model = MODELS["atrdf_binary_payload"]
    feature_names = FEATURE_LISTS.get("atrdf_payload") or list(REQUEST_ONLY_10)
    probs = binary_model.predict_proba(vector)[0]
    p_benign = float(probs[0])
    p_malicious = float(probs[1]) if len(probs) > 1 else 0.0
    is_malicious = p_malicious >= PAYLOAD_THRESHOLD
    binary_result = {
        "prediction": "MALICIOUS" if is_malicious else "BENIGN",
        "confidence": round(p_malicious if is_malicious else p_benign, 4),
        "probabilities": {"BENIGN": round(p_benign, 4), "MALICIOUS": round(p_malicious, 4)},
        "model_name": "candidate_binary_rf_six_heldout",
        "feature_set": "REQUEST_ONLY_10",
        "threshold": PAYLOAD_THRESHOLD,
    }
    if not is_malicious:
        return with_mitigation({
            "request_id": req.request_id,
            "attack_family": "BENIGN",
            "predicted_class": "BENIGN",
            "confidence": binary_result["confidence"],
            "decision": "ALLOW",
            "model_profile": PROFILE_PAYLOAD,
            "binary_detection": binary_result,
            "multiclass_detection": None,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }, "BENIGN")

    multi_model = MODELS["atrdf_multiclass_payload"]
    multi_probs = multi_model.predict_proba(vector)[0]
    pred_idx = int(np.argmax(multi_probs))
    if pred_idx < 0 or pred_idx >= len(SCOPED_ATTACKS):
        raise HTTPException(status_code=500, detail="Payload multiclass index is outside the six supported classes")
    attack_class = SCOPED_ATTACKS[pred_idx]
    multi_result = {
        "prediction": attack_class,
        "confidence": round(float(multi_probs[pred_idx]), 4),
        "probabilities": {
            name: round(float(multi_probs[index]), 4) for index, name in enumerate(SCOPED_ATTACKS)
        },
        "model_name": "candidate_multiclass_rf_six_heldout",
        "feature_set": "REQUEST_ONLY_10",
    }
    return with_mitigation({
        "request_id": req.request_id,
        "attack_family": "ATRDF",
        "predicted_class": attack_class,
        "confidence": multi_result["confidence"],
        "decision": "BLOCK",
        "model_profile": PROFILE_PAYLOAD,
        "binary_detection": binary_result,
        "multiclass_detection": multi_result,
        "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
    }, attack_class)


def experimental_vector(payload: AtrdfFeaturePayload):
    feat_dict = payload.dict()
    missing = [name for name in EXPERIMENTAL_FEATURES if name not in feat_dict]
    if missing:
        raise HTTPException(status_code=400, detail="Missing experimental ATRDF features")
    return np.array([[feat_dict[name] for name in EXPERIMENTAL_FEATURES]])


def predict_experimental_atrdf(req: UnifiedPredictRequest, t_start: float):
    """Score the augmented 14-feature candidate. The marker is one model input, not a block rule."""
    if "atrdf_binary_experimental" not in MODELS or "atrdf_multiclass_experimental" not in MODELS:
        raise HTTPException(status_code=503, detail="Experimental ATRDF candidate is not loaded")

    vector = experimental_vector(req.atrdf_features)
    binary_model = MODELS["atrdf_binary_experimental"]
    probs = binary_model.predict_proba(vector)[0]
    p_benign = float(probs[0])
    p_malicious = float(probs[1]) if len(probs) > 1 else 0.0
    is_malicious = p_malicious >= EXPERIMENTAL_THRESHOLD
    binary_result = {
        "prediction": "MALICIOUS" if is_malicious else "BENIGN",
        "confidence": round(p_malicious if is_malicious else p_benign, 4),
        "probabilities": {"BENIGN": round(p_benign, 4), "MALICIOUS": round(p_malicious, 4)},
        "model_name": "candidate_binary_rf_jndi_augmented",
        "feature_set": "REQUEST_ONLY_14_JNDI",
        "threshold": EXPERIMENTAL_THRESHOLD,
    }
    if not is_malicious:
        return with_mitigation({
            "request_id": req.request_id,
            "attack_family": "BENIGN",
            "predicted_class": "BENIGN",
            "confidence": binary_result["confidence"],
            "decision": "ALLOW",
            "model_profile": PROFILE_EXPERIMENTAL,
            "binary_detection": binary_result,
            "multiclass_detection": None,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }, "BENIGN")

    multi_model = MODELS["atrdf_multiclass_experimental"]
    multi_probs = multi_model.predict_proba(vector)[0]
    pred_idx = int(np.argmax(multi_probs))
    if pred_idx < 0 or pred_idx >= len(ATTACK_CLASSES):
        raise HTTPException(status_code=500, detail="Experimental multiclass index is outside 0-6")
    attack_class = ATTACK_CLASSES[pred_idx]
    multi_result = {
        "prediction": attack_class,
        "confidence": round(float(multi_probs[pred_idx]), 4),
        "probabilities": {
            name: round(float(multi_probs[index]), 4) for index, name in enumerate(ATTACK_CLASSES)
        },
        "model_name": "candidate_multiclass_rf_jndi_augmented",
        "feature_set": "REQUEST_ONLY_14_JNDI",
    }
    return with_mitigation({
        "request_id": req.request_id,
        "attack_family": "ATRDF",
        "predicted_class": attack_class,
        "confidence": multi_result["confidence"],
        "decision": "BLOCK",
        "model_profile": PROFILE_EXPERIMENTAL,
        "binary_detection": binary_result,
        "multiclass_detection": multi_result,
        "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
    }, attack_class)


def with_mitigation(payload, predicted_class):
    info = mitigation_describe(predicted_class)
    payload["mitigation"] = info["mitigation"]
    payload["mitigation_techniques"] = info["techniques"]
    return payload


def _payload_dict(payload):
    return payload.dict() if hasattr(payload, "dict") else payload.model_dump()


def spr_atrdf_vector(payload: AtrdfFeaturePayload):
    feat_dict = _payload_dict(payload)
    return np.array([[feat_dict[name] for name in SPR_ATRDF_FEATURES]], dtype=float)


def spr_bola_vector(payload: BolaFeaturePayload):
    feat_dict = _payload_dict(payload)
    return np.array([[feat_dict[name] for name in SPR_BOLA_FEATURES]], dtype=float)


def predict_spr_atrdf(req: UnifiedPredictRequest, t_start: float):
    if "atrdf_spr" not in MODELS:
        raise HTTPException(status_code=503, detail="ATRDF pattern-reinforcement model is not loaded")
    spr = MODELS["atrdf_spr"]
    vector = spr_atrdf_vector(req.atrdf_features)
    decision = spr.decide(vector)
    score = decision["score"]
    is_malicious = decision["positive"]
    binary_result = {
        "prediction": "MALICIOUS" if is_malicious else "BENIGN",
        "confidence": round(score if is_malicious else 1.0 - score, 4),
        "probabilities": {"BENIGN": round(1.0 - score, 4), "MALICIOUS": round(score, 4)},
        "model_name": "atrdf_spr",
        "feature_set": "REQUEST_ONLY_13_SPR",
        "threshold": decision["threshold"],
        "pattern_similarity": round(decision["pattern_similarity"], 4),
        "nearest_family": decision["nearest_family"],
        "rf_probability": round(decision["rf_probability"], 4),
    }
    if not is_malicious:
        return with_mitigation({
            "request_id": req.request_id,
            "attack_family": "BENIGN",
            "predicted_class": "BENIGN",
            "confidence": binary_result["confidence"],
            "decision": "ALLOW",
            "model_profile": PROFILE_SPR,
            "binary_detection": binary_result,
            "multiclass_detection": None,
            "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
        }, "BENIGN")
    family = decision["nearest_family"] or "UNKNOWN"
    if "atrdf_multiclass" in MODELS:
        multi = predict_atrdf_multiclass(req.atrdf_features)
        family = multi["prediction"]
        multi_result = multi
    else:
        multi_result = {
            "prediction": family,
            "confidence": round(decision["pattern_similarity"], 4),
            "model_name": "atrdf_spr_prototypes",
        }
    return with_mitigation({
        "request_id": req.request_id,
        "attack_family": "ATRDF",
        "predicted_class": family,
        "confidence": round(score, 4),
        "decision": "BLOCK",
        "model_profile": PROFILE_SPR,
        "binary_detection": binary_result,
        "multiclass_detection": multi_result,
        "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
    }, family)


def predict_spr_bola(req: UnifiedPredictRequest, t_start: float):
    if "bola_spr" not in MODELS:
        raise HTTPException(status_code=503, detail="BOLA pattern-reinforcement model is not loaded")
    spr = MODELS["bola_spr"]
    vector = spr_bola_vector(req.bola_features)
    decision = spr.decide(vector)
    score = decision["score"]
    is_bola = decision["positive"]
    detection = {
        "prediction": "BOLA" if is_bola else "NORMAL",
        "is_bola": int(is_bola),
        "confidence": round(score if is_bola else 1.0 - score, 4),
        "probabilities": {"NORMAL": round(1.0 - score, 4), "BOLA": round(score, 4)},
        "model_name": "bola_spr",
        "feature_set": "BOLA_BEHAVIORAL_14_SPR",
        "threshold": decision["threshold"],
        "pattern_similarity": round(decision["pattern_similarity"], 4),
        "rf_probability": round(decision["rf_probability"], 4),
    }
    action = "BLOCK" if is_bola else "ALLOW"
    return with_mitigation({
        "request_id": req.request_id,
        "attack_family": "BOLA",
        "predicted_class": detection["prediction"],
        "confidence": detection["confidence"],
        "decision": action,
        "model_profile": PROFILE_SPR,
        "detection": detection,
        "total_inference_latency_ms": round((time.time() - t_start) * 1000, 3),
    }, detection["prediction"] if action == "BLOCK" else "BENIGN")


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    """Online prototype update from a confirmed label (historical/live attack)."""
    label = (req.label or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="Missing label")
    updated = False
    kind = req.detection_mode.upper()
    if kind == "BOLA":
        if "bola_spr" not in MODELS or not req.bola_features:
            raise HTTPException(status_code=400, detail="BOLA SPR or features missing")
        updated = MODELS["bola_spr"].update_online(spr_bola_vector(req.bola_features), label)
        if updated:
            save_spr(MODELS["bola_spr"], os.path.join(MODELS_DIR, "spr", "bola_spr.joblib"))
    else:
        if "atrdf_spr" not in MODELS or not req.atrdf_features:
            raise HTTPException(status_code=400, detail="ATRDF SPR or features missing")
        updated = MODELS["atrdf_spr"].update_online(spr_atrdf_vector(req.atrdf_features), label)
        if updated:
            save_spr(MODELS["atrdf_spr"], os.path.join(MODELS_DIR, "spr", "atrdf_spr.joblib"))
    log_path = os.path.join(MODELS_DIR, "spr", "feedback.jsonl")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"request_id": req.request_id, "mode": kind, "label": label, "updated": updated}) + "\n")
    return {"status": "OK", "updated": updated, "label": label, "mode": kind}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
