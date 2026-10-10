"""
FastAPI ML Inference Service
=============================
Loads trained models ONCE at startup and serves predictions.

Endpoints:
  GET  /health
  GET  /model-info
  POST /predict/atrdf/binary     — binary BENIGN/MALICIOUS
  POST /predict/atrdf/multiclass — 8-class attack type
  POST /predict/bola             — NORMAL/BOLA behavioral
  POST /predict                  — unified endpoint (routes by detection_mode)
"""

import os
import sys
import time
import json
import logging
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib
import numpy as np

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

MODEL_DIR_ATRDF = os.environ.get('ATRDF_MODEL_DIR',
    r'C:\Users\Admin\OneDrive\Desktop\API\REST_API_ML_SECURITY_RESEARCH\models\atrdf')
MODEL_DIR_BOLA = os.environ.get('BOLA_MODEL_DIR',
    r'C:\Users\Admin\OneDrive\Desktop\API\REST_API_ML_SECURITY_RESEARCH\models\bola')

# ============================================================
# Global model store — loaded ONCE at startup
# ============================================================
models: Dict[str, Any] = {}
metadata: Dict[str, Any] = {}


def load_models():
    """Load all models at startup. Fail clearly if files are missing."""
    log.info("Loading ML models...")

    # ATRDF models
    atrdf_rf_bin_path  = os.path.join(MODEL_DIR_ATRDF, 'atrdf_binary_rf_request_only.joblib')
    atrdf_rf_multi_path = os.path.join(MODEL_DIR_ATRDF, 'atrdf_multiclass_rf_request_only.joblib')
    atrdf_lr_bin_path  = os.path.join(MODEL_DIR_ATRDF, 'atrdf_binary_lr_request_only.joblib')
    le_path            = os.path.join(MODEL_DIR_ATRDF, 'label_encoder_multiclass.joblib')
    atrdf_meta_path    = os.path.join(MODEL_DIR_ATRDF, 'model_metadata.json')

    # BOLA models
    bola_rf_path   = os.path.join(MODEL_DIR_BOLA, 'bola_rf_behavioral.joblib')
    bola_meta_path = os.path.join(MODEL_DIR_BOLA, 'model_metadata.json')

    required_files = [
        atrdf_rf_bin_path, atrdf_rf_multi_path, bola_rf_path
    ]

    missing = [f for f in required_files if not os.path.exists(f)]
    if missing:
        log.error("REQUIRED MODEL FILES MISSING:")
        for f in missing:
            log.error(f"  {f}")
        log.error("Run scripts/train-all.ps1 first to train models.")
        raise FileNotFoundError(f"Model files missing: {missing}")

    models['atrdf_binary_rf']    = joblib.load(atrdf_rf_bin_path)
    models['atrdf_multiclass_rf'] = joblib.load(atrdf_rf_multi_path)
    models['bola_rf']            = joblib.load(bola_rf_path)
    models['label_encoder']      = joblib.load(le_path) if os.path.exists(le_path) else None

    if os.path.exists(atrdf_lr_bin_path):
        models['atrdf_binary_lr'] = joblib.load(atrdf_lr_bin_path)

    # Load metadata
    if os.path.exists(atrdf_meta_path):
        with open(atrdf_meta_path) as f:
            metadata['atrdf'] = json.load(f)

    if os.path.exists(bola_meta_path):
        with open(bola_meta_path) as f:
            metadata['bola'] = json.load(f)

    # Load feature lists
    feat_path = os.path.join(MODEL_DIR_ATRDF, 'feature_list_request_only.json')
    if os.path.exists(feat_path):
        with open(feat_path) as f:
            metadata['atrdf_features'] = json.load(f)['features']

    bola_feat_path = os.path.join(MODEL_DIR_BOLA, 'feature_list.json')
    if os.path.exists(bola_feat_path):
        with open(bola_feat_path) as f:
            bola_feat_data = json.load(f)
            metadata['bola_features'] = bola_feat_data['features']

    log.info(f"Loaded: atrdf_binary_rf, atrdf_multiclass_rf, bola_rf")
    if 'atrdf_binary_lr' in models:
        log.info(f"Loaded: atrdf_binary_lr (baseline)")
    log.info("Models ready.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_models()
    yield
    log.info("Shutting down ML service.")


app = FastAPI(
    title="SecureBook ML Inference Service",
    description="Real-time attack detection for ATRDF and BOLA threats",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST / RESPONSE SCHEMAS
# ============================================================

class ATRDFFeatures(BaseModel):
    url_entropy: float
    header_count: float
    path_length: float
    url_special_count: float
    url_length: float
    path_segment_count: float
    cookie_present: float
    query_length: float
    url_digit_count: float
    user_agent_entropy: float
    query_parameter_count: float
    request_body_entropy: float
    request_body_digit_count: float


class BOLAFeatures(BaseModel):
    request_frequency: float = 0.0
    unique_objects_recent: float = 0.0
    object_switch: float = 0.0
    unique_owners_recent: float = 0.0
    owner_switch: float = 0.0
    cross_owner_count_recent: float = 0.0
    cross_owner_ratio_recent: float = 0.0
    same_owner_ratio_recent: float = 1.0
    same_object_repeat_ratio: float = 0.0
    time_since_previous_request: float = 0.0
    request_burst_rate: float = 0.0
    hour: float = 12.0
    session_length: float = 1.0
    request_index: float = 1.0


class UnifiedPredictRequest(BaseModel):
    detection_mode: str = Field(..., description="'atrdf' or 'bola'")
    request_id: Optional[str] = None
    atrdf_features: Optional[ATRDFFeatures] = None
    bola_features: Optional[BOLAFeatures] = None


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    probabilities: Dict[str, float]
    model_name: str
    model_version: str
    feature_set: str
    inference_latency_ms: float
    top_predictive_features: List[Dict[str, float]]
    request_id: Optional[str] = None


ATRDF_FEATURE_ORDER = [
    "url_entropy", "header_count", "path_length", "url_special_count",
    "url_length", "path_segment_count", "cookie_present", "query_length",
    "url_digit_count", "user_agent_entropy", "query_parameter_count",
    "request_body_entropy", "request_body_digit_count"
]


def get_top_features(model, feature_names: List[str], n: int = 5) -> List[Dict[str, float]]:
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        top_idx = np.argsort(importances)[::-1][:n]
        return [{"feature": feature_names[i], "importance": float(importances[i])} for i in top_idx]
    return []


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "securebook-ml-service",
        "models_loaded": list(models.keys()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


@app.get("/model-info")
async def model_info():
    return {
        "loaded_models": list(models.keys()),
        "atrdf_metadata": metadata.get("atrdf", {}),
        "bola_metadata": metadata.get("bola", {}),
        "atrdf_features": metadata.get("atrdf_features", ATRDF_FEATURE_ORDER),
        "bola_features": metadata.get("bola_features", [])
    }


# ============================================================
# ATRDF BINARY
# ============================================================

@app.post("/predict/atrdf/binary", response_model=PredictionResponse)
async def predict_atrdf_binary(features: ATRDFFeatures, request_id: Optional[str] = None):
    if 'atrdf_binary_rf' not in models:
        raise HTTPException(503, detail="ATRDF binary model not loaded")

    t0 = time.perf_counter()
    X = np.array([[getattr(features, f) for f in ATRDF_FEATURE_ORDER]])

    model = models['atrdf_binary_rf']
    proba = model.predict_proba(X)[0]
    classes = model.classes_  # [0, 1]

    # Map to BENIGN / MALICIOUS
    benign_prob = float(proba[0]) if classes[0] == 0 else float(proba[1])
    malicious_prob = float(proba[1]) if classes[1] == 1 else float(proba[0])

    # Use stored threshold from metadata
    atrdf_meta = metadata.get('atrdf', {}).get('atrdf_binary_rf', {})
    threshold = atrdf_meta.get('threshold', 0.5)

    prediction = "MALICIOUS" if malicious_prob >= threshold else "BENIGN"
    confidence = malicious_prob if prediction == "MALICIOUS" else benign_prob

    latency_ms = (time.perf_counter() - t0) * 1000

    return PredictionResponse(
        prediction=prediction,
        confidence=round(confidence, 4),
        probabilities={"BENIGN": round(benign_prob, 4), "MALICIOUS": round(malicious_prob, 4)},
        model_name="atrdf_binary_rf_request_only",
        model_version="1.0.0",
        feature_set="REQUEST_ONLY_13",
        inference_latency_ms=round(latency_ms, 2),
        top_predictive_features=get_top_features(model, ATRDF_FEATURE_ORDER),
        request_id=request_id
    )


# ============================================================
# ATRDF MULTICLASS
# ============================================================

@app.post("/predict/atrdf/multiclass", response_model=PredictionResponse)
async def predict_atrdf_multiclass(features: ATRDFFeatures, request_id: Optional[str] = None):
    if 'atrdf_multiclass_rf' not in models:
        raise HTTPException(503, detail="ATRDF multiclass model not loaded")

    t0 = time.perf_counter()
    X = np.array([[getattr(features, f) for f in ATRDF_FEATURE_ORDER]])

    model = models['atrdf_multiclass_rf']
    le    = models.get('label_encoder')
    proba = model.predict_proba(X)[0]

    if le is not None:
        class_names = list(le.classes_)
    else:
        class_names = [str(c) for c in model.classes_]

    pred_idx = int(np.argmax(proba))
    prediction = class_names[pred_idx]
    confidence = float(proba[pred_idx])

    probabilities = {class_names[i]: round(float(proba[i]), 4) for i in range(len(class_names))}

    latency_ms = (time.perf_counter() - t0) * 1000

    return PredictionResponse(
        prediction=prediction,
        confidence=round(confidence, 4),
        probabilities=probabilities,
        model_name="atrdf_multiclass_rf_request_only",
        model_version="1.0.0",
        feature_set="REQUEST_ONLY_13",
        inference_latency_ms=round(latency_ms, 2),
        top_predictive_features=get_top_features(model, ATRDF_FEATURE_ORDER),
        request_id=request_id
    )


# ============================================================
# BOLA
# ============================================================

BOLA_FEATURE_ORDER = [
    "request_frequency", "unique_objects_recent", "object_switch",
    "unique_owners_recent", "owner_switch", "cross_owner_count_recent",
    "cross_owner_ratio_recent", "same_owner_ratio_recent",
    "same_object_repeat_ratio", "time_since_previous_request",
    "request_burst_rate", "hour", "session_length", "request_index"
]

@app.post("/predict/bola", response_model=PredictionResponse)
async def predict_bola(features: BOLAFeatures, request_id: Optional[str] = None):
    if 'bola_rf' not in models:
        raise HTTPException(503, detail="BOLA model not loaded")

    t0 = time.perf_counter()

    # Use available features (intersection with trained features)
    bola_features_trained = metadata.get('bola_features', BOLA_FEATURE_ORDER)
    X_vals = []
    feat_names_used = []
    for f in bola_features_trained:
        if hasattr(features, f):
            X_vals.append(getattr(features, f))
            feat_names_used.append(f)

    X = np.array([X_vals])
    model = models['bola_rf']
    proba = model.predict_proba(X)[0]
    classes = model.classes_

    normal_idx = list(classes).index(0) if 0 in classes else 0
    bola_idx   = list(classes).index(1) if 1 in classes else 1

    normal_prob = float(proba[normal_idx])
    bola_prob   = float(proba[bola_idx])

    # Use stored threshold
    bola_meta = metadata.get('bola', {}).get('bola_rf', {})
    threshold = bola_meta.get('threshold', 0.5)

    prediction = "BOLA" if bola_prob >= threshold else "NORMAL"
    confidence = bola_prob if prediction == "BOLA" else normal_prob

    latency_ms = (time.perf_counter() - t0) * 1000

    return PredictionResponse(
        prediction=prediction,
        confidence=round(confidence, 4),
        probabilities={"NORMAL": round(normal_prob, 4), "BOLA": round(bola_prob, 4)},
        model_name="bola_rf_behavioral",
        model_version="1.0.0",
        feature_set="BOLA_BEHAVIORAL_14",
        inference_latency_ms=round(latency_ms, 2),
        top_predictive_features=get_top_features(model, feat_names_used),
        request_id=request_id
    )


# ============================================================
# UNIFIED PREDICT — used by gateway for simplicity
# ============================================================

@app.post("/predict", response_model=PredictionResponse)
async def predict_unified(req: UnifiedPredictRequest):
    if req.detection_mode == 'bola':
        if not req.bola_features:
            raise HTTPException(400, detail="bola_features required for BOLA detection")
        return await predict_bola(req.bola_features, req.request_id)

    elif req.detection_mode == 'atrdf':
        if not req.atrdf_features:
            raise HTTPException(400, detail="atrdf_features required for ATRDF detection")
        # Two-stage: binary first, then multiclass if malicious
        binary_result = await predict_atrdf_binary(req.atrdf_features, req.request_id)

        if binary_result.prediction == "MALICIOUS":
            multi_result = await predict_atrdf_multiclass(req.atrdf_features, req.request_id)
            # Return multiclass result with combined latency
            total_latency = binary_result.inference_latency_ms + multi_result.inference_latency_ms
            return PredictionResponse(
                prediction=multi_result.prediction,
                confidence=multi_result.confidence,
                probabilities=multi_result.probabilities,
                model_name="atrdf_rf_two_stage",
                model_version="1.0.0",
                feature_set="REQUEST_ONLY_13",
                inference_latency_ms=round(total_latency, 2),
                top_predictive_features=multi_result.top_predictive_features,
                request_id=req.request_id
            )
        return binary_result
    else:
        raise HTTPException(400, detail=f"Unknown detection_mode: {req.detection_mode}. Use 'atrdf' or 'bola'")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("ML_PORT", 8000)), reload=False)
