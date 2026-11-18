package com.apisecurity.gateway.ml;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Service
public class MlServiceClient {

    private final RestTemplate restTemplate;

    @Value("${target.ml-service.url:http://localhost:8000}")
    private String mlServiceUrl;

    public MlServiceClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> predict(String mode, String requestId, Map<String, Object> features) {
        return predict(mode, requestId, features, "production");
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> predict(String mode, String requestId, Map<String, Object> features, String modelProfile) {
        String endpoint = mlServiceUrl + "/predict";
        
        Map<String, Object> payload = new HashMap<>();
        payload.put("detection_mode", mode);
        payload.put("request_id", requestId);
        payload.put("model_profile", modelProfile == null || modelProfile.isBlank() ? "production" : modelProfile);
        
        if ("BOLA".equalsIgnoreCase(mode)) {
            payload.put("bola_features", features);
        } else {
            payload.put("atrdf_features", features);
        }
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(payload, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(endpoint, entity, Map.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return (Map<String, Object>) response.getBody();
            }
        } catch (Exception e) {
            Map<String, Object> fallback = new HashMap<>();
            fallback.put("request_id", requestId);
            fallback.put("error", "ML prediction unavailable");
            fallback.put("exception", e.getMessage());
            fallback.put("decision", "ALERT");
            fallback.put("mitigation", "ALERT (ML Unavailable Fail-Safe)");
            fallback.put("mitigation_techniques", List.of("fail_safe_alert"));
            return fallback;
        }

        Map<String, Object> errorResp = new HashMap<>();
        errorResp.put("request_id", requestId);
        errorResp.put("error", "ML service returned non-2xx or empty response");
        errorResp.put("decision", "ALERT");
        errorResp.put("mitigation", "ALERT (ML Unavailable Fail-Safe)");
        errorResp.put("mitigation_techniques", List.of("fail_safe_alert"));
        return errorResp;
    }

    public void sendFeedback(String mode, String requestId, Map<String, Object> features, String label) {
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("detection_mode", mode);
            payload.put("request_id", requestId);
            payload.put("label", label);
            if ("BOLA".equalsIgnoreCase(mode)) {
                payload.put("bola_features", features);
            } else {
                payload.put("atrdf_features", features);
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            restTemplate.postForEntity(mlServiceUrl + "/feedback", new HttpEntity<>(payload, headers), Map.class);
        } catch (Exception ignored) {
            // Feedback must not change the request outcome.
        }
    }
}
