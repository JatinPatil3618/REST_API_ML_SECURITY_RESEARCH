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

    @SuppressWarnings("unchecked")
    public Map<String, Object> predict(String mode, String requestId, Map<String, Object> features) {
        String endpoint = mlServiceUrl + "/predict";
        
        Map<String, Object> payload = new HashMap<>();
        payload.put("detection_mode", mode);
        payload.put("request_id", requestId);
        
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
            return fallback;
        }

        Map<String, Object> errorResp = new HashMap<>();
        errorResp.put("request_id", requestId);
        errorResp.put("error", "ML service returned non-2xx or empty response");
        errorResp.put("decision", "ALERT");
        errorResp.put("mitigation", "ALERT (ML Unavailable Fail-Safe)");
        return errorResp;
    }
}
