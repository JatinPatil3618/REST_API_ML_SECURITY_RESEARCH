package com.apisecurity.gateway.controllers;

import com.apisecurity.gateway.events.TelemetryService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@RestController
@CrossOrigin(origins = "*")
public class GatewayTelemetryController {

    private final TelemetryService telemetryService;
    private final RestTemplate restTemplate;

    @Value("${target.ml-service.url:http://localhost:8000}")
    private String mlServiceUrl;

    @Value("${target.demo-api.url:http://localhost:5001}")
    private String demoApiUrl;

    public GatewayTelemetryController(TelemetryService telemetryService, RestTemplate restTemplate) {
        this.telemetryService = telemetryService;
        this.restTemplate = restTemplate;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("status", "PASS");
        status.put("service", "gateway");
        status.put("port", 8080);
        status.put("timestamp", System.currentTimeMillis());
        return status;
    }

    @GetMapping("/api/telemetry/events")
    public List<TelemetryService.SecurityEvent> getEvents(@RequestParam(defaultValue = "50") int limit) {
        return telemetryService.getRecentEvents(limit);
    }

    @GetMapping("/api/telemetry/stats")
    public Map<String, Object> getStats() {
        return telemetryService.calculateStats();
    }

    @GetMapping("/api/research/metrics")
    public Map<String, Object> getResearchMetrics() {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("gateway_stats", telemetryService.calculateStats());
        
        try {
            Map mlInfo = restTemplate.getForObject(mlServiceUrl + "/model-info", Map.class);
            res.put("ml_info", mlInfo);
        } catch (Exception e) {
            res.put("ml_info", "Unavailable");
        }
        
        return res;
    }
}
