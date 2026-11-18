package com.apisecurity.gateway.events;

import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

@Service
public class TelemetryService {

    public static class SecurityEvent {
        public String requestId;
        public String experimentId;
        public String testCaseId;
        public String timestamp;
        public String method;
        public String endpoint;
        public String source;
        public String authenticatedUser;
        public String attackFamily;
        public String predictedClass;
        public double confidence;
        public Map<String, Double> probabilities;
        public Map<String, Double> binaryProbabilities;
        public String multiclassLabel;
        public Map<String, Double> multiclassProbabilities;
        public List<String> topPredictiveFeatures;
        public String decision;
        public String mitigation;
        public List<String> mitigationTechniques;
        public String mlDecision;
        public String mlPredictedClass;
        public String mlMitigation;
        public String ruleId;
        public String ruleOutcome;
        public String finalReason;
        public int statusCode;
        public long detectionLatencyMs;
        public long mitigationLatencyMs;
        public long totalGatewayLatencyMs;
        public String modelName;
        public String modelVersion;
        public String groundTruth;
        public boolean backendReached;
    }

    private final ConcurrentLinkedDeque<SecurityEvent> events = new ConcurrentLinkedDeque<>();
    private static final int MAX_EVENTS = 1000;

    public void recordEvent(SecurityEvent event) {
        events.addFirst(event);
        while (events.size() > MAX_EVENTS) {
            events.removeLast();
        }
    }

    public List<SecurityEvent> getRecentEvents(int limit) {
        return events.stream().limit(limit).collect(Collectors.toList());
    }

    public Map<String, Object> calculateStats() {
        int total = events.size();
        int normal = 0;
        int malicious = 0;
        int bola = 0;
        int atrdf = 0;
        int blocked = 0;
        int allowed = 0;
        List<Long> latencies = new ArrayList<>();

        for (SecurityEvent e : events) {
            if ("ALLOW".equalsIgnoreCase(e.decision)) {
                normal++;
                allowed++;
            } else {
                malicious++;
                blocked++;
                if ("BOLA".equalsIgnoreCase(e.attackFamily)) {
                    bola++;
                } else {
                    atrdf++;
                }
            }
            latencies.add(e.totalGatewayLatencyMs);
        }

        Collections.sort(latencies);
        double avgLat = latencies.isEmpty() ? 0.0 : latencies.stream().mapToLong(v -> v).average().orElse(0.0);
        long p95 = getPercentile(latencies, 95);
        long p99 = getPercentile(latencies, 99);

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total_requests", total);
        stats.put("normal", normal);
        stats.put("malicious", malicious);
        stats.put("bola", bola);
        stats.put("atrdf", atrdf);
        stats.put("blocked", blocked);
        stats.put("allowed", allowed);
        stats.put("average_latency_ms", Math.round(avgLat * 100.0) / 100.0);
        stats.put("p95_latency_ms", p95);
        stats.put("p99_latency_ms", p99);
        stats.put("active_sessions", 5);

        return stats;
    }

    private long getPercentile(List<Long> sorted, double pct) {
        if (sorted.isEmpty()) return 0;
        int idx = (int) Math.ceil((pct / 100.0) * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(idx, sorted.size() - 1)));
    }
}
