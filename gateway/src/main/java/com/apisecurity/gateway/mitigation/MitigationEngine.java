package com.apisecurity.gateway.mitigation;

import com.apisecurity.gateway.decision.DecisionEngine;
import com.apisecurity.gateway.events.TelemetryService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Executes mitigation techniques. Existing ALLOW / BLOCK / BOLA-alert
 * decisions stay in place; this layer adds cookie wipe, log redaction,
 * cache headers, and a source cooldown after repeated blocks.
 */
@Service
public class MitigationEngine {

    private final ConcurrentHashMap<String, Deque<Long>> recentBlocks = new ConcurrentHashMap<>();

    @Value("${gateway.mitigation.rate-limit.blocks:8}")
    private int blockBurst = 8;

    @Value("${gateway.mitigation.rate-limit.window-seconds:120}")
    private int windowSeconds = 120;

    public void attachTechniques(DecisionEngine.SecurityDecision decision) {
        if (decision == null) {
            return;
        }
        if (decision.mitigationTechniques == null || decision.mitigationTechniques.isEmpty()) {
            decision.mitigationTechniques = new ArrayList<>(
                    MitigationCatalog.forClass(decision.predictedClass).techniques);
        }
        if (decision.mitigation == null || decision.mitigation.isBlank()
                || "BLOCK".equals(decision.mitigation)) {
            String catalog = MitigationCatalog.forClass(decision.predictedClass).mitigation;
            if (decision.mitigation == null || "BLOCK".equals(decision.mitigation)) {
                decision.mitigation = catalog;
            }
        }
    }

    public boolean rateLimitExceeded(HttpServletRequest request) {
        String key = sourceKey(request);
        long now = System.currentTimeMillis();
        long windowMs = windowSeconds * 1000L;
        Deque<Long> hits = recentBlocks.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (hits) {
            while (!hits.isEmpty() && now - hits.peekFirst() > windowMs) {
                hits.removeFirst();
            }
            return hits.size() >= blockBurst;
        }
    }

    public void recordBlock(HttpServletRequest request) {
        String key = sourceKey(request);
        long now = System.currentTimeMillis();
        Deque<Long> hits = recentBlocks.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (hits) {
            hits.addLast(now);
        }
    }

    public void applyBlockControls(HttpServletRequest request, HttpServletResponse response,
                                   DecisionEngine.SecurityDecision decision,
                                   TelemetryService.SecurityEvent event) {
        if (event != null) {
            event.endpoint = redact(event.endpoint);
            event.finalReason = redact(event.finalReason);
            event.mitigationTechniques = decision != null ? decision.mitigationTechniques : null;
        }
        if (response == null || decision == null) {
            return;
        }
        if (decision.mitigationTechniques != null && !decision.mitigationTechniques.isEmpty()) {
            response.setHeader("X-Mitigation-Techniques", String.join(",", decision.mitigationTechniques));
        }
        if (!"BLOCK".equalsIgnoreCase(decision.action)) {
            return;
        }
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        if (uses(decision, "invalidate_session_cookie")
                || "Cookie Injection".equalsIgnoreCase(decision.predictedClass)) {
            response.addHeader("Set-Cookie", "session=; Max-Age=0; Path=/; HttpOnly");
            response.addHeader("Set-Cookie", "JSESSIONID=; Max-Age=0; Path=/; HttpOnly");
        }
        if (uses(decision, "content_security_policy")) {
            response.setHeader("Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
        }
    }

    public void applyRateLimitResponse(HttpServletResponse response) {
        response.setHeader("Retry-After", String.valueOf(windowSeconds));
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Mitigation-Action", "MITIGATION-RATE-LIMIT");
        response.setHeader("X-Mitigation-Techniques", "source_cooldown,retry_after");
    }

    private static boolean uses(DecisionEngine.SecurityDecision decision, String technique) {
        return decision.mitigationTechniques != null && decision.mitigationTechniques.contains(technique);
    }

    private static String sourceKey(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        String user = request.getHeader("Authorization");
        String addr = request.getRemoteAddr();
        return (addr == null ? "na" : addr) + "|" + (user == null ? "anon" : Integer.toHexString(user.hashCode()));
    }

    public static String redact(String value) {
        if (value == null) {
            return null;
        }
        return value.replace('\r', ' ').replace('\n', ' ').replaceAll(" +", " ").trim();
    }
}
