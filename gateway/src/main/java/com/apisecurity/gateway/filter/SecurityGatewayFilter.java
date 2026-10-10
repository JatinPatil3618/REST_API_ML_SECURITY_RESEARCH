package com.apisecurity.gateway.filter;

import com.apisecurity.gateway.decision.DecisionEngine;
import com.apisecurity.gateway.events.TelemetryService;
import com.apisecurity.gateway.features.BolaSessionTracker;
import com.apisecurity.gateway.features.FeatureExtractor;
import com.apisecurity.gateway.ml.MlServiceClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Component
@Order(1)
public class SecurityGatewayFilter implements Filter {

    private final FeatureExtractor featureExtractor;
    private final BolaSessionTracker bolaSessionTracker;
    private final MlServiceClient mlServiceClient;
    private final DecisionEngine decisionEngine;
    private final TelemetryService telemetryService;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AtomicLong requestCounter = new AtomicLong(1000);

    @Value("${target.demo-api.url:http://localhost:5001}")
    private String demoApiUrl;

    public SecurityGatewayFilter(FeatureExtractor featureExtractor,
                                 BolaSessionTracker bolaSessionTracker,
                                 MlServiceClient mlServiceClient,
                                 DecisionEngine decisionEngine,
                                 TelemetryService telemetryService,
                                 RestTemplate restTemplate) {
        this.featureExtractor = featureExtractor;
        this.bolaSessionTracker = bolaSessionTracker;
        this.mlServiceClient = mlServiceClient;
        this.decisionEngine = decisionEngine;
        this.telemetryService = telemetryService;
        this.restTemplate = restTemplate;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest rawRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Handle CORS headers for browser fetch requests
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        response.setHeader("Access-Control-Allow-Headers", "*");
        response.setHeader("Access-Control-Expose-Headers", "X-Request-Id, X-Security-Decision, X-Attack-Family, X-Mitigation-Action, X-Gateway-Processed");

        if ("OPTIONS".equalsIgnoreCase(rawRequest.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        String uri = rawRequest.getRequestURI();

        // Allow gateway telemetry and health endpoints through directly
        if (uri.startsWith("/api/telemetry") || uri.startsWith("/api/research") ||
            uri.startsWith("/api/zap") || uri.equals("/health") || uri.startsWith("/actuator")) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        long tStart = System.currentTimeMillis();
        String requestId = "REQ-" + requestCounter.incrementAndGet();
        CachedBodyHttpServletRequest request = new CachedBodyHttpServletRequest(rawRequest);
        String body = request.getBodyAsString();

        // 1. Identify User & Session Context
        String authUser = extractUsername(request);
        String sessionId = request.getHeader("X-Session-Id");
        String sessionKey = (sessionId != null && !sessionId.isEmpty()) ? sessionId : (authUser != null ? authUser : "anonymous");
        String experimentId = request.getHeader("X-Experiment-Id");
        String testCaseId = request.getHeader("X-Test-Case-Id");

        // 2. Determine Detection Mode
        boolean isBolaCandidate = isBolaRoute(request);
        String mode = isBolaCandidate ? "BOLA" : "ATRDF";

        // 3. Extract Features
        long tFeatStart = System.currentTimeMillis();
        Map<String, Object> features;
        if (isBolaCandidate) {
            String objectId = extractObjectId(request);
            features = bolaSessionTracker.recordAndExtract(sessionKey, authUser, objectId);
        } else {
            features = featureExtractor.extractAtrdfFeatures(request, body);
        }
        // testCaseId is retained for telemetry correlation only.
        // It must NOT be forwarded into the ML feature map or influence model input.
        long featLatencyMs = System.currentTimeMillis() - tFeatStart;

        // 4. Query ML Service
        long tMlStart = System.currentTimeMillis();
        Map<String, Object> mlResult = mlServiceClient.predict(mode, requestId, features);
        long mlLatencyMs = System.currentTimeMillis() - tMlStart;

        // 5. Evaluate Decision
        long tDecStart = System.currentTimeMillis();
        DecisionEngine.SecurityDecision decision = decisionEngine.evaluate(mlResult, mode);
        long decLatencyMs = System.currentTimeMillis() - tDecStart;

        long totalLatencyMs = System.currentTimeMillis() - tStart;

        // Record Telemetry Event
        TelemetryService.SecurityEvent event = new TelemetryService.SecurityEvent();
        event.requestId = requestId;
        event.experimentId = experimentId != null ? experimentId : "EXP-LIVE";
        event.testCaseId = testCaseId != null ? testCaseId : "CASE-WEB";
        event.timestamp = Instant.now().toString();
        event.method = request.getMethod();
        event.endpoint = uri;
        event.source = request.getRemoteAddr();
        event.authenticatedUser = authUser != null ? authUser : "anonymous";
        event.attackFamily = decision.attackFamily;
        event.predictedClass = decision.predictedClass;
        event.confidence = decision.confidence;
        event.decision = decision.action;
        event.mitigation = decision.mitigation;
        event.statusCode = decision.httpStatusCode;
        event.detectionLatencyMs = mlLatencyMs;
        event.mitigationLatencyMs = decLatencyMs;
        event.totalGatewayLatencyMs = totalLatencyMs;
        event.modelName = isBolaCandidate ? "bola_rf_behavioral" : "atrdf_binary_rf_request_only";
        event.modelVersion = "1.0.0";
        event.groundTruth = testCaseId;
        event.backendReached = "ALLOW".equalsIgnoreCase(decision.action);

        telemetryService.recordEvent(event);

        // 6. Enforce Mitigation
        if ("BLOCK".equalsIgnoreCase(decision.action)) {
            response.setStatus(decision.httpStatusCode);
            response.setContentType("application/json");
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("X-Request-Id", requestId);
            response.setHeader("X-Security-Decision", "BLOCK");
            response.setHeader("X-Attack-Family", decision.attackFamily);
            response.setHeader("X-Mitigation-Action", decision.mitigation);

            Map<String, Object> errorBody = new LinkedHashMap<>();
            errorBody.put("error", decision.userMessage);
            errorBody.put("code", decision.predictedClass);
            errorBody.put("request_id", requestId);
            errorBody.put("mitigation", decision.mitigation);
            errorBody.put("gateway_latency_ms", totalLatencyMs);

            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
            return;
        }

        // 7. Forward Safe Traffic to Demo API Backend
        forwardToDemoApi(request, response, body, requestId);
    }

    private boolean isBolaRoute(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.matches("^/api/books/\\d+.*$");
    }

    private String extractObjectId(HttpServletRequest request) {
        String path = request.getRequestURI();
        String[] parts = path.split("/");
        for (int i = 0; i < parts.length; i++) {
            if ("books".equalsIgnoreCase(parts[i]) && i + 1 < parts.length) {
                return parts[i + 1];
            }
        }
        return "101";
    }

    private String extractUsername(HttpServletRequest request) {
        String customHeader = request.getHeader("X-Authenticated-User");
        if (customHeader != null && !customHeader.isEmpty()) {
            return customHeader;
        }
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            return "user01"; // Fallback session context
        }
        return null;
    }

    private void forwardToDemoApi(HttpServletRequest request, HttpServletResponse response, String body, String requestId)
            throws IOException {
        String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
        String targetUrl = demoApiUrl + request.getRequestURI() + queryString;

        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                if (!name.equalsIgnoreCase("host") && !name.equalsIgnoreCase("content-length")) {
                    headers.set(name, request.getHeader(name));
                }
            }
        }
        headers.set("X-Forwarded-By", "SecurityGateway");
        headers.set("X-Request-Id", requestId);

        HttpMethod method = HttpMethod.valueOf(request.getMethod());
        HttpEntity<String> entity = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<byte[]> demoResp = restTemplate.exchange(URI.create(targetUrl), method, entity, byte[].class);
            response.setStatus(demoResp.getStatusCode().value());
            demoResp.getHeaders().forEach((k, v) -> {
                if (!k.equalsIgnoreCase("transfer-encoding")) {
                    response.setHeader(k, String.join(",", v));
                }
            });
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("X-Request-Id", requestId);
            response.setHeader("X-Security-Decision", "ALLOW");
            response.setHeader("X-Gateway-Processed", "true");
            if (demoResp.getBody() != null) {
                response.getOutputStream().write(demoResp.getBody());
            }
        } catch (HttpStatusCodeException e) {
            response.setStatus(e.getStatusCode().value());
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("X-Request-Id", requestId);
            response.getOutputStream().write(e.getResponseBodyAsByteArray());
        } catch (Exception e) {
            response.setStatus(502);
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("X-Request-Id", requestId);
            response.getWriter().write("{\"error\": \"Demo API backend unavailable: " + e.getMessage() + "\"}");
        }
    }
}
