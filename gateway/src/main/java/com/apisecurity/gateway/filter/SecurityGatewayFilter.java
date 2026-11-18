package com.apisecurity.gateway.filter;

import com.apisecurity.gateway.auth.VerifiedIdentityResolver;
import com.apisecurity.gateway.decision.DecisionEngine;
import com.apisecurity.gateway.events.TelemetryService;
import com.apisecurity.gateway.features.BolaSessionTracker;
import com.apisecurity.gateway.features.FeatureExtractor;
import com.apisecurity.gateway.mitigation.MitigationEngine;
import com.apisecurity.gateway.ml.MlServiceClient;
import com.apisecurity.gateway.policy.ReviewRequestGuard;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
    private final VerifiedIdentityResolver identityResolver;
    private final ReviewRequestGuard reviewRequestGuard;
    private final MitigationEngine mitigationEngine;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AtomicLong requestCounter = new AtomicLong(1000);
    private static final Set<String> REVIEW_ORIGINS = Set.of(
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "http://localhost:4173",
            "http://127.0.0.1:4173");
    private static final String REVIEW_ALLOW_HEADERS =
            "Content-Type, Authorization, X-Authenticated-User, X-Experiment-Id, X-Test-Case-Id, X-Ground-Truth";
    private static final String EXPOSE_HEADERS =
            "X-Request-Id, X-Security-Decision, X-Attack-Family, X-Mitigation-Action, X-Mitigation-Techniques, X-Gateway-Processed, X-Ml-Decision, X-Rule-Id, X-Rule-Outcome, Retry-After";

    @Value("${target.demo-api.url:http://localhost:5001}")
    private String demoApiUrl;

    @Value("${gateway.atrdf.profile:production}")
    private String atrdfProfile = "production";

    public SecurityGatewayFilter(FeatureExtractor featureExtractor,
                                 BolaSessionTracker bolaSessionTracker,
                                 MlServiceClient mlServiceClient,
                                 DecisionEngine decisionEngine,
                                 TelemetryService telemetryService,
                                 RestTemplate restTemplate,
                                 VerifiedIdentityResolver identityResolver,
                                 ReviewRequestGuard reviewRequestGuard) {
        this(featureExtractor, bolaSessionTracker, mlServiceClient, decisionEngine,
                telemetryService, restTemplate, identityResolver, reviewRequestGuard, new MitigationEngine());
    }

    @Autowired
    public SecurityGatewayFilter(FeatureExtractor featureExtractor,
                                 BolaSessionTracker bolaSessionTracker,
                                 MlServiceClient mlServiceClient,
                                 DecisionEngine decisionEngine,
                                 TelemetryService telemetryService,
                                 RestTemplate restTemplate,
                                 VerifiedIdentityResolver identityResolver,
                                 ReviewRequestGuard reviewRequestGuard,
                                 MitigationEngine mitigationEngine) {
        this.featureExtractor = featureExtractor;
        this.bolaSessionTracker = bolaSessionTracker;
        this.mlServiceClient = mlServiceClient;
        this.decisionEngine = decisionEngine;
        this.telemetryService = telemetryService;
        this.restTemplate = restTemplate;
        this.identityResolver = identityResolver;
        this.reviewRequestGuard = reviewRequestGuard;
        this.mitigationEngine = mitigationEngine;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest rawRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        applyBrowserHeaders(rawRequest, response);

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

        // 1. Identity comes only from the demo API's verified JWT result.
        String authUser = identityResolver.resolve(request);
        String verifiedUser = authUser != null ? authUser : "unknown";
        String sessionId = request.getHeader("X-Session-Id");
        String sessionKey = (sessionId != null && !sessionId.isEmpty()) ? sessionId : verifiedUser;
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
            features = bolaSessionTracker.recordAndExtract(sessionKey, verifiedUser, objectId);
        } else if ("experimental-payload".equalsIgnoreCase(atrdfProfile)) {
            features = featureExtractor.extractPayloadFeatures(request, body);
        } else if ("experimental-jndi".equalsIgnoreCase(atrdfProfile)) {
            features = featureExtractor.extractAtrdfExperimentalFeatures(request, body);
        } else {
            features = featureExtractor.extractAtrdfFeatures(request, body);
        }
        // testCaseId is retained for telemetry correlation only.
        // It must NOT be forwarded into the ML feature map or influence model input.
        long featLatencyMs = System.currentTimeMillis() - tFeatStart;

        // 4. Query ML Service
        long tMlStart = System.currentTimeMillis();
        String modelProfile = "production";
        if ("pattern-reinforcement".equalsIgnoreCase(atrdfProfile)) {
            modelProfile = "pattern-reinforcement";
        } else if (!isBolaCandidate && "experimental-jndi".equalsIgnoreCase(atrdfProfile)) {
            modelProfile = "experimental-jndi";
        } else if (!isBolaCandidate && "experimental-payload".equalsIgnoreCase(atrdfProfile)) {
            modelProfile = "experimental-payload";
        }
        Map<String, Object> mlResult = mlServiceClient.predict(mode, requestId, features, modelProfile);
        String groundTruth = request.getHeader("X-Ground-Truth");
        if (groundTruth != null && !groundTruth.isBlank()
                && "pattern-reinforcement".equalsIgnoreCase(atrdfProfile)) {
            mlServiceClient.sendFeedback(mode, requestId, features, groundTruth);
        }
        long mlLatencyMs = System.currentTimeMillis() - tMlStart;

        // 5. Evaluate Decision
        long tDecStart = System.currentTimeMillis();
        DecisionEngine.SecurityDecision decision = decisionEngine.evaluate(mlResult, mode);
        mitigationEngine.attachTechniques(decision);
        long decLatencyMs = System.currentTimeMillis() - tDecStart;

        boolean reviewProfile = isReviewProfile();
        ReviewRequestGuard.Match ruleMatch = reviewProfile ? reviewRequestGuard.inspect(request, body) : null;
        boolean ruleBlocks = ruleMatch != null && !"BLOCK".equalsIgnoreCase(decision.action);

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
        event.authenticatedUser = verifiedUser;
        event.attackFamily = decision.attackFamily;
        event.predictedClass = decision.predictedClass;
        event.confidence = decision.confidence;
        event.mlDecision = decision.action;
        event.mlPredictedClass = decision.predictedClass;
        event.mlMitigation = decision.mitigation;
        event.ruleId = ruleMatch == null ? null : ruleMatch.id;
        event.ruleOutcome = reviewProfile ? (ruleMatch == null ? "NONE" : "MATCH") : "NOT_APPLICABLE";
        event.decision = ruleBlocks ? "BLOCK" : decision.action;
        event.mitigation = ruleBlocks ? ruleMatch.id : decision.mitigation;
        event.mitigationTechniques = decision.mitigationTechniques;
        event.statusCode = ruleBlocks ? ruleMatch.status : decision.httpStatusCode;
        event.finalReason = ruleBlocks ? ruleMatch.message : decision.action;
        event.detectionLatencyMs = mlLatencyMs;
        event.mitigationLatencyMs = decLatencyMs;
        event.totalGatewayLatencyMs = totalLatencyMs;
        if ("pattern-reinforcement".equalsIgnoreCase(atrdfProfile)) {
            event.modelName = isBolaCandidate ? "bola_spr" : "atrdf_spr";
        } else if (isBolaCandidate) {
            event.modelName = "bola_rf_behavioral";
        } else if ("experimental-payload".equalsIgnoreCase(atrdfProfile)) {
            event.modelName = "candidate_binary_rf_six_heldout";
        } else if ("experimental-jndi".equalsIgnoreCase(atrdfProfile)) {
            event.modelName = "candidate_binary_rf_jndi_augmented";
        } else {
            event.modelName = "atrdf_binary_rf_request_only";
        }
        event.modelVersion = "1.0.0";
        event.groundTruth = null; // Ground truth belongs to external test evaluation manifests only
        // True only after the demo API returns an HTTP status. An allow is not proof of receipt.
        event.backendReached = false;

        // A BOLA model block stays in telemetry. Management and mutation routes are
        // forwarded so the demo API can apply the JWT and the owner check.
        // On the review profiles, a plain book GET is a public catalog read, so a
        // model block is not turned into the HTTP result. ATRDF blocks are unchanged.
        boolean deferBolaToBackend = shouldDeferBolaBlock(request, decision) && ruleMatch == null;
        if (deferBolaToBackend) {
            event.decision = "ALERT";
            if (isBookAuthorizationOperation(request)) {
                event.mitigation = "ALERT + backend authorization";
                event.finalReason = "BOLA alert forwarded to backend authorization";
            } else {
                event.mitigation = "ALERT + public catalog read";
                event.finalReason = "Public book read forwarded. The model block is not the HTTP result.";
            }
            List<String> bolaTechniques = new ArrayList<>();
            if (decision.mitigationTechniques != null) {
                bolaTechniques.addAll(decision.mitigationTechniques);
            }
            bolaTechniques.add("defer_to_backend");
            event.mitigationTechniques = bolaTechniques;
        }

        if (mlResult != null) {
            if (mlResult.get("binary_detection") instanceof Map) {
                Map<?, ?> bDet = (Map<?, ?>) mlResult.get("binary_detection");
                if (bDet.get("probabilities") instanceof Map) {
                    event.binaryProbabilities = (Map<String, Double>) bDet.get("probabilities");
                    event.probabilities = event.binaryProbabilities;
                }
                if (bDet.get("top_predictive_features") instanceof List) {
                    event.topPredictiveFeatures = (List<String>) bDet.get("top_predictive_features");
                }
            }
            if (mlResult.get("multiclass_detection") instanceof Map) {
                Map<?, ?> mDet = (Map<?, ?>) mlResult.get("multiclass_detection");
                if (mDet.get("prediction") instanceof String) {
                    event.multiclassLabel = (String) mDet.get("prediction");
                }
                if (mDet.get("probabilities") instanceof Map) {
                    event.multiclassProbabilities = (Map<String, Double>) mDet.get("probabilities");
                    event.probabilities = event.multiclassProbabilities;
                }
                if (mDet.get("top_predictive_features") instanceof List) {
                    event.topPredictiveFeatures = (List<String>) mDet.get("top_predictive_features");
                }
            } else if (mlResult.get("detection") instanceof Map && event.probabilities == null) {
                Map<?, ?> det = (Map<?, ?>) mlResult.get("detection");
                if (det.get("probabilities") instanceof Map) {
                    event.probabilities = (Map<String, Double>) det.get("probabilities");
                }
                if (det.get("top_predictive_features") instanceof List) {
                    event.topPredictiveFeatures = (List<String>) det.get("top_predictive_features");
                }
            }
        }

        event.endpoint = MitigationEngine.redact(event.endpoint);
        event.finalReason = MitigationEngine.redact(event.finalReason);
        telemetryService.recordEvent(event);

        response.setHeader("X-Ml-Decision", decision.action);
        response.setHeader("X-Rule-Outcome", event.ruleOutcome);
        if (ruleMatch != null) {
            response.setHeader("X-Rule-Id", ruleMatch.id);
        }

        // 6. Enforce Mitigation. A review rule is recorded separately from the ML class.
        boolean hardBlock = "BLOCK".equalsIgnoreCase(decision.action) && !deferBolaToBackend;
        if (!ruleBlocks && hardBlock && mitigationEngine.rateLimitExceeded(request)) {
            event.decision = "BLOCK";
            event.mitigation = "MITIGATION-RATE-LIMIT";
            event.finalReason = "source_cooldown";
            event.statusCode = 429;
            event.mitigationTechniques = List.of("source_cooldown", "retry_after");
            event.endpoint = MitigationEngine.redact(event.endpoint);
            writeRateLimit(request, response, requestId, decision, event, totalLatencyMs);
            return;
        }
        if (ruleBlocks) {
            mitigationEngine.recordBlock(request);
            writeRuleBlock(request, response, requestId, ruleMatch, decision, event, totalLatencyMs);
            return;
        }
        if (hardBlock) {
            mitigationEngine.recordBlock(request);
            response.setStatus(decision.httpStatusCode);
            response.setContentType("application/json");
            applyBrowserHeaders(request, response);
            response.setHeader("X-Request-Id", requestId);
            response.setHeader("X-Security-Decision", "BLOCK");
            response.setHeader("X-Attack-Family", decision.attackFamily);
            response.setHeader("X-Mitigation-Action", decision.mitigation);
            mitigationEngine.applyBlockControls(request, response, decision, event);

            Map<String, Object> errorBody = new LinkedHashMap<>();
            errorBody.put("error", decision.userMessage);
            errorBody.put("code", decision.predictedClass);
            errorBody.put("request_id", requestId);
            errorBody.put("mitigation", decision.mitigation);
            errorBody.put("mitigation_techniques", decision.mitigationTechniques);
            errorBody.put("gateway_latency_ms", totalLatencyMs);

            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
            return;
        }

        // 7. Forward to the demo API. A deferred BOLA alert still carries the backend status and body.
        event.backendReached = forwardToDemoApi(request, response, body, requestId, deferBolaToBackend ? "ALERT" : "ALLOW");
        event.statusCode = response.getStatus();
        if (event.mitigationTechniques != null && !event.mitigationTechniques.isEmpty()) {
            response.setHeader("X-Mitigation-Techniques", String.join(",", event.mitigationTechniques));
        }
    }

    /**
     * Book management views and book mutations keep the BOLA score in telemetry,
     * then use the demo API's verified JWT and owner checks for the HTTP result.
     * Review profiles also forward a plain book read, which the demo API serves
     * without an owner check.
     */
    private boolean shouldDeferBolaBlock(HttpServletRequest request, DecisionEngine.SecurityDecision decision) {
        if (decision == null || !"BLOCK".equalsIgnoreCase(decision.action)) {
            return false;
        }
        if (!"BOLA".equalsIgnoreCase(decision.attackFamily)) {
            return false;
        }
        if (isBookAuthorizationOperation(request)) {
            return true;
        }
        return isReviewProfile() && isPublicBookRead(request);
    }

    private boolean isPublicBookRead(HttpServletRequest request) {
        if (!isBolaRoute(request)) {
            return false;
        }
        String method = request.getMethod() == null ? "" : request.getMethod();
        if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
            return false;
        }
        return !isManagementView(request);
    }

    private boolean isManagementView(HttpServletRequest request) {
        return "manage".equals(request.getParameter("view")) || "edit".equals(request.getParameter("access"));
    }

    private boolean isBookAuthorizationOperation(HttpServletRequest request) {
        if (!isBolaRoute(request)) {
            return false;
        }
        String method = request.getMethod() == null ? "" : request.getMethod();
        if ("PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)
                || "DELETE".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method)) {
            return true;
        }
        if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
            return false;
        }
        return isManagementView(request);
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

    /**
     * Rebuilds the query from the parsed parameters so characters such as "|" are
     * percent-encoded. The demo API search is a literal substring filter, not a command.
     * Returns true only when the demo API sends an HTTP response.
     */
    private boolean forwardToDemoApi(HttpServletRequest request, HttpServletResponse response, String body, String requestId, String securityDecision)
            throws IOException {
        URI targetUri;
        try {
            targetUri = buildDemoApiUri(request);
        } catch (IllegalArgumentException ex) {
            writeGatewayError(request, response, 400, requestId, "INVALID_QUERY",
                    "The request query could not be encoded for forwarding.");
            return false;
        }

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
            ResponseEntity<byte[]> demoResp = restTemplate.exchange(targetUri, method, entity, byte[].class);
            response.setStatus(demoResp.getStatusCode().value());
            copyDemoHeaders(request, response, demoResp.getHeaders());
            applyBrowserHeaders(request, response);
            if (isReviewProfile() && response.getContentType() == null && demoResp.getBody() != null && demoResp.getBody().length > 0) {
                response.setContentType(looksLikeJson(demoResp.getBody()) ? "application/json" : "text/plain;charset=UTF-8");
            }
            applyReviewHtmlPolicy(response);
            response.setHeader("X-Request-Id", requestId);
            response.setHeader("X-Security-Decision", securityDecision);
            response.setHeader("X-Gateway-Processed", "true");
            if (demoResp.getBody() != null) {
                response.getOutputStream().write(demoResp.getBody());
            }
            return true;
        } catch (HttpStatusCodeException e) {
            response.setStatus(e.getStatusCode().value());
            copyDemoHeaders(request, response, e.getResponseHeaders());
            applyBrowserHeaders(request, response);
            applyReviewHtmlPolicy(response);
            response.setHeader("X-Request-Id", requestId);
            if ("ALERT".equalsIgnoreCase(securityDecision)) {
                response.setHeader("X-Security-Decision", securityDecision);
            }
            response.getOutputStream().write(e.getResponseBodyAsByteArray());
            return true;
        } catch (IllegalArgumentException e) {
            writeGatewayError(request, response, 400, requestId, "INVALID_QUERY",
                    "The request query could not be encoded for forwarding.");
            return false;
        } catch (Exception e) {
            writeGatewayError(request, response, 502, requestId, "BACKEND_UNAVAILABLE",
                    "Demo API backend unavailable.");
            return false;
        }
    }

    private URI buildDemoApiUri(HttpServletRequest request) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(demoApiUrl)
                .path(request.getRequestURI());
        Map<String, String[]> parameters = request.getParameterMap();
        if (parameters != null && !parameters.isEmpty()) {
            StringJoiner query = new StringJoiner("&");
            for (Map.Entry<String, String[]> entry : parameters.entrySet()) {
                String name = UriUtils.encodeQueryParam(entry.getKey(), StandardCharsets.UTF_8);
                String[] values = entry.getValue();
                if (values == null || values.length == 0) {
                    query.add(name);
                    continue;
                }
                for (String value : values) {
                    String encoded = UriUtils.encodeQueryParam(value == null ? "" : value, StandardCharsets.UTF_8);
                    query.add(name + "=" + encoded);
                }
            }
            builder.query(query.toString());
        }
        return builder.build(true).toUri();
    }

    private void copyDemoHeaders(HttpServletRequest request, HttpServletResponse response, HttpHeaders headers) {
        if (headers == null) {
            return;
        }
        headers.forEach((name, values) -> {
            if (name.equalsIgnoreCase("transfer-encoding")) {
                return;
            }
            if (isReviewProfile() && (name.equalsIgnoreCase("x-powered-by")
                    || name.equalsIgnoreCase("access-control-allow-origin")
                    || name.equalsIgnoreCase("access-control-allow-headers")
                    || name.equalsIgnoreCase("access-control-allow-methods"))) {
                return;
            }
            response.setHeader(name, String.join(",", values));
        });
    }

    private void applyBrowserHeaders(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        response.setHeader("Access-Control-Expose-Headers", EXPOSE_HEADERS);
        if (!isReviewProfile()) {
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Headers", "*");
            return;
        }
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Access-Control-Allow-Headers", REVIEW_ALLOW_HEADERS);
        response.setHeader("Vary", "Origin");
        String origin = request == null ? null : request.getHeader("Origin");
        if (origin != null && REVIEW_ORIGINS.contains(origin)) {
            response.setHeader("Access-Control-Allow-Origin", origin);
        }
    }

    private boolean isReviewProfile() {
        return "experimental-jndi".equalsIgnoreCase(atrdfProfile)
                || "experimental-payload".equalsIgnoreCase(atrdfProfile)
                || "pattern-reinforcement".equalsIgnoreCase(atrdfProfile);
    }

    private void applyReviewHtmlPolicy(HttpServletResponse response) {
        if (!isReviewProfile()) {
            return;
        }
        String contentType = response.getContentType();
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("text/html")) {
            response.setHeader("Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
        }
    }

    private static boolean looksLikeJson(byte[] body) {
        for (byte value : body) {
            if (value == ' ' || value == '\n' || value == '\r' || value == '\t') {
                continue;
            }
            return value == '{' || value == '[';
        }
        return false;
    }

    private void writeRuleBlock(HttpServletRequest request, HttpServletResponse response, String requestId,
                                 ReviewRequestGuard.Match ruleMatch, DecisionEngine.SecurityDecision mlDecision,
                                 TelemetryService.SecurityEvent event, long totalLatencyMs) throws IOException {
        response.setStatus(ruleMatch.status);
        response.setContentType("application/json");
        applyBrowserHeaders(request, response);
        response.setHeader("X-Request-Id", requestId);
        response.setHeader("X-Security-Decision", "BLOCK");
        response.setHeader("X-Attack-Family", mlDecision.attackFamily);
        response.setHeader("X-Mitigation-Action", ruleMatch.id);
        response.setHeader("X-Rule-Id", ruleMatch.id);
        response.setHeader("X-Ml-Decision", mlDecision.action);

        Map<String, Object> errorBody = new LinkedHashMap<>();
        errorBody.put("error", ruleMatch.message);
        errorBody.put("code", ruleMatch.id);
        errorBody.put("rule_id", ruleMatch.id);
        errorBody.put("rule_outcome", "MATCH");
        errorBody.put("ml_decision", mlDecision.action);
        errorBody.put("ml_prediction", mlDecision.predictedClass);
        errorBody.put("ml_probabilities", event.binaryProbabilities);
        errorBody.put("multiclass_label", event.multiclassLabel);
        errorBody.put("request_id", requestId);
        errorBody.put("mitigation", ruleMatch.id);
        errorBody.put("mitigation_techniques", event.mitigationTechniques);
        errorBody.put("gateway_latency_ms", totalLatencyMs);
        mitigationEngine.applyBlockControls(request, response, mlDecision, event);
        if ("ATRDF-COOKIE-AUTHORITY".equals(ruleMatch.id)) {
            response.addHeader("Set-Cookie", "session=; Max-Age=0; Path=/; HttpOnly");
            response.addHeader("Set-Cookie", "JSESSIONID=; Max-Age=0; Path=/; HttpOnly");
        }
        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }

    private void writeRateLimit(HttpServletRequest request, HttpServletResponse response, String requestId,
                                DecisionEngine.SecurityDecision decision, TelemetryService.SecurityEvent event,
                                long totalLatencyMs) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        applyBrowserHeaders(request, response);
        mitigationEngine.applyRateLimitResponse(response);
        response.setHeader("X-Request-Id", requestId);
        response.setHeader("X-Security-Decision", "BLOCK");
        response.setHeader("X-Attack-Family", decision.attackFamily);
        response.setHeader("X-Ml-Decision", decision.action);
        Map<String, Object> errorBody = new LinkedHashMap<>();
        errorBody.put("error", "Too many blocked requests from this source. Retry later.");
        errorBody.put("code", "MITIGATION-RATE-LIMIT");
        errorBody.put("request_id", requestId);
        errorBody.put("mitigation", "MITIGATION-RATE-LIMIT");
        errorBody.put("ml_mitigation", decision.mitigation);
        errorBody.put("mitigation_techniques", List.of("source_cooldown", "retry_after"));
        errorBody.put("gateway_latency_ms", totalLatencyMs);
        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }

    private void writeGatewayError(HttpServletRequest request, HttpServletResponse response, int status,
                                    String requestId, String code, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        applyBrowserHeaders(request, response);
        response.setHeader("X-Request-Id", requestId);
        Map<String, Object> errorBody = new LinkedHashMap<>();
        errorBody.put("error", message);
        errorBody.put("code", code);
        errorBody.put("request_id", requestId);
        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }
}
