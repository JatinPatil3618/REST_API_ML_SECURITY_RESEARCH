package com.apisecurity.gateway.filter;

import com.apisecurity.gateway.auth.VerifiedIdentityResolver;
import com.apisecurity.gateway.decision.DecisionEngine;
import com.apisecurity.gateway.events.TelemetryService;
import com.apisecurity.gateway.features.BolaSessionTracker;
import com.apisecurity.gateway.features.FeatureExtractor;
import com.apisecurity.gateway.ml.MlServiceClient;
import com.apisecurity.gateway.policy.ReviewRequestGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.apisecurity.gateway.ml.MlServiceClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ReviewInspectionGatewayTest {

    private TelemetryService telemetry;
    private RestTemplateDouble rest;
    private SecurityGatewayFilter filter;

    @BeforeEach
    public void setup() {
        telemetry = new TelemetryService();
        org.springframework.web.client.RestTemplate restTemplate = mock(org.springframework.web.client.RestTemplate.class);
        rest = new RestTemplateDouble(restTemplate);
        MlServiceClient ml = mock(MlServiceClient.class);
        DecisionEngine decisionEngine = new DecisionEngine();
        ReflectionTestUtils.setField(decisionEngine, "defaultConfidenceThreshold", 0.70);
        ReflectionTestUtils.setField(decisionEngine, "failSafeMode", "ALERT");
        filter = new SecurityGatewayFilter(
                new FeatureExtractor(),
                new BolaSessionTracker(),
                ml,
                decisionEngine,
                telemetry,
                restTemplate,
                mock(VerifiedIdentityResolver.class),
                new ReviewRequestGuard()
        );
        ReflectionTestUtils.setField(filter, "demoApiUrl", "http://localhost:5001");
        ReflectionTestUtils.setField(filter, "atrdfProfile", "experimental-jndi");
        Map<String, Object> allow = new HashMap<>();
        allow.put("decision", "ALLOW");
        allow.put("attack_family", "BENIGN");
        allow.put("predicted_class", "BENIGN");
        allow.put("mitigation", "ALLOW");
        allow.put("confidence", 0.556);
        Map<String, Object> binary = new HashMap<>();
        binary.put("probabilities", Map.of("BENIGN", 0.556, "MALICIOUS", 0.444));
        allow.put("binary_detection", binary);
        when(ml.predict(any(), any(), any(), eq("experimental-jndi"))).thenReturn(allow);
        when(ml.predict(any(), any(), any(), eq("production"))).thenReturn(allow);
        when(restTemplate.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(ResponseEntity.ok("{\"total\":1}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void reviewRuleBlocksWithoutRelabelingTheModel() throws Exception {
        MockHttpServletResponse response = send("experimental-jndi", "/api/books",
                "search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*");

        assertEquals(403, response.getStatus());
        assertEquals("ATRDF-SQL-STRUCTURE", response.getHeader("X-Rule-Id"));
        assertEquals("ALLOW", response.getHeader("X-Ml-Decision"));
        assertTrue(response.getContentAsString().contains("\"ml_prediction\":\"BENIGN\""));
        assertFalse(response.getContentAsString().contains("\"code\":\"SQL Injection\""));
        verify(rest.template, never()).exchange(any(), any(), any(), eq(byte[].class));

        TelemetryService.SecurityEvent event = telemetry.getRecentEvents(1).get(0);
        assertEquals("ALLOW", event.mlDecision);
        assertEquals("BENIGN", event.mlPredictedClass);
        assertEquals("MATCH", event.ruleOutcome);
        assertEquals("ATRDF-SQL-STRUCTURE", event.ruleId);
        assertEquals("BLOCK", event.decision);
        assertEquals(0.444, event.binaryProbabilities.get("MALICIOUS"));
        assertEquals(null, event.multiclassLabel);
        assertFalse(event.backendReached);
    }

    @Test
    public void productionProfileDoesNotApplyTheReviewRule() throws Exception {
        MockHttpServletResponse response = send("production", "/api/books",
                "search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*");

        assertEquals(200, response.getStatus());
        assertEquals("NOT_APPLICABLE", response.getHeader("X-Rule-Outcome"));
        verify(rest.template).exchange(any(), any(), any(), eq(byte[].class));
        assertEquals("NOT_APPLICABLE", telemetry.getRecentEvents(1).get(0).ruleOutcome);
    }

    @Test
    public void reviewBrowserResponsesKeepTheFrontendOriginAndAContentType() throws Exception {
        HttpHeaders backend = new HttpHeaders();
        backend.add("X-Powered-By", "Express");
        backend.add("Access-Control-Allow-Origin", "*");
        when(rest.template.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(new ResponseEntity<>("{\"books\":[]}".getBytes(StandardCharsets.UTF_8), backend, HttpStatus.OK));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/books");
        request.setRequestURI("/api/books");
        request.setQueryString("category=Technology");
        request.addHeader("Origin", "http://localhost:5173");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("gateway handles the request");
        });

        assertEquals(200, response.getStatus());
        assertEquals("http://localhost:5173", response.getHeader("Access-Control-Allow-Origin"));
        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertNull(response.getHeader("X-Powered-By"));
        assertEquals("application/json", response.getContentType());

        MockHttpServletRequest foreign = new MockHttpServletRequest("GET", "/api/books");
        foreign.setRequestURI("/api/books");
        foreign.addHeader("Origin", "https://evil.example");
        foreign.setContent(new byte[0]);
        MockHttpServletResponse hidden = new MockHttpServletResponse();
        filter.doFilter(foreign, hidden, (servletRequest, servletResponse) -> {
            throw new AssertionError("gateway handles the request");
        });
        assertNull(hidden.getHeader("Access-Control-Allow-Origin"));
    }

    @Test
    public void reviewPublicBookReadKeepsTheModelBlockAndReachesTheBackend() throws Exception {
        stubBolaBlock();
        HttpHeaders backend = new HttpHeaders();
        backend.add("Content-Type", "application/json");
        when(rest.template.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(new ResponseEntity<>(
                        "{\"id\":\"101\",\"title\":\"Foundations of Network Protocol Security\"}".getBytes(StandardCharsets.UTF_8),
                        backend,
                        HttpStatus.OK));

        MockHttpServletResponse response = send("experimental-payload", "/api/books/101", null);

        assertEquals(200, response.getStatus());
        assertEquals("BLOCK", response.getHeader("X-Ml-Decision"));
        assertEquals("ALERT", response.getHeader("X-Security-Decision"));
        assertTrue(response.getContentAsString().contains("Foundations of Network Protocol Security"));
        assertNull(response.getHeader("Content-Security-Policy"));
        TelemetryService.SecurityEvent event = telemetry.getRecentEvents(1).get(0);
        assertEquals("BLOCK", event.mlDecision);
        assertEquals("BOLA", event.mlPredictedClass);
        assertEquals("ALERT", event.decision);
        assertEquals("ALERT + public catalog read", event.mitigation);
        assertEquals("bola_rf_behavioral", event.modelName);
        assertTrue(event.backendReached);
        verify(rest.template).exchange(any(), any(), any(), eq(byte[].class));
    }

    @Test
    public void productionProfileStillHardBlocksAPublicBookRead() throws Exception {
        stubBolaBlock();
        MockHttpServletResponse response = send("production", "/api/books/101", null);

        assertEquals(403, response.getStatus());
        assertEquals("BLOCK", response.getHeader("X-Security-Decision"));
        TelemetryService.SecurityEvent event = telemetry.getRecentEvents(1).get(0);
        assertEquals("BLOCK", event.mlDecision);
        assertEquals("BLOCK", event.decision);
        assertFalse(event.backendReached);
        verify(rest.template, never()).exchange(any(), any(), any(), eq(byte[].class));
    }

    @Test
    public void managementReadStillReachesBackendAuthorization() throws Exception {
        stubBolaBlock();
        HttpHeaders backend = new HttpHeaders();
        backend.add("Content-Type", "application/json");
        byte[] denied = "{\"code\":\"BOLA_AUTHORIZATION_DENIED\"}".getBytes(StandardCharsets.UTF_8);
        when(rest.template.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(new ResponseEntity<>(denied, backend, HttpStatus.FORBIDDEN));

        MockHttpServletResponse response = send("experimental-payload", "/api/books/201", "view=manage");

        assertEquals(403, response.getStatus());
        assertEquals("BLOCK", response.getHeader("X-Ml-Decision"));
        assertEquals("ALERT", response.getHeader("X-Security-Decision"));
        assertTrue(response.getContentAsString().contains("BOLA_AUTHORIZATION_DENIED"));
        TelemetryService.SecurityEvent event = telemetry.getRecentEvents(1).get(0);
        assertEquals("ALERT", event.decision);
        assertEquals("ALERT + backend authorization", event.mitigation);
        assertTrue(event.backendReached);
    }

    @Test
    public void reviewHtmlErrorsReceiveARestrictiveContentSecurityPolicy() throws Exception {
        HttpHeaders backend = new HttpHeaders();
        backend.add("Content-Type", "text/html;charset=utf-8");
        backend.add("X-Powered-By", "Express");
        when(rest.template.exchange(any(), any(), any(), eq(byte[].class)))
                .thenThrow(HttpClientErrorException.create(
                        HttpStatus.NOT_FOUND,
                        "Not Found",
                        backend,
                        "Cannot GET /robots.txt".getBytes(StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8));

        MockHttpServletResponse response = send("experimental-payload", "/robots.txt", null);

        assertEquals(404, response.getStatus());
        assertEquals("text/html;charset=utf-8", response.getContentType());
        assertEquals(
                "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
                response.getHeader("Content-Security-Policy"));
        assertEquals("nosniff", response.getHeader("X-Content-Type-Options"));
        assertNull(response.getHeader("X-Powered-By"));
        assertTrue(response.getContentAsString().contains("Cannot GET /robots.txt"));
    }

    @Test
    public void ordinarySearchStillReachesTheBackend() throws Exception {
        MockHttpServletResponse response = send("experimental-jndi", "/api/books", "search=protocol");
        assertEquals(200, response.getStatus());
        assertEquals("NONE", response.getHeader("X-Rule-Outcome"));
        assertTrue(telemetry.getRecentEvents(1).get(0).backendReached);
    }

    private void stubBolaBlock() {
        MlServiceClient ml = (MlServiceClient) ReflectionTestUtils.getField(filter, "mlServiceClient");
        Map<String, Object> block = new HashMap<>();
        block.put("decision", "BLOCK");
        block.put("attack_family", "BOLA");
        block.put("predicted_class", "BOLA");
        block.put("mitigation", "BLOCK + authorization");
        block.put("confidence", 1.0);
        when(ml.predict(eq("BOLA"), any(), any(), eq("production"))).thenReturn(block);
    }

    private MockHttpServletResponse send(String profile, String path, String query) throws Exception {
        ReflectionTestUtils.setField(filter, "atrdfProfile", profile);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        if (query != null) {
            request.setQueryString(query);
            for (String part : query.split("&")) {
                String[] pair = part.split("=", 2);
                String value = pair.length == 2
                        ? java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8)
                        : "";
                request.addParameter(pair[0], value);
            }
        }
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("gateway handles the request");
        });
        return response;
    }

    private static final class RestTemplateDouble {
        private final org.springframework.web.client.RestTemplate template;

        private RestTemplateDouble(org.springframework.web.client.RestTemplate template) {
            this.template = template;
        }
    }
}
