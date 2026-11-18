package com.apisecurity.gateway.auth;

import com.apisecurity.gateway.decision.DecisionEngine;
import com.apisecurity.gateway.events.TelemetryService;
import com.apisecurity.gateway.features.BolaSessionTracker;
import com.apisecurity.gateway.features.FeatureExtractor;
import com.apisecurity.gateway.filter.SecurityGatewayFilter;
import com.apisecurity.gateway.ml.MlServiceClient;
import com.apisecurity.gateway.policy.ReviewRequestGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class VerifiedIdentityTest {

    private RestTemplate restTemplate;
    private VerifiedIdentityResolver resolver;
    private TelemetryService telemetry;
    private SecurityGatewayFilter filter;

    @BeforeEach
    public void setup() {
        restTemplate = mock(RestTemplate.class);
        resolver = new VerifiedIdentityResolver(restTemplate);
        ReflectionTestUtils.setField(resolver, "demoApiUrl", "http://localhost:5001");
        telemetry = new TelemetryService();
        DecisionEngine decisionEngine = new DecisionEngine();
        ReflectionTestUtils.setField(decisionEngine, "defaultConfidenceThreshold", 0.70);
        ReflectionTestUtils.setField(decisionEngine, "failSafeMode", "ALERT");
        filter = new SecurityGatewayFilter(
                mock(FeatureExtractor.class),
                new BolaSessionTracker(),
                mock(MlServiceClient.class),
                decisionEngine,
                telemetry,
                restTemplate,
                resolver,
                new ReviewRequestGuard()
        );
        ReflectionTestUtils.setField(filter, "demoApiUrl", "http://localhost:5001");
        ReflectionTestUtils.setField(filter, "atrdfProfile", "experimental-jndi");
        MlServiceClient ml = (MlServiceClient) ReflectionTestUtils.getField(filter, "mlServiceClient");
        Map<String, Object> allow = new HashMap<>();
        allow.put("decision", "ALLOW");
        allow.put("attack_family", "BOLA");
        allow.put("predicted_class", "NORMAL");
        allow.put("confidence", 0.55);
        when(ml.predict(any(), any(), any(), eq("production"))).thenReturn(allow);
        when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(), eq(byte[].class)))
                .thenReturn(ResponseEntity.ok("{}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void user01ComesFromVerifiedProfile() throws Exception {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("username", "user01")));
        send("Bearer user01-token", null);
        assertEquals("user01", telemetry.getRecentEvents(1).get(0).authenticatedUser);
    }

    @Test
    public void user02IsNotRelabeledAsUser01() throws Exception {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("username", "user02")));
        send("Bearer user02-token", "user01");
        assertEquals("user02", resolver.resolve(requestWith("Bearer user02-token", "user01")));
        assertEquals("user02", telemetry.getRecentEvents(1).get(0).authenticatedUser);
    }

    @Test
    public void missingTokenIsUnknown() throws Exception {
        send(null, "user01");
        assertEquals("unknown", telemetry.getRecentEvents(1).get(0).authenticatedUser);
        verify(restTemplate, never()).exchange(any(URI.class), eq(HttpMethod.GET), any(), eq(Map.class));
    }

    @Test
    public void invalidTokenIsUnknown() throws Exception {
        when(restTemplate.exchange(any(URI.class), eq(HttpMethod.GET), any(), eq(Map.class)))
                .thenThrow(HttpClientErrorException.create(
                        HttpStatus.FORBIDDEN,
                        "Forbidden",
                        HttpHeaders.EMPTY,
                        "{\"error\":\"Session invalid or expired. Reauthentication required.\"}".getBytes(StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8));
        assertNull(resolver.resolve(requestWith("Bearer not-a-jwt", "user02")));
        send("Bearer not-a-jwt", "user02");
        assertEquals("unknown", telemetry.getRecentEvents(1).get(0).authenticatedUser);
    }

    @Test
    public void spoofedIdentityHeaderIsIgnored() throws Exception {
        MockHttpServletRequest request = requestWith(null, "user02");
        assertNull(resolver.resolve(request));
        send(null, "user02");
        assertEquals("unknown", telemetry.getRecentEvents(1).get(0).authenticatedUser);
    }

    private MockHttpServletResponse send(String authorization, String spoof) throws Exception {
        MockHttpServletRequest request = requestWith(authorization, spoof);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("gateway handles the request");
        });
        return response;
    }

    private MockHttpServletRequest requestWith(String authorization, String spoof) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/books/201");
        request.setContent(new byte[0]);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        if (spoof != null) {
            request.addHeader("X-Authenticated-User", spoof);
        }
        return request;
    }
}
