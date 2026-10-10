package com.apisecurity.gateway.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FeatureExtractorTest {

    private FeatureExtractor featureExtractor;

    @BeforeEach
    public void setup() {
        featureExtractor = new FeatureExtractor();
    }

    @Test
    public void testTestHeadersDoNotAlterExtractedFeatures() {
        // Base request without test headers
        MockHttpServletRequest req1 = new MockHttpServletRequest("GET", "/api/books");
        req1.addHeader("Host", "localhost:8080");
        req1.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        req1.addHeader("Accept", "application/json");
        req1.addHeader("Accept-Language", "en-US,en;q=0.9");
        req1.addHeader("Connection", "keep-alive");
        req1.addHeader("Authorization", "Bearer test-token");

        // Same request with X-Test-Case-Id: NORMAL_001
        MockHttpServletRequest req2 = new MockHttpServletRequest("GET", "/api/books");
        req2.addHeader("Host", "localhost:8080");
        req2.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        req2.addHeader("Accept", "application/json");
        req2.addHeader("Accept-Language", "en-US,en;q=0.9");
        req2.addHeader("Connection", "keep-alive");
        req2.addHeader("Authorization", "Bearer test-token");
        req2.addHeader("X-Test-Case-Id", "NORMAL_001");
        req2.addHeader("X-Experiment-Id", "EXP-LIVE");

        // Same request with X-Test-Case-Id: SQLI_999
        MockHttpServletRequest req3 = new MockHttpServletRequest("GET", "/api/books");
        req3.addHeader("Host", "localhost:8080");
        req3.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        req3.addHeader("Accept", "application/json");
        req3.addHeader("Accept-Language", "en-US,en;q=0.9");
        req3.addHeader("Connection", "keep-alive");
        req3.addHeader("Authorization", "Bearer test-token");
        req3.addHeader("X-Test-Case-Id", "SQLI_999");

        Map<String, Object> feat1 = featureExtractor.extractAtrdfFeatures(req1, "");
        Map<String, Object> feat2 = featureExtractor.extractAtrdfFeatures(req2, "");
        Map<String, Object> feat3 = featureExtractor.extractAtrdfFeatures(req3, "");

        assertEquals(feat1, feat2, "Features with X-Test-Case-Id: NORMAL_001 must match request without test ID");
        assertEquals(feat1, feat3, "Features with X-Test-Case-Id: SQLI_999 must match request without test ID");
        assertEquals(feat1.get("header_count"), feat2.get("header_count"));
        assertEquals(feat1.get("header_count"), feat3.get("header_count"));
    }

    @Test
    public void testEntropyCalculationIsDeterministic() {
        double e1 = featureExtractor.calculateShannonEntropy("http://localhost:8080/api/books");
        double e2 = featureExtractor.calculateShannonEntropy("http://localhost:8080/api/books");
        assertEquals(e1, e2);
        assertTrue(e1 > 0.0);
    }
}
