package com.apisecurity.gateway.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Expected numbers are the golden vectors produced by
 * scripts/test_atrdf_feature_golden.py from entropy_utils.py.
 */
public class FeatureExtractorTest {

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    private static final List<String> FEATURE_ORDER = Arrays.asList(
            "url_entropy",
            "header_count",
            "path_length",
            "url_special_count",
            "url_length",
            "path_segment_count",
            "cookie_present",
            "query_length",
            "url_digit_count",
            "user_agent_entropy",
            "query_parameter_count",
            "request_body_entropy",
            "request_body_digit_count"
    );

    private FeatureExtractor featureExtractor;

    @BeforeEach
    public void setup() {
        featureExtractor = new FeatureExtractor();
    }

    @Test
    public void testNormalUrlMatchesCanonicalVector() {
        MockHttpServletRequest request = request("api.example.com", 8080, "/api/books/101", null);
        request.addHeader("Host", "api.example.com:8080");
        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Accept", "application/json");

        Map<String, Object> features = featureExtractor.extractAtrdfFeatures(request, "");

        assertEquals(FEATURE_ORDER, List.copyOf(features.keySet()));
        assertEquals(4.141106, asDouble(features.get("url_entropy")), 0.0000005);
        assertEquals(3, features.get("header_count"));
        assertEquals(14, features.get("path_length"));
        assertEquals(9, features.get("url_special_count"));
        assertEquals(41, features.get("url_length"));
        assertEquals(3, features.get("path_segment_count"));
        assertEquals(0, features.get("cookie_present"));
        assertEquals(0, features.get("query_length"));
        assertEquals(7, features.get("url_digit_count"));
        assertEquals(4.4522, asDouble(features.get("user_agent_entropy")), 0.0000005);
        assertEquals(0, features.get("query_parameter_count"));
        assertEquals(0.0, asDouble(features.get("request_body_entropy")), 0.0);
        assertEquals(0, features.get("request_body_digit_count"));
    }

    @Test
    public void testLocalhostUrlDoesNotInflateDigitCount() {
        MockHttpServletRequest request = request("localhost", 8080, "/api/books", null);
        request.addHeader("Host", "localhost:8080");
        request.addHeader("User-Agent", USER_AGENT);

        Map<String, Object> features = featureExtractor.extractAtrdfFeatures(request, "");

        assertEquals(4, features.get("url_digit_count"));
        assertEquals(31, features.get("url_length"));
        assertEquals(6, features.get("url_special_count"));
        assertEquals(10, features.get("path_length"));
        assertEquals(2, features.get("path_segment_count"));
        assertEquals(2, features.get("header_count"));
        assertEquals(3.768555, asDouble(features.get("url_entropy")), 0.0000005);
        assertEquals(4.4522, asDouble(features.get("user_agent_entropy")), 0.0000005);
    }

    @Test
    public void testQueryStringVectorIgnoresBodyParameters() {
        MockHttpServletRequest request = request(
                "localhost", 8080, "/api/books", "search=science&category=Engineering");
        request.setMethod("POST");
        request.addHeader("Host", "localhost:8080");
        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Accept", "application/json");
        request.addHeader("Accept-Language", "en-US");
        request.addHeader("Connection", "keep-alive");
        request.addHeader("Authorization", "Bearer test-token");
        request.setParameter("b", "2");
        request.setParameter("c", "3");

        Map<String, Object> features = featureExtractor.extractAtrdfFeatures(request, "b=2&c=3");

        assertEquals(6, features.get("header_count"));
        assertEquals(35, features.get("query_length"));
        assertEquals(2, features.get("query_parameter_count"));
        assertEquals(67, features.get("url_length"));
        assertEquals(10, features.get("url_special_count"));
        assertEquals(4, features.get("url_digit_count"));
        assertEquals(4.379616, asDouble(features.get("url_entropy")), 0.0000005);
        assertEquals(2.521641, asDouble(features.get("request_body_entropy")), 0.0000005);
        assertEquals(2, features.get("request_body_digit_count"));
    }

    @Test
    public void testHeaderCountTracksActualHeaders() {
        MockHttpServletRequest four = request("localhost", 8080, "/api/books", null);
        four.addHeader("Host", "localhost:8080");
        four.addHeader("User-Agent", USER_AGENT);
        four.addHeader("Accept", "application/json");
        four.addHeader("Connection", "keep-alive");

        MockHttpServletRequest six = request("localhost", 8080, "/api/books", null);
        addStandardHeaders(six);

        MockHttpServletRequest eight = request("localhost", 8080, "/api/books", null);
        addStandardHeaders(eight);
        eight.addHeader("Sec-Fetch-Site", "same-origin");
        eight.addHeader("Sec-CH-UA", "\"Chromium\"");

        assertEquals(4, featureExtractor.extractAtrdfFeatures(four, "").get("header_count"));
        assertEquals(6, featureExtractor.extractAtrdfFeatures(six, "").get("header_count"));
        assertEquals(8, featureExtractor.extractAtrdfFeatures(eight, "").get("header_count"));
    }

    @Test
    public void testPunctuationAndSpaceMatchCanonicalCounts() {
        MockHttpServletRequest punct = request(
                "localhost",
                8080,
                "/api/comments/book/101",
                "q=<script>alert(1)</script>");
        punct.addHeader("Host", "localhost:8080");
        punct.addHeader("User-Agent", USER_AGENT);
        punct.addHeader("Cookie", "session=abc");

        Map<String, Object> punctFeatures = featureExtractor.extractAtrdfFeatures(
                punct, "{\"text\": \"<script>alert(1)</script>\"}");

        assertEquals(17, punctFeatures.get("url_special_count"));
        assertEquals(71, punctFeatures.get("url_length"));
        assertEquals(22, punctFeatures.get("path_length"));
        assertEquals(4, punctFeatures.get("path_segment_count"));
        assertEquals(27, punctFeatures.get("query_length"));
        assertEquals(1, punctFeatures.get("query_parameter_count"));
        assertEquals(1, punctFeatures.get("cookie_present"));
        assertEquals(8, punctFeatures.get("url_digit_count"));
        assertEquals(4.495635, asDouble(punctFeatures.get("url_entropy")), 0.0000005);
        assertEquals(4.172574, asDouble(punctFeatures.get("request_body_entropy")), 0.0000005);
        assertEquals(1, punctFeatures.get("request_body_digit_count"));

        MockHttpServletRequest spaced = request("localhost", 8080, "/api/search", "q=a b");
        spaced.addHeader("Host", "localhost:8080");
        Map<String, Object> spacedFeatures = featureExtractor.extractAtrdfFeatures(spaced, "");
        assertEquals(8, spacedFeatures.get("url_special_count"));
        assertEquals(38, spacedFeatures.get("url_length"));
        assertEquals(5, spacedFeatures.get("query_length"));
        assertEquals(1, spacedFeatures.get("query_parameter_count"));
        assertEquals(4.155565, asDouble(spacedFeatures.get("url_entropy")), 0.0000005);
        assertEquals(0.0, asDouble(spacedFeatures.get("user_agent_entropy")), 0.0);

        MockHttpServletRequest atSign = request("localhost", 8080, "/api/search", "email=a@b.com");
        Map<String, Object> atFeatures = featureExtractor.extractAtrdfFeatures(atSign, null);
        assertEquals(10, atFeatures.get("url_special_count"));
        assertEquals(46, atFeatures.get("url_length"));
        assertEquals(4, atFeatures.get("url_digit_count"));
        assertEquals(4.232604, asDouble(atFeatures.get("url_entropy")), 0.0000005);
    }

    @Test
    public void testDuplicateAndEncodedQueryKeys() {
        MockHttpServletRequest duplicates = request("localhost", 8080, "/api/books", "a=1&a=2&flag");
        assertEquals(2, featureExtractor.extractAtrdfFeatures(duplicates, "b=9&c=8").get("query_parameter_count"));

        MockHttpServletRequest blanks = request("localhost", 8080, "/api/books", "a=1&&b=2");
        assertEquals(2, featureExtractor.extractAtrdfFeatures(blanks, "").get("query_parameter_count"));

        MockHttpServletRequest encoded = request("localhost", 8080, "/api/books", "a%5B%5D=1&a%5B%5D=2");
        assertEquals(1, featureExtractor.extractAtrdfFeatures(encoded, "").get("query_parameter_count"));
    }

    @Test
    public void testTestHeadersDoNotAlterExtractedFeatures() {
        MockHttpServletRequest plain = request("localhost", 8080, "/api/books", null);
        addStandardHeaders(plain);

        MockHttpServletRequest normalCase = request("localhost", 8080, "/api/books", null);
        addStandardHeaders(normalCase);
        normalCase.addHeader("X-Test-Case-Id", "NORMAL_001");
        normalCase.addHeader("X-Experiment-Id", "EXP-LIVE");
        normalCase.addHeader("X-Ground-Truth", "Benign");

        MockHttpServletRequest attackCase = request("localhost", 8080, "/api/books", null);
        addStandardHeaders(attackCase);
        attackCase.addHeader("X-Test-Case-Id", "SQLI_999");
        attackCase.addHeader("X-Ground-Truth", "SQL Injection");

        Map<String, Object> plainFeatures = featureExtractor.extractAtrdfFeatures(plain, "");
        Map<String, Object> normalFeatures = featureExtractor.extractAtrdfFeatures(normalCase, "");
        Map<String, Object> attackFeatures = featureExtractor.extractAtrdfFeatures(attackCase, "");

        assertEquals(plainFeatures, normalFeatures);
        assertEquals(plainFeatures, attackFeatures);
        assertEquals(6, plainFeatures.get("header_count"));
        assertEquals(4, plainFeatures.get("url_digit_count"));
    }

    @Test
    public void testEntropyCalculationIsDeterministic() {
        double first = featureExtractor.calculateShannonEntropy("http://localhost:8080/api/books");
        double second = featureExtractor.calculateShannonEntropy("http://localhost:8080/api/books");
        assertEquals(first, second);
        assertEquals(3.768555, first, 0.0000005);
        assertEquals(0.0, featureExtractor.calculateShannonEntropy(""), 0.0);
        assertEquals(0, featureExtractor.countSpecialCharacters("a b"));
        assertEquals(2, featureExtractor.countSpecialCharacters("a@b.com"));
    }

    private static MockHttpServletRequest request(String host, int port, String path, String query) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setScheme("http");
        request.setServerName(host);
        request.setServerPort(port);
        request.setRequestURI(path);
        if (query != null) {
            request.setQueryString(query);
        }
        return request;
    }

    private static void addStandardHeaders(MockHttpServletRequest request) {
        request.addHeader("Host", "localhost:8080");
        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Accept", "application/json");
        request.addHeader("Accept-Language", "en-US,en;q=0.9");
        request.addHeader("Connection", "keep-alive");
        request.addHeader("Authorization", "Bearer test-token");
    }

    private static double asDouble(Object value) {
        return ((Number) value).doubleValue();
    }
}
