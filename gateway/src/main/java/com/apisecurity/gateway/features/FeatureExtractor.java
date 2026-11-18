package com.apisecurity.gateway.features;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Live ATRDF request-only feature extractor.
 * Feature names and order match REQUEST_ONLY_13 / feature_list_request_only.json.
 * Entropy, digit counts, and URL punctuation follow ml-pipeline/shared/entropy_utils.py.
 * Caller-controlled test metadata headers are omitted. The 14-feature BOLA pipeline is not handled here.
 */
@Component
public class FeatureExtractor {

    /**
     * Canonical punctuation from entropy_utils.count_special_chars.
     * Space and other characters outside this set are not special.
     */
    /**
     * Same marker as ml_service.jndi_lookup. Case-insensitive, optional whitespace.
     * Applied to the raw header value and, when different, to its percent-decoded form.
     */
    static final Pattern JNDI_LOOKUP_PATTERN = Pattern.compile("\\$\\{\\s*jndi\\s*:", Pattern.CASE_INSENSITIVE);

    private static final Set<Character> SPECIAL_CHARS = new HashSet<>();

    static {
        for (char c : "!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~".toCharArray()) {
            SPECIAL_CHARS.add(c);
        }
    }

    /**
     * Shannon entropy: H(S) = -sum(p(c) * log2(p(c))). Empty input is 0.0.
     * Rounded to 6 decimal places, the same precision as the published parity vectors.
     */
    public double calculateShannonEntropy(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> freq = new LinkedHashMap<>();
        for (char c : s.toCharArray()) {
            freq.put(c, freq.getOrDefault(c, 0) + 1);
        }
        double total = s.length();
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = count / total;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return Math.round(entropy * 1000000.0) / 1000000.0;
    }

    public int countSpecialCharacters(String s) {
        if (s == null || s.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (char c : s.toCharArray()) {
            if (SPECIAL_CHARS.contains(c)) {
                count++;
            }
        }
        return count;
    }

    public int countDigits(String s) {
        if (s == null || s.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (char c : s.toCharArray()) {
            if (Character.isDigit(c)) {
                count++;
            }
        }
        return count;
    }

    public Map<String, Object> extractAtrdfFeatures(HttpServletRequest request, String requestBody) {
        Map<String, Object> features = new LinkedHashMap<>();

        String path = request.getRequestURI() != null ? request.getRequestURI() : "";
        String queryString = request.getQueryString() != null ? request.getQueryString() : "";
        // Servlet-reconstructed absolute URL plus the raw query string.
        // Not lowercased, not percent-decoded, and not rewritten when the host is localhost.
        // No further normalizer is defined by the training feature modules.
        String fullUrl = request.getRequestURL() != null ? request.getRequestURL().toString() : path;
        if (request.getQueryString() != null) {
            fullUrl += "?" + request.getQueryString();
        }

        String userAgent = request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "";
        String cookieHeader = request.getHeader("Cookie");
        String body = requestBody != null ? requestBody : "";

        features.put("url_entropy", calculateShannonEntropy(fullUrl));
        features.put("header_count", countRequestHeaders(request));
        features.put("path_length", path.length());
        features.put("url_special_count", countSpecialCharacters(fullUrl));
        features.put("url_length", fullUrl.length());
        features.put("path_segment_count", countPathSegments(path));
        features.put("cookie_present", (cookieHeader != null && !cookieHeader.trim().isEmpty()) ? 1 : 0);
        features.put("query_length", queryString.length());
        features.put("url_digit_count", countDigits(fullUrl));
        features.put("user_agent_entropy", calculateShannonEntropy(userAgent));
        features.put("query_parameter_count", countQueryParameters(request.getQueryString()));
        features.put("request_body_entropy", calculateShannonEntropy(body));
        features.put("request_body_digit_count", countDigits(body));

        return features;
    }

    /**
     * Experimental 14-feature map. The production extractor above stays at 13 features.
     * The marker is not a decision; the experimental model still scores the full vector.
     */
    public Map<String, Object> extractAtrdfExperimentalFeatures(HttpServletRequest request, String requestBody) {
        Map<String, Object> features = extractAtrdfFeatures(request, requestBody);
        features.put("jndi_lookup_marker", jndiLookupMarker(request, requestBody));
        return features;
    }

    /**
     * Original 13 features plus the seven payload-structure flags.
     * Used only by the experimental-payload profile.
     */
    public Map<String, Object> extractPayloadFeatures(HttpServletRequest request, String requestBody) {
        Map<String, Object> features = extractAtrdfFeatures(request, requestBody);
        features.putAll(PayloadFeatures.extractRequest(request, requestBody));
        return features;
    }

    /**
     * 1 when a non-metadata header, the path, the query, or the body contains the lookup marker.
     * Test ids and ground-truth headers are not feature inputs. This value is a model input, not a block.
     */
    public static int jndiLookupMarker(HttpServletRequest request) {
        return jndiLookupMarker(request, null);
    }

    public static int jndiLookupMarker(HttpServletRequest request, String body) {
        if (headerHasJndiLookup(request) || valueHasJndiLookup(body)) {
            return 1;
        }
        if (request == null) {
            return 0;
        }
        return valueHasJndiLookup(request.getRequestURI()) || valueHasJndiLookup(request.getQueryString()) ? 1 : 0;
    }

    private static boolean headerHasJndiLookup(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) {
            return false;
        }
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (isTestMetadataHeader(name)) {
                continue;
            }
            Enumeration<String> values = request.getHeaders(name);
            while (values != null && values.hasMoreElements()) {
                if (valueHasJndiLookup(values.nextElement())) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean valueHasJndiLookup(String value) {
        String current = value == null ? "" : value;
        String previous = null;
        for (int pass = 0; pass < 3 && !current.equals(previous); pass++) {
            if (JNDI_LOOKUP_PATTERN.matcher(current).find()) {
                return true;
            }
            previous = current;
            current = percentDecode(current);
        }
        return false;
    }

    static List<String> experimentalFeatureOrder() {
        List<String> order = new ArrayList<>();
        order.add("url_entropy");
        order.add("header_count");
        order.add("path_length");
        order.add("url_special_count");
        order.add("url_length");
        order.add("path_segment_count");
        order.add("cookie_present");
        order.add("query_length");
        order.add("url_digit_count");
        order.add("user_agent_entropy");
        order.add("query_parameter_count");
        order.add("request_body_entropy");
        order.add("request_body_digit_count");
        order.add("jndi_lookup_marker");
        return order;
    }

    /** Percent-decoding compatible with urllib.parse.unquote. Plus signs are preserved. */
    public static String percentDecode(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '%' && i + 2 < raw.length()) {
                int hi = Character.digit(raw.charAt(i + 1), 16);
                int lo = Character.digit(raw.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    bytes.write((hi << 4) + lo);
                    i += 2;
                    continue;
                }
            }
            if (c <= 0x7F) {
                bytes.write(c);
            } else {
                byte[] utf8 = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                bytes.write(utf8, 0, utf8.length);
            }
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * Count header names on the request.
     * Test metadata is excluded. Legitimate headers, including Sec-CH-* and Sec-Fetch-*, are kept.
     * The count is not remapped onto the old 5/15 buckets.
     */
    private int countRequestHeaders(HttpServletRequest request) {
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames == null) {
            return 0;
        }
        int headerCount = 0;
        while (headerNames.hasMoreElements()) {
            if (!isTestMetadataHeader(headerNames.nextElement())) {
                headerCount++;
            }
        }
        return headerCount;
    }

    public static boolean isTestMetadataHeader(String name) {
        if (name == null) {
            return false;
        }
        String header = name.toLowerCase(Locale.ROOT);
        return header.equals("x-ground-truth")
                || header.startsWith("x-test-")
                || header.startsWith("x-experiment-");
    }

    static int countPathSegments(String path) {
        if (path == null || path.isEmpty()) {
            return 0;
        }
        int segmentCount = 0;
        for (String segment : path.split("/", -1)) {
            if (!segment.isEmpty()) {
                segmentCount++;
            }
        }
        return segmentCount;
    }

    /**
     * Unique form-decoded query parameter names from the raw query string.
     * Body parameters are ignored. Duplicate names count once.
     * Empty segments and empty names are ignored. Valueless flags are counted.
     */
    static int countQueryParameters(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return 0;
        }
        Set<String> keys = new HashSet<>();
        for (String part : queryString.split("&", -1)) {
            if (part.isEmpty()) {
                continue;
            }
            int separator = part.indexOf('=');
            String rawKey = separator >= 0 ? part.substring(0, separator) : part;
            String key = formDecode(rawKey);
            if (!key.isEmpty()) {
                keys.add(key);
            }
        }
        return keys.size();
    }

    /**
     * application/x-www-form-urlencoded decoding compatible with urllib.parse.unquote_plus
     * for the ASCII and well-formed percent sequences used in request URLs.
     * Invalid percent sequences are left in place.
     */
    public static String formDecode(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '+') {
                bytes.write(' ');
                continue;
            }
            if (c == '%' && i + 2 < raw.length()) {
                int hi = Character.digit(raw.charAt(i + 1), 16);
                int lo = Character.digit(raw.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    bytes.write((hi << 4) + lo);
                    i += 2;
                    continue;
                }
            }
            if (c <= 0x7F) {
                bytes.write(c);
            } else {
                byte[] utf8 = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                bytes.write(utf8, 0, utf8.length);
            }
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }
}
