package com.apisecurity.gateway.features;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Controlled benign reads of routes that exist on the demo API and that the
 * gateway classifies as ATRDF. Feature maps come only from FeatureExtractor.
 * Specification labels are stored beside the vectors and are not extractor input.
 */
public class DeploymentShiftAtrdfSuiteTest {

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    private static final String HOST = "127.0.0.1:8080";

    @Test
    public void extractControlledBenignReads() throws Exception {
        FeatureExtractor extractor = new FeatureExtractor();
        List<Map<String, Object>> cases = new ArrayList<>();
        int number = 1;
        for (CaseSpec spec : specs()) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", spec.route);
            request.setScheme("http");
            request.setServerName("127.0.0.1");
            request.setServerPort(8080);
            request.setRequestURI(spec.route);
            if (spec.query != null) {
                request.setQueryString(spec.query);
            }
            List<String> headerNames = addHeaders(request, spec.profile);
            Map<String, Object> features = null;
            String error = null;
            try {
                features = extractor.extractAtrdfFeatures(request, "");
            } catch (RuntimeException ex) {
                error = ex.getClass().getSimpleName();
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("case_id", String.format("C%02d", number));
            row.put("method", "GET");
            row.put("route", spec.route);
            row.put("query", spec.query);
            row.put("header_profile", spec.profile);
            row.put("header_names", headerNames);
            row.put("specification_label", "BENIGN");
            row.put("gateway_pipeline", "ATRDF");
            row.put("features", features);
            row.put("extraction_error", error);
            cases.add(row);
            number++;
        }

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("extractor", FeatureExtractor.class.getName());
        document.put("host", HOST);
        document.put("specification_note",
                "specification_label is assigned by this harness and is not a model input.");
        document.put("case_count", cases.size());
        document.put("cases", cases);

        Path output = Paths.get("..", "research", "atrdf_header_count_ablation",
                "controlled_suite_features.json").toAbsolutePath().normalize();
        assertTrue(Files.isDirectory(output.getParent()), output.getParent().toString());
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(output.toFile(), document);

        assertTrue(cases.size() >= 25 && cases.size() <= 40, "case count " + cases.size());
        for (Map<String, Object> row : cases) {
            assertEquals(null, row.get("extraction_error"), String.valueOf(row.get("case_id")));
            @SuppressWarnings("unchecked")
            Map<String, Object> features = (Map<String, Object>) row.get("features");
            int extracted = ((Number) features.get("header_count")).intValue();
            @SuppressWarnings("unchecked")
            List<String> names = (List<String>) row.get("header_names");
            assertEquals(names.size(), extracted, String.valueOf(row.get("case_id")));
            assertTrue(extracted >= 2 && extracted <= 6, String.valueOf(row.get("case_id")));
        }
    }

    private static List<String> addHeaders(MockHttpServletRequest request, String profile) {
        List<String> names = new ArrayList<>();
        names.add("Host");
        request.addHeader("Host", HOST);
        names.add("User-Agent");
        request.addHeader("User-Agent", USER_AGENT);
        if ("H2".equals(profile)) {
            return names;
        }
        names.add("Accept");
        request.addHeader("Accept", "application/json");
        if ("H3".equals(profile)) {
            return names;
        }
        names.add("Accept-Language");
        request.addHeader("Accept-Language", "en-US,en;q=0.9");
        if ("H4".equals(profile)) {
            return names;
        }
        names.add("Accept-Encoding");
        request.addHeader("Accept-Encoding", "gzip, deflate");
        if ("H5".equals(profile)) {
            return names;
        }
        names.add("Connection");
        request.addHeader("Connection", "keep-alive");
        return names;
    }

    private static List<CaseSpec> specs() {
        List<CaseSpec> specs = new ArrayList<>();
        for (String profile : List.of("H2", "H3", "H4", "H5", "H6")) {
            specs.add(new CaseSpec("/api/books", null, profile));
            specs.add(new CaseSpec("/api/comments/book/101", null, profile));
            specs.add(new CaseSpec("/api/health", null, profile));
        }
        specs.add(new CaseSpec("/", null, "H2"));
        specs.add(new CaseSpec("/", null, "H3"));
        specs.add(new CaseSpec("/", null, "H6"));
        specs.add(new CaseSpec("/api/books", "search=protocol", "H3"));
        specs.add(new CaseSpec("/api/books", "search=maths", "H3"));
        specs.add(new CaseSpec("/api/books", "category=Technology", "H3"));
        specs.add(new CaseSpec("/api/books", "category=Science", "H3"));
        specs.add(new CaseSpec("/api/books", "category=Engineering", "H3"));
        specs.add(new CaseSpec("/api/books", "category=Mathematics", "H3"));
        specs.add(new CaseSpec("/api/books", "category=Computer%20Science", "H3"));
        specs.add(new CaseSpec("/api/books", "search=gateway&category=Technology", "H3"));
        specs.add(new CaseSpec("/api/books", "category=All", "H3"));
        specs.add(new CaseSpec("/api/comments/book/201", null, "H3"));
        specs.add(new CaseSpec("/api/comments/book/302", null, "H3"));
        specs.add(new CaseSpec("/api/books", "search=protocol", "H2"));
        specs.add(new CaseSpec("/api/books", "search=protocol", "H6"));
        specs.add(new CaseSpec("/api/books", "category=Technology", "H5"));
        specs.add(new CaseSpec("/api/comments/book/201", null, "H4"));
        specs.add(new CaseSpec("/api/comments/book/302", null, "H6"));
        specs.add(new CaseSpec("/api/books", "search=anomaly", "H4"));
        return specs;
    }

    private static final class CaseSpec {
        private final String route;
        private final String query;
        private final String profile;

        private CaseSpec(String route, String query, String profile) {
            this.route = route;
            this.query = query;
            this.profile = profile;
        }
    }
}
