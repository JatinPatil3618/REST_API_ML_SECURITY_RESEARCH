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
 * Training-only benign GETs. These requests are not the 35-case controlled suite.
 * Feature maps come only from FeatureExtractor. Labels stay in the manifest.
 */
public class BenignAugmentationExtractorTest {

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    private static final String HOST = "127.0.0.1:8080";

    @Test
    public void extractAugmentationReads() throws Exception {
        FeatureExtractor extractor = new FeatureExtractor();
        List<Map<String, Object>> featuresOnly = new ArrayList<>();
        List<Map<String, Object>> manifest = new ArrayList<>();
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
            Map<String, Object> features = extractor.extractAtrdfFeatures(request, "");
            String caseId = String.format("A%02d", number);
            Map<String, Object> featureRow = new LinkedHashMap<>();
            featureRow.put("case_id", caseId);
            featureRow.put("features", features);
            featuresOnly.add(featureRow);

            Map<String, Object> manifestRow = new LinkedHashMap<>();
            manifestRow.put("case_id", caseId);
            manifestRow.put("method", "GET");
            manifestRow.put("route", spec.route);
            manifestRow.put("query", spec.query);
            manifestRow.put("header_profile", spec.profile);
            manifestRow.put("header_names", headerNames);
            manifestRow.put("specification_label", "BENIGN");
            manifestRow.put("benign_reason", spec.reason);
            manifest.add(manifestRow);

            int extracted = ((Number) features.get("header_count")).intValue();
            assertEquals(headerNames.size(), extracted, caseId);
            assertTrue(extracted >= 2 && extracted <= 6, caseId);
            number++;
        }

        Path directory = Paths.get("..", "research", "atrdf_header_count_ablation",
                "benign_augmentation").toAbsolutePath().normalize();
        Files.createDirectories(directory);
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(directory.resolve("augmentation_features.json").toFile(), featuresOnly);
        mapper.writeValue(directory.resolve("augmentation_manifest.json").toFile(), manifest);
        assertTrue(manifest.size() >= 20 && manifest.size() <= 40, "count " + manifest.size());
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
        specs.add(new CaseSpec("/api/books", "search=network", "H2",
                "search=network matches seeded title Foundations of Network Protocol Security"));
        specs.add(new CaseSpec("/api/books", "search=network", "H6",
                "same supported catalog search with six ordinary headers"));
        specs.add(new CaseSpec("/api/books", "search=cloud", "H3",
                "search=cloud matches seeded title Zero Trust Architecture in Cloud Systems"));
        specs.add(new CaseSpec("/api/books", "search=cryptography", "H4",
                "search=cryptography matches seeded title Cryptography and Public Key Infrastructure"));
        specs.add(new CaseSpec("/api/books", "search=consensus", "H5",
                "search=consensus matches seeded title Distributed Systems Consensus Algorithms"));
        specs.add(new CaseSpec("/api/books", "search=database", "H2",
                "search=database matches seeded title Database Internals and Query Optimization"));
        specs.add(new CaseSpec("/api/books", "search=forest", "H3",
                "search=forest matches seeded description text Random Forests"));
        specs.add(new CaseSpec("/api/books", "search=defect", "H6",
                "search=defect matches seeded description text defect prediction"));
        specs.add(new CaseSpec("/api/books", "search=network&category=Technology", "H4",
                "book 101 is category Technology and its title contains Network"));
        specs.add(new CaseSpec("/api/books", "search=cloud&category=Technology", "H2",
                "book 102 is category Technology and its title contains Cloud"));
        specs.add(new CaseSpec("/api/books", "search=cryptography&category=Mathematics", "H5",
                "book 301 is category Mathematics and its title contains Cryptography"));
        specs.add(new CaseSpec("/api/books", "search=consensus&category=Computer%20Science", "H3",
                "book 401 is category Computer Science and its title contains Consensus"));
        specs.add(new CaseSpec("/api/books", "search=database&category=Computer%20Science", "H6",
                "book 402 is category Computer Science and its title contains Database"));
        specs.add(new CaseSpec("/api/books", "search=forest&category=Science", "H4",
                "book 201 is category Science and its description contains Forests"));
        specs.add(new CaseSpec("/api/books", "search=defect&category=Engineering", "H5",
                "book 202 is category Engineering and its description contains defect"));
        specs.add(new CaseSpec("/api/books", "search=defensive&category=Technology", "H2",
                "book 501 is category Technology and its title contains Defensive"));
        specs.add(new CaseSpec("/api/comments/book/102", null, "H2",
                "GET comments for seeded book 102; the route returns the comment list"));
        specs.add(new CaseSpec("/api/comments/book/102", null, "H6",
                "same comments route for book 102 with six ordinary headers"));
        specs.add(new CaseSpec("/api/comments/book/202", null, "H3",
                "GET comments for seeded book 202"));
        specs.add(new CaseSpec("/api/comments/book/301", null, "H4",
                "GET comments for seeded book 301"));
        specs.add(new CaseSpec("/api/comments/book/401", null, "H5",
                "GET comments for seeded book 401"));
        specs.add(new CaseSpec("/api/comments/book/402", null, "H2",
                "GET comments for seeded book 402"));
        specs.add(new CaseSpec("/api/comments/book/501", null, "H3",
                "GET comments for seeded book 501"));
        specs.add(new CaseSpec("/api/comments/book/502", null, "H6",
                "GET comments for seeded book 502"));
        specs.add(new CaseSpec("/", null, "H4",
                "GET / is the unauthenticated demo API status document; this header profile is not in the 35-case suite"));
        specs.add(new CaseSpec("/", null, "H5",
                "same status route with five ordinary headers; H2, H3, and H6 for / are reserved for the suite"));
        return specs;
    }

    private static final class CaseSpec {
        private final String route;
        private final String query;
        private final String profile;
        private final String reason;

        private CaseSpec(String route, String query, String profile, String reason) {
            this.route = route;
            this.query = query;
            this.profile = profile;
            this.reason = reason;
        }
    }
}
