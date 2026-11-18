package com.apisecurity.gateway.features;

import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The seven structural flags appended after the original 13 ATRDF features.
 * The formulas match ml_service/payload_features.py. Labels and test ids are not read.
 */
public final class PayloadFeatures {

    public static final List<String> NAMES = List.of(
            "sql_structure",
            "markup_script",
            "path_traversal",
            "command_chain",
            "cookie_signal",
            "log_control",
            "jndi_lookup"
    );

    private static final Pattern SQL_OR = Pattern.compile("'\\s*or\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_SELECT = Pattern.compile("\\bselect\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_COMMENT = Pattern.compile("--");
    private static final Pattern SQL_UNION = Pattern.compile("\\bunion\\s+select\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern MARKUP = Pattern.compile(
            "<\\s*script\\b|\\balert\\s*\\(|\\bon(?:error|load|click|mouseover)\\s*=",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern TRAVERSAL = Pattern.compile("\\.\\./|\\.\\.\\\\");
    private static final Pattern COMMAND = Pattern.compile(
            "(?:;|\\||&&|`)\\s*(?:cat|nc|bash|sh|cmd|powershell|wget|curl)\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern TEMPLATE = Pattern.compile(
            "\\{\\{|__globals__|__builtins__|__import__",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern COOKIE_WORD = Pattern.compile("cookie", Pattern.CASE_INSENSITIVE);
    private static final Pattern LOG_CONTROL = Pattern.compile("%0a|%0d|\\r|\\n|\\\\r|\\\\n", Pattern.CASE_INSENSITIVE);
    private static final Pattern JNDI = Pattern.compile("\\$\\{\\s*jndi\\s*:", Pattern.CASE_INSENSITIVE);
    private static final Set<String> COOKIE_AUTHORITY = Set.of("admin", "role");

    private PayloadFeatures() {
    }

    public static Map<String, Integer> extract(String path, String query, String body, String userAgent,
                                               List<String> headerValues, String cookieHeader) {
        return extract(path, query, body, userAgent, headerValues, cookieHeader, null);
    }

    public static Map<String, Integer> extract(String path, String query, String body, String userAgent,
                                               List<String> headerValues, String cookieHeader,
                                               List<String> lookupHeaderValues) {
        String text = contentText(path, query, body, userAgent, headerValues);
        String sensitive = text;
        if (lookupHeaderValues != null && !lookupHeaderValues.isEmpty()) {
            StringBuilder extra = new StringBuilder(text);
            for (String value : lookupHeaderValues) {
                extra.append('\u0001').append(unfold(value));
            }
            sensitive = extra.toString();
        }
        boolean sql = SQL_OR.matcher(text).find()
                || SQL_UNION.matcher(text).find()
                || (SQL_SELECT.matcher(text).find() && SQL_COMMENT.matcher(text).find());
        Map<String, Integer> features = new LinkedHashMap<>();
        features.put("sql_structure", sql ? 1 : 0);
        features.put("markup_script", MARKUP.matcher(sensitive).find() ? 1 : 0);
        features.put("path_traversal", TRAVERSAL.matcher(text).find() ? 1 : 0);
        features.put("command_chain", COMMAND.matcher(text).find() || TEMPLATE.matcher(text).find() ? 1 : 0);
        features.put("cookie_signal", cookieSignal(text, cookieHeader));
        features.put("log_control", LOG_CONTROL.matcher(text).find() ? 1 : 0);
        features.put("jndi_lookup", JNDI.matcher(sensitive).find() ? 1 : 0);
        return features;
    }

    public static Map<String, Integer> extractRequest(HttpServletRequest request, String body) {
        String path = request.getRequestURI() == null ? "" : request.getRequestURI();
        String query = request.getQueryString() == null ? "" : request.getQueryString();
        String userAgent = header(request, "User-Agent");
        String cookie = header(request, "Cookie");
        List<String> headerValues = new ArrayList<>();
        List<String> lookupHeaderValues = new ArrayList<>();
        var names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (FeatureExtractor.isTestMetadataHeader(name) || "user-agent".equalsIgnoreCase(name) || "cookie".equalsIgnoreCase(name)) {
                continue;
            }
            boolean setCookie = "set-cookie".equalsIgnoreCase(name);
            var values = request.getHeaders(name);
            while (values != null && values.hasMoreElements()) {
                String value = values.nextElement();
                if (setCookie) {
                    lookupHeaderValues.add(value);
                } else {
                    headerValues.add(value);
                }
            }
        }
        return extract(path, query, body, userAgent, headerValues, cookie, lookupHeaderValues);
    }

    static String unfold(String value) {
        String raw = value == null ? "" : value;
        String once = FeatureExtractor.percentDecode(raw);
        String twice = FeatureExtractor.percentDecode(once);
        String form = FeatureExtractor.formDecode(raw);
        return raw + "\u0001" + once + "\u0001" + twice + "\u0001" + form;
    }

    private static String contentText(String path, String query, String body, String userAgent, List<String> headerValues) {
        StringBuilder text = new StringBuilder();
        text.append(unfold(path)).append('\u0001');
        text.append(unfold(query)).append('\u0001');
        text.append(unfold(body)).append('\u0001');
        text.append(unfold(userAgent));
        if (headerValues != null) {
            for (String value : headerValues) {
                text.append('\u0001').append(unfold(value));
            }
        }
        return text.toString();
    }

    private static int cookieSignal(String text, String cookieHeader) {
        if (COOKIE_WORD.matcher(text).find()) {
            return 1;
        }
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return 0;
        }
        for (String part : cookieHeader.split(";")) {
            String name = part.split("=", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (COOKIE_AUTHORITY.contains(name)) {
                return 1;
            }
        }
        return 0;
    }

    private static String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value;
    }
}
