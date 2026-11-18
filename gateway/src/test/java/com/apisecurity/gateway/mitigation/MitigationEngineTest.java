package com.apisecurity.gateway.mitigation;

import com.apisecurity.gateway.decision.DecisionEngine;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;

public class MitigationEngineTest {

    @Test
    public void redactStripsControlCharacters() {
        assertEquals("a b c", MitigationEngine.redact("a\r\nb\nc"));
    }

    @Test
    public void catalogKeepsOriginalSqlString() {
        assertEquals("BLOCK + parameterized query path",
                MitigationCatalog.forClass("SQL Injection").mitigation);
        assertTrue(MitigationCatalog.forClass("SQL Injection").techniques.contains("hard_block"));
        assertTrue(MitigationCatalog.forClass("SQL Injection").techniques.contains("no_sql_execution"));
    }

    @Test
    public void cookieInjectionClearsSessionCookies() {
        MitigationEngine engine = new MitigationEngine();
        DecisionEngine.SecurityDecision decision = new DecisionEngine.SecurityDecision(
                "BLOCK", "ATRDF", "Cookie Injection", 0.9,
                "BLOCK + session validation", "Invalid session", 401);
        engine.attachTechniques(decision);
        MockHttpServletResponse response = new MockHttpServletResponse();
        engine.applyBlockControls(new MockHttpServletRequest(), response, decision, null);
        String cookies = String.join(" | ", response.getHeaders("Set-Cookie"));
        assertTrue(cookies.contains("Max-Age=0"));
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertTrue(response.getHeader("X-Mitigation-Techniques").contains("invalidate_session_cookie"));
    }

    @Test
    public void rateLimitTripsAfterBurst() {
        MitigationEngine engine = new MitigationEngine();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.9");
        for (int i = 0; i < 8; i++) {
            assertFalse(engine.rateLimitExceeded(request));
            engine.recordBlock(request);
        }
        assertTrue(engine.rateLimitExceeded(request));
    }
}
