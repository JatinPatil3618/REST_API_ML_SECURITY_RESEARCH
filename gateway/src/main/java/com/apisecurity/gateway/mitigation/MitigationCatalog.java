package com.apisecurity.gateway.mitigation;

import java.util.List;
import java.util.Map;

/**
 * Keeps the original mitigation strings and lists the actions the gateway runs.
 */
public final class MitigationCatalog {

    public static final class Entry {
        public final String mitigation;
        public final List<String> techniques;

        Entry(String mitigation, List<String> techniques) {
            this.mitigation = mitigation;
            this.techniques = techniques;
        }
    }

    private static final Map<String, Entry> BY_CLASS = Map.of(
            "SQL Injection", new Entry("BLOCK + parameterized query path",
                    List.of("hard_block", "reject_untrusted_query", "no_sql_execution")),
            "Cookie Injection", new Entry("BLOCK + session validation",
                    List.of("hard_block", "invalidate_session_cookie", "require_reauthentication")),
            "Log Forging", new Entry("BLOCK / ALERT + structured logging",
                    List.of("hard_block", "redact_control_characters")),
            "RCE", new Entry("BLOCK (Execution: NOT PERFORMED)",
                    List.of("hard_block", "never_execute_command")),
            "Directory Traversal", new Entry("BLOCK + path validation",
                    List.of("hard_block", "reject_path_escape")),
            "LOG4J", new Entry("BLOCK / ALERT + safe logging",
                    List.of("hard_block", "drop_jndi_lookup", "redact_control_characters")),
            "XSS", new Entry("BLOCK / ALERT + safe rendering",
                    List.of("hard_block", "content_security_policy")),
            "BOLA", new Entry("BLOCK + authorization",
                    List.of("alert_and_authorize", "backend_owner_check")),
            "BENIGN", new Entry("ALLOW", List.of("forward"))
    );

    private MitigationCatalog() {
    }

    public static Entry forClass(String predictedClass) {
        if (predictedClass == null || predictedClass.isBlank()) {
            return new Entry("BLOCK", List.of("hard_block"));
        }
        Entry found = BY_CLASS.get(predictedClass);
        if (found != null) {
            return found;
        }
        if ("BOLA".equalsIgnoreCase(predictedClass)) {
            return BY_CLASS.get("BOLA");
        }
        return new Entry("BLOCK", List.of("hard_block"));
    }
}
