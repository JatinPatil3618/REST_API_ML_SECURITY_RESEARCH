package com.apisecurity.gateway.decision;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DecisionEngine {

    @Value("${gateway.confidence.threshold:0.70}")
    private double defaultConfidenceThreshold;

    @Value("${gateway.fail-safe.mode:ALERT}")
    private String failSafeMode;

    public static class SecurityDecision {
        public String action; // ALLOW, BLOCK, ALERT
        public String attackFamily;
        public String predictedClass;
        public double confidence;
        public String mitigation;
        public String userMessage;
        public int httpStatusCode;

        public SecurityDecision(String action, String attackFamily, String predictedClass, double confidence, String mitigation, String userMessage, int httpStatusCode) {
            this.action = action;
            this.attackFamily = attackFamily;
            this.predictedClass = predictedClass;
            this.confidence = confidence;
            this.mitigation = mitigation;
            this.userMessage = userMessage;
            this.httpStatusCode = httpStatusCode;
        }
    }

    public SecurityDecision evaluate(Map<String, Object> mlResult, String mode) {
        if (mlResult == null || mlResult.containsKey("error")) {
            return new SecurityDecision(
                failSafeMode,
                "UNKNOWN",
                "UNAVAILABLE",
                0.0,
                "Fail-safe Alert",
                "Security verification temporarily unavailable",
                200
            );
        }

        String decision = (String) mlResult.getOrDefault("decision", "ALLOW");
        String attackFamily = (String) mlResult.getOrDefault("attack_family", "BENIGN");
        String mitigation = (String) mlResult.getOrDefault("mitigation", "ALLOW");
        String predictedClass = (String) mlResult.getOrDefault("predicted_class", "NORMAL");

        if ("BLOCK".equalsIgnoreCase(decision)) {
            String userMsg;
            int status = 403;

            if ("BOLA".equalsIgnoreCase(attackFamily)) {
                userMsg = "Access denied. This book belongs to another user.";
            } else {
                switch (predictedClass) {
                    case "XSS":
                        userMsg = "Unsafe content blocked.";
                        break;
                    case "SQL Injection":
                        userMsg = "Suspicious query input detected and rejected.";
                        break;
                    case "Cookie Injection":
                        userMsg = "Invalid session state. Reauthentication required.";
                        status = 401;
                        break;
                    case "Log Forging":
                        userMsg = "Malformed logging input detected.";
                        break;
                    case "RCE":
                        userMsg = "Command execution attempt blocked. No command was executed.";
                        break;
                    case "Directory Traversal":
                        userMsg = "Invalid resource path.";
                        break;
                    case "LOG4J":
                        userMsg = "Dangerous lookup pattern blocked.";
                        break;
                    default:
                        userMsg = "Request blocked due to security policy violation.";
                }
            }

            return new SecurityDecision(
                "BLOCK",
                attackFamily,
                predictedClass,
                0.95,
                mitigation,
                userMsg,
                status
            );
        }

        return new SecurityDecision(
            "ALLOW",
            "BENIGN",
            "BENIGN",
            0.99,
            "ALLOW",
            "Request allowed",
            200
        );
    }
}
