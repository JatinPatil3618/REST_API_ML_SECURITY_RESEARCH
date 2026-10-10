package com.apisecurity.gateway.decision;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class DecisionEngineTest {

    private DecisionEngine decisionEngine;

    @BeforeEach
    public void setup() {
        decisionEngine = new DecisionEngine();
        ReflectionTestUtils.setField(decisionEngine, "defaultConfidenceThreshold", 0.70);
        ReflectionTestUtils.setField(decisionEngine, "failSafeMode", "ALERT");
    }

    @Test
    public void testHonestConfidenceExtractedOnBlock() {
        Map<String, Object> mlResult = new HashMap<>();
        mlResult.put("decision", "BLOCK");
        mlResult.put("attack_family", "ATRDF");
        mlResult.put("predicted_class", "SQL Injection");
        mlResult.put("confidence", 0.7845);
        mlResult.put("mitigation", "BLOCK + parameterized query path");

        DecisionEngine.SecurityDecision dec = decisionEngine.evaluate(mlResult, "ATRDF");

        assertEquals("BLOCK", dec.action);
        assertEquals("SQL Injection", dec.predictedClass);
        assertEquals(0.7845, dec.confidence, 0.0001, "Confidence must match genuine model probability");
        assertNotEquals(0.95, dec.confidence, "Confidence must not be fabricated to 0.95");
        assertEquals(403, dec.httpStatusCode);
    }

    @Test
    public void testHonestConfidenceExtractedOnAllow() {
        Map<String, Object> mlResult = new HashMap<>();
        mlResult.put("decision", "ALLOW");
        mlResult.put("attack_family", "BENIGN");
        mlResult.put("predicted_class", "BENIGN");
        mlResult.put("confidence", 0.6521);
        mlResult.put("mitigation", "ALLOW");

        DecisionEngine.SecurityDecision dec = decisionEngine.evaluate(mlResult, "ATRDF");

        assertEquals("ALLOW", dec.action);
        assertEquals("BENIGN", dec.predictedClass);
        assertEquals(0.6521, dec.confidence, 0.0001, "Confidence must match genuine model probability");
        assertNotEquals(0.99, dec.confidence, "Confidence must not be fabricated to 0.99");
        assertEquals(200, dec.httpStatusCode);
    }

    @Test
    public void testNestedMulticlassDetectionConfidenceExtraction() {
        Map<String, Object> mlResult = new HashMap<>();
        mlResult.put("decision", "BLOCK");
        mlResult.put("attack_family", "ATRDF");
        mlResult.put("predicted_class", "XSS");
        Map<String, Object> multiDet = new HashMap<>();
        multiDet.put("confidence", 0.8123);
        mlResult.put("multiclass_detection", multiDet);

        DecisionEngine.SecurityDecision dec = decisionEngine.evaluate(mlResult, "ATRDF");

        assertEquals("BLOCK", dec.action);
        assertEquals(0.8123, dec.confidence, 0.0001);
    }

    @Test
    public void testFailSafeOnMlErrorDoesNotInventPrediction() {
        Map<String, Object> mlResult = new HashMap<>();
        mlResult.put("error", "ML prediction unavailable: Connection refused");

        DecisionEngine.SecurityDecision dec = decisionEngine.evaluate(mlResult, "ATRDF");

        assertEquals("ALERT", dec.action, "Fail-safe action must be configured ALERT");
        assertEquals("UNAVAILABLE", dec.predictedClass);
        assertEquals(0.0, dec.confidence, 0.0001, "Confidence must be 0.0 when unavailable");
    }

    @Test
    public void testNullResultProducesFailSafe() {
        DecisionEngine.SecurityDecision dec = decisionEngine.evaluate(null, "ATRDF");

        assertEquals("ALERT", dec.action);
        assertEquals("UNAVAILABLE", dec.predictedClass);
        assertEquals(0.0, dec.confidence, 0.0001);
    }
}
