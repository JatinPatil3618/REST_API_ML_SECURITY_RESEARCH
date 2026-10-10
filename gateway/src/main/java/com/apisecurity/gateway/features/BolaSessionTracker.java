package com.apisecurity.gateway.features;

import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stateful BOLA Session Tracker.
 * Maintains rolling window of size W = 10 per session.
 * Excludes explicit identity and direct outcome fields from model representation.
 */
@Component
public class BolaSessionTracker {

    private static final int WINDOW_SIZE = 10;

    public static class RequestRecord {
        public String requestedObject;
        public String expectedOwner;
        public long timestampMs;

        public RequestRecord(String requestedObject, String expectedOwner, long timestampMs) {
            this.requestedObject = requestedObject;
            this.expectedOwner = expectedOwner;
            this.timestampMs = timestampMs;
        }
    }

    public static class SessionHistory {
        public List<RequestRecord> window = new ArrayList<>();
        public int totalRequests = 0;
        public long sessionStartMs = System.currentTimeMillis();
    }

    private final Map<String, SessionHistory> sessionMap = new ConcurrentHashMap<>();

    // Known object owners for simulation/context tracking
    private final Map<String, String> objectOwnerMap = new HashMap<>() {{
        put("101", "user01"); put("102", "user01");
        put("201", "user02"); put("202", "user02");
        put("301", "user03"); put("302", "user03");
        put("401", "user04"); put("402", "user04");
        put("501", "user05"); put("502", "user05");
    }};

    public String resolveOwner(String objectId) {
        return objectOwnerMap.getOrDefault(objectId, "unknown");
    }

    public Map<String, Object> recordAndExtract(String sessionKey, String user, String requestedObject) {
        if (sessionKey == null || sessionKey.isEmpty()) {
            sessionKey = "sess_default";
        }
        if (user == null || user.isEmpty()) {
            user = "anonymous";
        }

        SessionHistory history = sessionMap.computeIfAbsent(sessionKey, k -> new SessionHistory());
        long now = System.currentTimeMillis();
        String expectedOwner = resolveOwner(requestedObject);

        long timeSincePrev = 0;
        if (!history.window.isEmpty()) {
            RequestRecord last = history.window.get(history.window.size() - 1);
            timeSincePrev = Math.max(1, (now - last.timestampMs) / 1000);
        }

        // Add to history
        history.totalRequests++;
        RequestRecord current = new RequestRecord(requestedObject, expectedOwner, now);
        history.window.add(current);
        if (history.window.size() > WINDOW_SIZE) {
            history.window.remove(0);
        }

        int N = history.window.size();
        Set<String> uniqueObjs = new HashSet<>();
        Set<String> uniqueOwners = new HashSet<>();
        int crossOwnerCount = 0;
        int objectSwitches = 0;
        int ownerSwitches = 0;
        int sameObjectRepeats = 0;

        for (int i = 0; i < N; i++) {
            RequestRecord rec = history.window.get(i);
            uniqueObjs.add(rec.requestedObject);
            uniqueOwners.add(rec.expectedOwner);

            if (!rec.expectedOwner.equals(user) && !rec.expectedOwner.equals("unknown")) {
                crossOwnerCount++;
            }

            if (i > 0) {
                RequestRecord prev = history.window.get(i - 1);
                if (!rec.requestedObject.equals(prev.requestedObject)) {
                    objectSwitches++;
                } else {
                    sameObjectRepeats++;
                }
                if (!rec.expectedOwner.equals(prev.expectedOwner)) {
                    ownerSwitches++;
                }
            }
        }

        double crossOwnerRatio = N > 0 ? (double) crossOwnerCount / N : 0.0;
        double sameOwnerRatio = 1.0 - crossOwnerRatio;
        double repeatRatio = N > 1 ? (double) sameObjectRepeats / (N - 1) : 0.0;

        long sessionElapsedSec = Math.max(1, (now - history.sessionStartMs) / 1000);
        double requestFreq = (double) history.totalRequests / sessionElapsedSec;
        double burstRate = timeSincePrev > 0 ? 1.0 / timeSincePrev : 5.0;

        Map<String, Object> features = new LinkedHashMap<>();
        features.put("request_frequency", Math.round(requestFreq * 1000.0) / 1000.0);
        features.put("unique_objects_recent", uniqueObjs.size());
        features.put("object_switch", objectSwitches > 0 ? 1 : 0);
        features.put("unique_owners_recent", uniqueOwners.size());
        features.put("owner_switch", ownerSwitches > 0 ? 1 : 0);
        features.put("cross_owner_count_recent", crossOwnerCount);
        features.put("cross_owner_ratio_recent", Math.round(crossOwnerRatio * 10000.0) / 10000.0);
        features.put("same_owner_ratio_recent", Math.round(sameOwnerRatio * 10000.0) / 10000.0);
        features.put("same_object_repeat_ratio", Math.round(repeatRatio * 10000.0) / 10000.0);
        features.put("time_since_previous_request", (double) timeSincePrev);
        features.put("request_burst_rate", Math.round(burstRate * 1000.0) / 1000.0);
        features.put("hour", LocalDateTime.now().getHour());
        features.put("session_length", Math.min(history.totalRequests, 50));
        features.put("request_index", history.totalRequests);

        return features;
    }
}
