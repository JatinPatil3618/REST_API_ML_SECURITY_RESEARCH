package com.apisecurity.gateway.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

/**
 * Asks the demo API to verify a Bearer token. The gateway does not trust
 * X-Authenticated-User and does not read an unverified JWT payload.
 */
@Component
public class VerifiedIdentityResolver {

    private final RestTemplate restTemplate;

    @Value("${target.demo-api.url:http://localhost:5001}")
    private String demoApiUrl;

    public VerifiedIdentityResolver(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String resolve(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authorization.substring(7).trim();
        if (token.isEmpty()) {
            return null;
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        headers.setAccept(MediaType.parseMediaTypes(MediaType.APPLICATION_JSON_VALUE));
        try {
            var response = restTemplate.exchange(
                    URI.create(demoApiUrl + "/api/profile"),
                    HttpMethod.GET,
                    new HttpEntity<Void>(headers),
                    Map.class);
            if (response.getBody() == null) {
                return null;
            }
            Object username = response.getBody().get("username");
            if (username instanceof String value && !value.isBlank()) {
                return value;
            }
            return null;
        } catch (HttpStatusCodeException ex) {
            return null;
        } catch (RuntimeException ex) {
            return null;
        }
    }
}
