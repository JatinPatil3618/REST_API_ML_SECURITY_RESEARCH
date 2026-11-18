package com.apisecurity.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

/**
 * Review profiles let an encoded slash reach the filter so path traversal
 * can be scored and refused. The decoded path is not forwarded.
 * The production profile keeps Tomcat's default rejection.
 */
@Component
public class ReviewEncodedSlashCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    @Value("${gateway.atrdf.profile:production}")
    private String atrdfProfile = "production";

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        if (!"experimental-jndi".equalsIgnoreCase(atrdfProfile)
                && !"experimental-payload".equalsIgnoreCase(atrdfProfile)
                && !"pattern-reinforcement".equalsIgnoreCase(atrdfProfile)) {
            return;
        }
        factory.addConnectorCustomizers(connector -> connector.setEncodedSolidusHandling("passthrough"));
    }
}
