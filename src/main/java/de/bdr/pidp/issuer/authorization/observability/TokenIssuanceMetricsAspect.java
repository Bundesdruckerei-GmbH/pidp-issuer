/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

@Aspect
@Component
class TokenIssuanceMetricsAspect {

    private final Counter refreshTokenIssuedCounter;
    private final Counter accessTokenIssuedCounter;

    TokenIssuanceMetricsAspect(MeterRegistry meterRegistry) {
        this.refreshTokenIssuedCounter = Counter.builder("token.refresh_token.issued")
            .description("Number of refresh tokens issued")
            .register(meterRegistry);

        this.accessTokenIssuedCounter = Counter.builder("token.access_token_by_refresh_token.issued")
            .description("Number of access tokens issued by refresh token")
            .register(meterRegistry);
    }

    @AfterReturning(
        pointcut = "execution(* de.bdr.pidp.issuer.authorization.in.OAuthController.token(..))",
        returning = "result"
    )
    void countRefreshTokenIssued(@Nullable ResponseEntity<JsonNode> result) {
        if (result != null && result.getBody() != null) {
            JsonNode body = result.getBody();
            if (body.has("refresh_token")) {
                refreshTokenIssuedCounter.increment();
            }
        }
    }

    @AfterReturning(
        pointcut = "execution(* de.bdr.pidp.issuer.authorization.in.OAuthController.refreshToken(..))",
        returning = "result"
    )
    void countAccessTokenIssued(@Nullable ResponseEntity<JsonNode> result) {
        if (result != null && result.getBody() != null) {
            JsonNode body = result.getBody();
            if (body.has("access_token")) {
                accessTokenIssuedCounter.increment();
            }
        }
    }
}
