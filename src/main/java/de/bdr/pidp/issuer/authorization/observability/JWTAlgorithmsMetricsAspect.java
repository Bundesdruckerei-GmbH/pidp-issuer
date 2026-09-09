/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.domain.ParRequest;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenRequest;
import de.bdr.pidp.issuer.authorization.core.domain.TokenRequest;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Aspect
@Component
class JWTAlgorithmsMetricsAspect {
    protected static final String DPOP_METRIC_NAME = "algorithms.dpop";
    protected static final String CLIENT_ATTESTATION_METRIC_NAME = "algorithms.client_attestation";
    protected static final String CLIENT_ATTESTATION_POP_METRIC_NAME = "algorithms.client_attestation_pop";
    protected static final String COUNTER_TAG_KEY = "algorithm";

    private final Map<String, Counter> dpopCounters = new ConcurrentHashMap<>();
    private final Map<String, Counter> clientAttestationCounters = new ConcurrentHashMap<>();
    private final Map<String, Counter> clientAttestationPopCounters = new ConcurrentHashMap<>();
    private final MeterRegistry meterRegistry;

    JWTAlgorithmsMetricsAspect(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Pointcut("execution(public * de.bdr.pidp.issuer.authorization.core.flows.TokenService.processTokenRequest(..)) && args(request)")
    public void tokenRequestExecution(TokenRequest request) { /* pointcut body is empty */ }

    @AfterReturning(value = "tokenRequestExecution(request)", argNames = "request")
    public void afterSuccessfulTokenRequest(TokenRequest request) {
        incDpopCounter(request.getDpopHeaders());
    }

    @Pointcut("execution(public * de.bdr.pidp.issuer.authorization.core.flows.ParService.processPushedAuthRequest(..)) && args(request)")
    public void parRequestExecution(ParRequest request) { /* pointcut body is empty */ }

    @AfterReturning(value = "parRequestExecution(request)", argNames = "request")
    public void afterSuccessfulParRequest(ParRequest request) {
        incClientAttestationCounter(request.getAttestation());
        incClientAttestationPoPCounter(request.getAttestationPoP());
    }

    @Pointcut("execution(public * de.bdr.pidp.issuer.authorization.core.flows.TokenService.processRefreshTokenRequest(..)) && args(request)")
    public void refreshTokenRequestExecution(RefreshTokenRequest request) { /* pointcut body is empty */ }

    @AfterReturning(value = "refreshTokenRequestExecution(request)", argNames = "request")
    public void afterSuccessfulRefreshTokenRequest(RefreshTokenRequest request) {
        incDpopCounter(request.getDpopHeaders());
        incClientAttestationCounter(request.getAttestation());
        incClientAttestationPoPCounter(request.getAttestationPoP());
    }

    private void incDpopCounter(@Nullable List<String> dpopHeaders) {
        if (dpopHeaders != null) {
            final String dpopJwt = dpopHeaders.getFirst();

            String alg = parseAlgFromJwt(dpopJwt);
            if (alg != null) {
                Counter counter = dpopCounters.computeIfAbsent(alg,
                    a -> Counter.builder(DPOP_METRIC_NAME)
                        .description("Total number of DPoP JWT algorithms")
                        .tag(COUNTER_TAG_KEY, a)
                        .register(meterRegistry));

                counter.increment();
            }
        }
    }

    private void incClientAttestationCounter(SignedJWT attestation) {
        String alg = attestation.getHeader().getAlgorithm().getName();
        if (alg != null) {
            Counter counter = clientAttestationCounters.computeIfAbsent(alg,
                a -> Counter.builder(CLIENT_ATTESTATION_METRIC_NAME)
                    .description("Total number of client attestation JWT algorithms")
                    .tag(COUNTER_TAG_KEY, a)
                    .register(meterRegistry));

            counter.increment();
        }
    }

    private void incClientAttestationPoPCounter(SignedJWT attestationPoP) {
        String alg = attestationPoP.getHeader().getAlgorithm().getName();
        if (alg != null) {
            Counter counter = clientAttestationPopCounters.computeIfAbsent(alg,
                a -> Counter.builder(CLIENT_ATTESTATION_POP_METRIC_NAME)
                    .description("Total number of client attestation PoP JWT algorithms")
                    .tag(COUNTER_TAG_KEY, a)
                    .register(meterRegistry));

            counter.increment();
        }
    }

    /**
     * Parses the JWT header and returns the value of the “alg” claim.
     *
     * @param jwt the full compact JWT (three base64url parts)
     * @return algorithm name (e.g. "RS256") or {@code null} on any parsing error.
     */
    private @Nullable String parseAlgFromJwt(String jwt) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);
            JWSHeader header = jwsObject.getHeader();
            return header.getAlgorithm().getName(); // e.g. "RS256"
        } catch (Exception _) {
            // should never occur, is already validated
            return null;
        }
    }
}
