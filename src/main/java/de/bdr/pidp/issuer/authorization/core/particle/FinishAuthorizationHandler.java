/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.data.FinishAuthorizationAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import de.bdr.pidp.issuer.base.RandomUtil;
import io.micrometer.common.util.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Component
public class FinishAuthorizationHandler {
    private static final String CODE = "code";
    private static final String STATE = "state";
    private static final String ISS = "iss";

    private final Duration authorizationCodeLifetime;
    private final String credentialIssuerIdentifier;
    private final IdentificationDataPortOut identificationProvider;

    public FinishAuthorizationHandler(AuthorizationConfiguration authorizationConfiguration, IdentificationDataPortOut identificationProvider) {
        this.authorizationCodeLifetime = authorizationConfiguration.getAuthorizationCodeLifetime();
        this.credentialIssuerIdentifier = authorizationConfiguration.getCredentialIssuerIdentifier();
        this.identificationProvider = identificationProvider;
    }

    public String processFinishAuthRequest(FinishAuthRequest request, FinishAuthorizationAuthSession session) {
        String issuerState = session.getIssuerState();
        validateIssuerState(request, issuerState);
        String redirectUri = session.getRedirectUri();
        if (StringUtils.isBlank(redirectUri)) {
            throw new InvalidRequestException("Missing redirect uri");
        }
        validateIdentificationResult(issuerState);

        var code = RandomUtil.randomString();

        var redirectUriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
          .queryParam(CODE, code)
          .queryParam(ISS, credentialIssuerIdentifier);
        String state = session.getState();
        if (state != null) {
            redirectUriBuilder.queryParam(STATE, state);
        }

        var authorizationCodeExpirationTime = Instant.now().plus(authorizationCodeLifetime);
        session.addGeneratedFinishAuthorizationProperties(code, authorizationCodeExpirationTime);

        return redirectUriBuilder.toUriString();
    }

    private static void validateIssuerState(FinishAuthRequest request, String issuerStateFromSession) {
        if (!Objects.equals(request.getIssuerState(), issuerStateFromSession)) {
            throw new InvalidGrantException("Invalid issuer state");
        }
    }

    private void validateIdentificationResult(String issuerStateFromSession) {
        var result = identificationProvider.checkIdentification(issuerStateFromSession);
        if (result.status().isError()) {
            throw new IdentificationFailedException(Objects.requireNonNull(result.error()));
        }
    }
}
