/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.oauth2.sdk.ResponseType;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.ParRequest;
import de.bdr.pidp.issuer.authorization.core.domain.ParResult;
import de.bdr.pidp.issuer.authorization.core.domain.data.ParAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.UnsupportedResponseTypeException;
import de.bdr.pidp.issuer.base.RandomUtil;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Component
public class ParHandler {

    private final Duration requestUriLifetime;
    private final List<ResponseType> responseTypes;

    public ParHandler(ReadOnlyAuthMetadata metadata, AuthorizationConfiguration authorizationConfiguration) {
        this.requestUriLifetime = authorizationConfiguration.getRequestUriLifetime();
        this.responseTypes = metadata.getResponseTypes();
    }

    public ParResult processPushedAuthRequest(ParRequest request, ParAuthSession session) {
        validatePARParams(request);

        String requestUri = createRequestUri();

        var expires = Instant.now().plus(requestUriLifetime);
        session.addGeneratedParProperties(requestUri, expires);

        return new ParResult(requestUri, requestUriLifetime);
    }

    private String createRequestUri() {
        return "urn:ietf:params:oauth:request_uri:" + RandomUtil.randomString();
    }

    private void validatePARParams(ParRequest request) {
        var responseType = request.getResponseType();
        if (responseTypes.stream().noneMatch(responseType::equals)) {
            throw new UnsupportedResponseTypeException();
        }
    }
}
