/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthorizeAuthSession;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.RandomUtil;
import org.springframework.stereotype.Component;
import org.springframework.web.util.InvalidUrlException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URL;

@Component
public class AuthorizationHandler {
    private final String baseUrl;
    private final IdentificationDataPortOut identificationProvider;

    public AuthorizationHandler(AuthorizationConfiguration authorizationConfiguration, IdentificationDataPortOut identificationProvider) {
        this.baseUrl = authorizationConfiguration.getBaseUrl().toString();
        this.identificationProvider = identificationProvider;
    }

    public URL processAuthRequest(AuthorizeAuthSession authorizeAuthSession) {
        String issuerState = RandomUtil.randomString();

        authorizeAuthSession.addGeneratedAuthorizeProperties(issuerState);
        try {
            var uriComponentsBuilder = UriComponentsBuilder.fromUriString(baseUrl);
            uriComponentsBuilder.pathSegment(Requests.FINISH_AUTHORIZATION_REQUEST.getPath());
            uriComponentsBuilder.queryParam("issuer_state", issuerState);

            var accessCodeUrl = uriComponentsBuilder.build().toUri().toURL();
            return identificationProvider.startIdentificationProcess(accessCodeUrl, issuerState, String.valueOf(authorizeAuthSession.getSessionId()));
        } catch (InvalidUrlException | MalformedURLException me) {
            throw new PidServerException("could not create accessCodeUrl", me);
        }
    }
}
