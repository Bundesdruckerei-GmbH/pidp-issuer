/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.util.List;

@Configuration
public class AuthorizationMetadataConfiguration {

    @Bean
    public ReadOnlyAuthMetadata authorizationMetadata(AuthorizationConfiguration configuration) {
        var issuerUrl = configuration.getCredentialIssuerIdentifier();
        var iss = new Issuer(issuerUrl);
        var am = new AuthMetadata(iss);

        am.setAuthorizationEndpointURI(URI.create(issuerUrl + "/authorize"));
        am.setTokenEndpointURI(URI.create(issuerUrl + "/token"));
        am.setPushedAuthorizationRequestEndpointURI(URI.create(issuerUrl + "/par"));
        if (configuration.isChallengeEnabled()) {
            am.setChallengeEndpointURI(URI.create(issuerUrl + "/challenge"));
        }
        am.requiresPushedAuthorizationRequests(true);
        am.setTokenEndpointAuthMethods(List.of(new ClientAuthenticationMethod("attest_jwt_client_auth")));
        am.setResponseTypes(List.of(ResponseType.CODE));
        am.setCodeChallengeMethods(List.of(CodeChallengeMethod.S256));
        am.setDPoPJWSAlgs(List.copyOf(JWSAlgorithm.Family.EC));
        am.setClientAttestationSigningAlgValuesSupported(List.copyOf(JWSAlgorithm.Family.SIGNATURE));
        am.setClientAttestationPoPSigningAlgValuesSupported(List.copyOf(JWSAlgorithm.Family.SIGNATURE));

        return am;
    }
}
