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
import de.bdr.pidp.issuer.testdata.TestConfig;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class MetaTestData {
    public static final ReadOnlyAuthMetadata AUTH_METADATA;

    static {
        var issuerUrl = TestConfig.pidiBaseUrl();
        var iss = new Issuer(issuerUrl);
        var asm = new AuthMetadata(iss);

        asm.setAuthorizationEndpointURI(URI.create(issuerUrl + "/authorize"));
        asm.setTokenEndpointURI(URI.create(issuerUrl + "/token"));
        asm.setPushedAuthorizationRequestEndpointURI(URI.create(issuerUrl + "/par"));
        asm.requiresPushedAuthorizationRequests(true);
        asm.setTokenEndpointAuthMethods(List.of(new ClientAuthenticationMethod("attest_jwt_client_auth")));
        asm.setResponseTypes(List.of(ResponseType.CODE));
        asm.setCodeChallengeMethods(List.of(CodeChallengeMethod.S256));
        asm.setDPoPJWSAlgs(new ArrayList<>(JWSAlgorithm.Family.EC));
        asm.setClientAttestationSigningAlgValuesSupported(List.of(JWSAlgorithm.ES256));
        asm.setClientAttestationPoPSigningAlgValuesSupported(List.of(JWSAlgorithm.ES256));

        AUTH_METADATA = asm;
    }
}
