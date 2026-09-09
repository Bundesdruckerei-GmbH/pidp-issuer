/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.testdata.TestConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;

class ReadOnlyAuthMetadataTest {

    @Test
    void metadataWithClientAttestation() {
        var issuer = new Issuer(TestConfig.pidiBaseUrl());
        var metadata = new AuthMetadata(issuer);

        metadata.setClientAttestationSigningAlgValuesSupported(List.of(JWSAlgorithm.ES256));
        metadata.setClientAttestationPoPSigningAlgValuesSupported(List.of(JWSAlgorithm.ES256));
        metadata.setTokenEndpointAuthMethods(List.of(new ClientAuthenticationMethod("attest_jwt_client_auth")));
        var json = metadata.toJSONObject().toJSONString();

        assertThatJson(json)
            .isObject()
            .hasSize(4)
            .containsEntry("issuer", issuer.getValue());
        assertThatJson(json)
            .node("token_endpoint_auth_methods_supported")
            .isArray()
            .contains("attest_jwt_client_auth");
        assertThatJson(json)
            .node("client_attestation_signing_alg_values_supported")
            .isArray()
            .containsOnly(JWSAlgorithm.ES256.getName());
        assertThatJson(json)
            .node("client_attestation_pop_signing_alg_values_supported")
            .isArray()
            .containsOnly(JWSAlgorithm.ES256.getName());
    }

    @Test
    void metadataMinimal() {
        var issuer = new Issuer(TestConfig.pidiBaseUrl());
        var metadata = new AuthMetadata(issuer);

        var json = metadata.toJSONObject().toJSONString();

        assertThatJson(json)
            .isObject()
            .hasSize(1)
            .containsEntry("issuer", issuer.getValue());
    }
}
