/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.out;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "hsm.enabled=true")
class HSMSeedCredentialSignerAdapterTest {

    @Autowired
    private HSMSeedCredentialSignerAdapter subject;

    @Autowired
    private IdentificationConfiguration configuration;

    @Test
    void contextLoads() {
        var context = subject.signingContext();

        assertThat(context.algorithm()).isEqualTo(JWSAlgorithm.ES384);
        assertThat(context.keyID()).isEqualTo(expectedKeyID());
        assertThat(context.signer()).isNotNull();
        assertThat(context.cert()).isNotNull();
    }

    @Test
    void jwkSourceKnownKID() throws KeySourceException {
        var source = subject.jwkSource();

        var matcher = new JWKMatcher.Builder().keyID(expectedKeyID()).build();
        var jwks = source.get(new JWKSelector(matcher), null);

        assertThat(jwks).hasSize(1);
        assertThat(jwks.getFirst().getKeyID()).isEqualTo(expectedKeyID());
    }

    @ParameterizedTest
    @ValueSource(strings = {"unknown/0", "unexpected", "c0rr/up{t}"})
    void jwkSourceUnknownKID(String kid) throws KeySourceException {
        var source = subject.jwkSource();

        var matcher = new JWKMatcher.Builder().algorithm(JWSAlgorithm.ES384).keyID(kid).build();
        var jwks = source.get(new JWKSelector(matcher), null);

        assertThat(jwks).isEmpty();
    }

    private String expectedKeyID() {
        return configuration.getSeedSigAliasHsm() + "/0";
    }
}
