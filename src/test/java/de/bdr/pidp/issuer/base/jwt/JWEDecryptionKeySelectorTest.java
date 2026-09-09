/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JWEDecryptionKeySelectorTest {
    private static final JWEAlgorithm ALGORITHM = JWEAlgorithm.ECDH_ES;
    private static final EncryptionMethod ENCRYPTION_METHOD = EncryptionMethod.A256GCM;

    private final JWK sourceKey = TestUtils.generateECDHEncryptionKey();
    private final JWK publicKey = TestUtils.generateECDHEncryptionKey().toPublicJWK();
    private JWEDecryptionKeySelector<SecurityContext> keySelector;

    @BeforeEach
    void setUp() {
        var supportedMethods = Collections.singletonList(ENCRYPTION_METHOD);
        JWKSource<SecurityContext> jwkSource = (context, _) -> context.select(new JWKSet(List.of(sourceKey, publicKey)));
        keySelector = new JWEDecryptionKeySelector<>(supportedMethods, jwkSource);
    }

    @Test
    void returnPrivateKey() throws KeySourceException {
        JWEHeader header = new JWEHeader.Builder(ALGORITHM, ENCRYPTION_METHOD)
            .keyID(sourceKey.getKeyID())
            .build();

        List<Key> keys = keySelector.selectJWEKeys(header, null);

        assertThat(keys).hasSize(1);
        assertThat(keys.getFirst()).isInstanceOf(PrivateKey.class);
    }

    @Test
    void skipPublicKey() {
        // Arrange
        JWEHeader header = new JWEHeader.Builder(ALGORITHM, ENCRYPTION_METHOD)
            .keyID(publicKey.getKeyID())
            .build();

        assertThatThrownBy(() -> keySelector.selectJWEKeys(header, null))
            .isInstanceOf(KeySourceException.class);
    }

    @Test
    void unsupportedEncryptionMethod() {
        JWEHeader header = new JWEHeader.Builder(ALGORITHM, EncryptionMethod.A128GCM)
            .keyID(sourceKey.getKeyID())
            .build();

        assertThatThrownBy(() -> keySelector.selectJWEKeys(header, null))
            .isInstanceOf(KeySourceException.class);
    }

    @Test
    void noMatchingKeysByAlgorithm() {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, ENCRYPTION_METHOD)
            .keyID(sourceKey.getKeyID())
            .build();

        assertThatThrownBy(() -> keySelector.selectJWEKeys(header, null))
            .isInstanceOf(KeySourceException.class);
    }

    @Test
    void noMatchingKeysByKID() {
        JWEHeader header = new JWEHeader.Builder(ALGORITHM, ENCRYPTION_METHOD)
            .keyID("unknownKid")
            .build();

        assertThatThrownBy(() -> keySelector.selectJWEKeys(header, null))
            .isInstanceOf(KeySourceException.class);
    }

    @Test
    void noMatchingKeysMissingKID() {
        JWEHeader header = new JWEHeader.Builder(ALGORITHM, ENCRYPTION_METHOD)
            .build();

        assertThatThrownBy(() -> keySelector.selectJWEKeys(header, null))
            .isInstanceOf(KeySourceException.class);
    }
}
