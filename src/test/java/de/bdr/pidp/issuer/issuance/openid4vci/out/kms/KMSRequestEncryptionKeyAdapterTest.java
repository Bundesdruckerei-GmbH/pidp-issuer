/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.kms;

import com.nimbusds.jose.JWEAlgorithm;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ComponentScan("de.bdr.pidp.issuer.identification")
class KMSRequestEncryptionKeyAdapterTest extends IntegrationTest {

    @Autowired
    private KMSRequestEncryptionKeyAdapter subject;

    @Test
    void fetchPublicKey() {
        var pub = subject.getLatestPublicKey();

        assertThat(pub.isPrivate()).isFalse();
        assertThat(pub.getKeyID()).isNotNull();
        assertThat(pub.getKeyType()).isNotNull();
        assertThat(pub.getAlgorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
    }

    @Test
    void publicKeyNotFound() {
        var original = ReflectionTestUtils.getField(subject, "reqEncKaAlias");
        try {
            ReflectionTestUtils.setField(subject, "reqEncKaAlias", new KeyID("unknown"));
            assertThatThrownBy(() -> subject.getLatestPublicKey()).isInstanceOf(KeyNotFoundException.class);
        } finally {
            ReflectionTestUtils.setField(subject, "reqEncKaAlias", original);
        }
    }

    @Test
    void fetchPrivateKeys() {
        var privs = subject.getPrivateKeys();

        assertThat(privs).hasSize(1);
        var priv = privs.getFirst();
        assertThat(priv.isPrivate()).isTrue();
        assertThat(priv.getKeyID()).isNotNull();
        assertThat(priv.getKeyType()).isNotNull();
        assertThat(priv.getAlgorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
    }

    @Test
    void privateKeyNotFound() {
        var original = ReflectionTestUtils.getField(subject, "reqEncKaAlias");
        try {
            ReflectionTestUtils.setField(subject, "reqEncKaAlias", new KeyID("unknown"));
            assertThatThrownBy(() -> subject.getPrivateKeys()).isInstanceOf(KeyNotFoundException.class);
        } finally {
            ReflectionTestUtils.setField(subject, "reqEncKaAlias", original);
        }
    }
}
