/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.out;

import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ComponentScan("de.bdr.pidp.issuer.identification")
class KMSEncryptionKeyAdapterTest extends IntegrationTest {

    private final int latestKeyVersion = 1;

    @Autowired
    private KMSEncryptionKeyAdapter subject;

    @Autowired
    private IdentificationConfiguration config;

    @Test
    void fetchEncryptionKey() {
        var kid = new VersionedKeyID(new KeyID(config.getSeedEncAlias()), latestKeyVersion);
        var key = subject.fetchEncryptionKey(kid);

        assertThat(key).isNotNull();
    }

    @Test
    void encryptionKeyNotFound() {
        var kid = new VersionedKeyID(new KeyID("does_not_exist"), latestKeyVersion);

        assertThatThrownBy(() -> subject.fetchEncryptionKey(kid))
            .isInstanceOf(KeyNotFoundException.class);
    }

    @Test
    void fetchEncryptionKeySet() {
        var kid = new VersionedKeyID(new KeyID(config.getSeedEncAlias()), latestKeyVersion);
        var jwks = subject.fetchEncryptionKeySet(kid);

        assertThat(jwks.isEmpty()).isFalse();
        assertThat(jwks.getKeyByKeyId(config.getSeedEncAlias() + "/" + latestKeyVersion)).isNotNull();
    }

    @Test
    void encryptionKeySetNotFound() {
        var kid = new VersionedKeyID(new KeyID("does_not_exist"), latestKeyVersion);

        assertThatThrownBy(() -> subject.fetchEncryptionKeySet(kid))
            .isInstanceOf(KeyNotFoundException.class);
    }

    @Test
    void getLatestVersion() {
        var kid = new KeyID(config.getSeedEncAlias());
        var version = subject.getLatestVersion(kid);

        assertThat(version).isEqualTo(latestKeyVersion);
    }

    @Test
    void latestVersionNotFound() {
        var kid = new KeyID("does_not_exist");

        assertThatThrownBy(() -> subject.getLatestVersion(kid))
            .isInstanceOf(KeyNotFoundException.class);
    }
}
