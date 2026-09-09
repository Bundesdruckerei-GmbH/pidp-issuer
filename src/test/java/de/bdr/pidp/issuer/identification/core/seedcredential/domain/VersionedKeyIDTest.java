/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential.domain;

import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VersionedKeyIDTest {

    @Test
    void correctStringRepresentation() {
        var kid = new KeyID("some_keyID");
        var versionedKid = new VersionedKeyID(kid, 1);

        assertThat(versionedKid).hasToString("some_keyID/1");
    }

    @Test
    void failureWithInvalidVersion() {
        var kid = new KeyID("some_keyID");
        assertThatThrownBy(() -> new VersionedKeyID(kid, -1))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseSuccess() {
        var vKid = VersionedKeyID.parse("some_keyID/1");

        assertThat(vKid.keyID().value()).isEqualTo("some_keyID");
        assertThat(vKid.version()).isEqualTo(1);
    }

    @ValueSource(strings = {"double/dash/1", "wrongDash\\2", "noVersion/", "not-only-numbers/3d", "TooNegative/-1", "/42"})
    @EmptySource
    @ParameterizedTest
    void parseFailureWithInvalidFormat(String value) {
        assertThatThrownBy(() -> VersionedKeyID.parse(value))
            .isInstanceOf(IllegalArgumentException.class);
    }

}
