/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential.domain;

import de.bdr.pidp.issuer.base.crypto.KeyID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyIDTest {

    @ValueSource(strings = {"JustLetters", "with_underscore", "dash-dash", "dot.com", "1"})
    @ParameterizedTest
    void successWithAllowedChars(String value) {
        var kid = new KeyID(value);

        assertThat(kid.value()).isEqualTo(value);
    }

    @ValueSource(strings = {"a/normal/path", "a\\win\\path", "another$symbol", "in space", "too_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooong"})
    @EmptySource
    @ParameterizedTest
    void failureWithInvalidFormat(String value) {
        assertThatThrownBy(() -> new KeyID(value))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
