/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidScopeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class ScopeValidatorTest {

    private final ScopeValidator validator = new ScopeValidator();

    @Test
    void processValidation() {
        assertThatNoException().isThrownBy(() -> validator.validateScope("pid"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PID", "pi", "pidi", "pid ", " pid"})
    @EmptySource
    void processInvalidRedirectUri(String scope) {
        assertThatExceptionOfType(InvalidScopeException.class).isThrownBy(() -> validator.validateScope(scope))
            .withMessage("Unknown scope");
    }
}
