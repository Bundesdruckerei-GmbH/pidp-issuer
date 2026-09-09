/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.OAuthException;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

class StateValidatorTest {

    private final StateValidator stateValidator = new StateValidator();

    @Test
    void stateValid() {
        assertThatNoException()
            .isThrownBy(() -> stateValidator.validateState("Es kann nur einen geben."));
    }

    @Test
    void stateTooLong() {
        var state = StringUtils.repeat("Du kommst hier nicht vorbei! ", 90);
        assertThatThrownBy(() -> stateValidator.validateState(state))
            .asInstanceOf(type(OAuthException.class))
            .extracting(OAuthException::getErrorCode)
            .isEqualTo("invalid_request");
    }
}
