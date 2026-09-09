/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.exception.ParameterTooLongException;
import org.springframework.stereotype.Component;

@Component
public class StateValidator {

    public static final String STATE = "state";
    public static final int MAX_STATE_LENGTH = 2048;

    public void validateState(final String state) {
        if (state.length() > MAX_STATE_LENGTH) {
            throw new ParameterTooLongException(STATE, MAX_STATE_LENGTH);
        }
    }
}
