/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

public class ParameterTooLongException extends OAuthException {
    public ParameterTooLongException(String parameter, int maxLength) {
        super("invalid_request", "The " + parameter + " parameter exceeds the maximum permitted size of " + maxLength + " bytes");
    }
}
