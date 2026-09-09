/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

/**
 * The request is malformed and rejected before further validation.
 * From OAuth 2.0 (RFC 6749)
 * <ul>
 *   <li>4.1.2.1 "The request is missing a required parameter, includes an
 *     invalid parameter value, includes a parameter more than
 *     once, or is otherwise malformed."
 *   <li>5.2 "The request is missing a required parameter, includes an
 *     unsupported parameter value (other than grant type),
 *     repeats a parameter, includes multiple credentials,
 *     utilizes more than one mechanism for authenticating the
 *     client, or is otherwise malformed."
 * </ul>
 */
public class InvalidRequestException extends OAuthException {
    private static final String MISSING_PARAM_MESSAGE = "Missing required parameter '%s'";
    private static final String CODE_INVALID_REQUEST = "invalid_request";

    public static InvalidRequestException forWrongRequestOrder(String path, String requestName) {
        return new InvalidRequestException("The /%s request is not allowed".formatted(path), requestName + " is not the allowed next request");
    }

    public static String missingParameter(String param) {
        return MISSING_PARAM_MESSAGE.formatted(param);
    }

    public InvalidRequestException(String message) {
        super(CODE_INVALID_REQUEST, message);
    }

    public InvalidRequestException(String message, Throwable cause) {
        super(CODE_INVALID_REQUEST, message, cause);
    }

    public InvalidRequestException(String errorDescription, String message, Throwable cause) {
        super(CODE_INVALID_REQUEST, errorDescription, message, cause);
    }

    public InvalidRequestException(String errorDescription, String message) {
        super(CODE_INVALID_REQUEST, errorDescription, message);
    }
}
