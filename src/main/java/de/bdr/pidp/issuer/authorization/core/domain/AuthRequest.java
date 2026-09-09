/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.base.RandomUtil;
import lombok.Getter;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

@Getter
public class AuthRequest extends OAuthRequest {
    private static final Pattern REQUEST_URI_PATTERN = Pattern.compile("urn:ietf:params:oauth:request_uri:[a-zA-Z\\d]{%s}$".formatted(RandomUtil.RANDOM_CHARS_ARRAY_LENGTH));

    private static final String REQUEST_URI_PARAM = "request_uri";

    private final String clientId;
    private final String requestUri;

    public AuthRequest(Map<String, String> params) {
        this.clientId = Optional.ofNullable(params.get(CLIENT_ID_PARAM))
            .orElseThrow(() -> new InvalidRequestException(InvalidRequestException.missingParameter(CLIENT_ID_PARAM)));

        this.requestUri = params.get(REQUEST_URI_PARAM);
        if (this.requestUri == null || !REQUEST_URI_PATTERN.matcher(this.requestUri).matches()) {
            throw new InvalidRequestException("invalid request_uri", "Invalid request_uri: " + this.requestUri);
        }
    }
}
