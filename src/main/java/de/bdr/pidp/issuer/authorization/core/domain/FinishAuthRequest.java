/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.base.RandomUtil;
import lombok.Getter;

import java.util.Map;

@Getter
public class FinishAuthRequest extends OAuthRequest {
    private static final String ISSUER_STATE_PARAM = "issuer_state";

    private final String issuerState;

    public FinishAuthRequest(Map<String, String> params) {
        this.issuerState = readRequiredParam(params, ISSUER_STATE_PARAM);
        if (!RandomUtil.isValid(issuerState)) {
            throw new InvalidRequestException("invalid issuer_state", "Invalid issuer state " + issuerState);
        }
    }
}
