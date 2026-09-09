/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.base.RandomUtil;
import lombok.Getter;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Getter
public class TokenRequest extends OAuthRequest {
    private static final String CODE_PARAM = "code";
    private static final String CODE_VERIFIER_PARAM = "code_verifier";
    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String DPOP_HEADER = "DPoP".toLowerCase();

    private final String codeVerifier;
    private final String redirectUri;
    private final String authCode;
    @Nullable
    private final List<String> dpopHeaders;

    public TokenRequest(Map<String, List<String>> allHeaders, Map<String, String> params) {
        this.authCode = Optional.ofNullable(params.get(CODE_PARAM))
            .orElseThrow(() -> new InvalidRequestException(InvalidRequestException.missingParameter(CODE_PARAM)));
        if (!RandomUtil.isValid(this.authCode)) {
            throw new InvalidGrantException("invalid authorization code");
        }
        this.codeVerifier = readRequiredParam(params, CODE_VERIFIER_PARAM);
        this.redirectUri = readRequiredParam(params, REDIRECT_URI_PARAM);

        this.dpopHeaders = allHeaders.get(DPOP_HEADER);
    }
}
