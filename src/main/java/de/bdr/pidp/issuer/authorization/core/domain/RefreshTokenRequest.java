/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import lombok.Getter;
import org.jspecify.annotations.Nullable;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Getter
public class RefreshTokenRequest extends OAuthRequest {
    private static final String SCOPE_PARAM = "scope";
    private static final String REFRESH_TOKEN_PARAM = "refresh_token";

    private static final String DPOP_HEADER = "DPoP".toLowerCase();

    private final String clientId;
    private final SignedJWT refreshToken;
    @Nullable
    private final String scope;

    private final SignedJWT attestation;
    private final SignedJWT attestationPoP;
    @Nullable
    private final List<String> dpopHeaders;

    public RefreshTokenRequest(Map<String, List<String>> allHeaders, Map<String, String> params) {
        this.clientId = readRequiredParam(params, CLIENT_ID_PARAM);
        var refreshTokenParam = readRequiredParam(params, REFRESH_TOKEN_PARAM);
        try {
            refreshToken = SignedJWT.parse(refreshTokenParam);
        } catch (ParseException e) {
            throw new InvalidGrantException("Refresh token invalid", e);
        }

        this.scope = params.get(SCOPE_PARAM);

        this.attestation = readClientAttestation(allHeaders);
        this.attestationPoP = readClientAttestationPoP(allHeaders);

        this.dpopHeaders = allHeaders.get(DPOP_HEADER);
    }
}
