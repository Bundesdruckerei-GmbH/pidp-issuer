/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import lombok.Getter;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

@Getter
public class ParRequest extends OAuthRequest {
    private static final String CODE_CHALLENGE_METHOD_PARAM = "code_challenge_method";
    private static final String CODE_CHALLENGE_PARAM = "code_challenge";
    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String SCOPE_PARAM = "scope";
    private static final String STATE_PARAM = "state";
    private static final String RESPONSE_TYPE_PARAM = "response_type";

    private final String clientId;
    private final String codeChallenge;
    private final CodeChallengeMethod codeChallengeMethod;
    private final String redirectUri;
    private final String scope;
    private final ResponseType responseType;
    @Nullable
    private final String state;

    private final SignedJWT attestation;
    private final SignedJWT attestationPoP;

    public ParRequest(Map<String, List<String>> allHeaders, Map<String, String> params) {
        this.clientId = readRequiredParam(params, CLIENT_ID_PARAM);
        this.codeChallengeMethod = CodeChallengeMethod.parse(readRequiredParam(params, CODE_CHALLENGE_METHOD_PARAM));
        this.codeChallenge = readRequiredParam(params, CODE_CHALLENGE_PARAM);
        this.redirectUri = readRequiredParam(params, REDIRECT_URI_PARAM);
        this.scope = readRequiredParam(params, SCOPE_PARAM);
        this.state = params.get(STATE_PARAM);

        try {
            this.responseType = ResponseType.parse(readRequiredParam(params, RESPONSE_TYPE_PARAM));
        } catch (ParseException e) {
            throw new InvalidRequestException("Invalid response type", "response_type must not be empty", e);
        }

        this.attestation = readClientAttestation(allHeaders);
        this.attestationPoP = readClientAttestationPoP(allHeaders);
    }
}
