/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.domain.AuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.ParRequest;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenRequest;
import de.bdr.pidp.issuer.authorization.core.domain.TokenRequest;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static de.bdr.pidp.issuer.testdata.ValidTestData.REDIRECT_URI;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RequestUtil {

    private static final Map<String, List<String>> ATTESTATION_HEADERS = TestUtils.getClientAttestationHeaders();

    public static Map<String, List<String>> getAttestationHeaders() {
        return new HashMap<>(ATTESTATION_HEADERS);
    }

    private static final Map<String, String> PAR_PARAMS = Map.of(
        "code_challenge_method", "S256",
        "code_challenge", "VPvsxc7h-NOKbZX9pKqzgLdc3-3VL_U8B4cKRt6r2xE",
        "client_id", UUID.randomUUID().toString(),
        "redirect_uri", REDIRECT_URI,
        "scope", "pid",
        "state", "Es lebt!",
        "response_type", "code"
    );

    public static Map<String, String> getValidParRequestParams() {
        return new HashMap<>(PAR_PARAMS);
    }

    public static ParRequest getParRequest() {
        return new ParRequest(ATTESTATION_HEADERS, PAR_PARAMS);
    }

    public static ParRequest getParRequest(Map<String, String> params) {
        return new ParRequest(ATTESTATION_HEADERS, params);
    }

    private static final Map<String, String> AUTH_PARAMS = Map.of(
        "client_id", UUID.randomUUID().toString(),
        "request_uri", "urn:ietf:params:oauth:request_uri:" + RandomUtil.randomString()
    );

    public static Map<String, String> getValidAuthRequestParams() {
        return new HashMap<>(AUTH_PARAMS);
    }

    public static AuthRequest getAuthRequest() {
        return new AuthRequest(AUTH_PARAMS);
    }

    private static final Map<String, String> FINISH_AUTH_PARAMS = Map.of(
        "issuer_state", RandomUtil.randomString()
    );

    public static Map<String, String> getValidFinishAuthRequestParams() {
        return new HashMap<>(FINISH_AUTH_PARAMS);
    }

    public static FinishAuthRequest getFinishAuthRequest() {
        return new FinishAuthRequest(FINISH_AUTH_PARAMS);
    }

    private static final Map<String, String> TOKEN_PARAMS = Map.of(
        "code", RandomUtil.randomString(),
        "code_verifier", "ABCDEFGHIJklmnopqrstUVWXYZ-._~0123456789-50Zeichen",
        "redirect_uri", REDIRECT_URI
    );

    public static Map<String, String> getValidTokenRequestParams() {
        return new HashMap<>(TOKEN_PARAMS);
    }

    public static TokenRequest getTokenRequest(@Nullable List<String> dpop) {
        Map<String, List<String>> headers = new HashMap<>();
        if (dpop != null) {
            headers.put("dpop", dpop);
        }
        return new TokenRequest(headers, TOKEN_PARAMS);
    }

    private static final Map<String, String> REFRESH_TOKEN_PARAMS = Map.of(
        "client_id", UUID.randomUUID().toString(),
        "scope", "pid",
        "refresh_token", TestRefreshTokenIssuer.buildRefreshToken().serialize()
    );

    public static Map<String, String> getValidRefreshTokenRequestParams() {
        return new HashMap<>(REFRESH_TOKEN_PARAMS);
    }

    public static RefreshTokenRequest getRefreshTokenRequest() {
        return getRefreshTokenRequest(null);
    }

    public static RefreshTokenRequest getRefreshTokenRequest(@Nullable List<String> dpop) {
        Map<String, List<String>> headers = new HashMap<>();
        if (dpop != null) {
            headers.put("dpop", dpop);
        }
        headers.putAll(ATTESTATION_HEADERS);
        return new RefreshTokenRequest(headers, REFRESH_TOKEN_PARAMS);
    }

    public static RefreshTokenRequest getRefreshTokenRequest(@Nullable List<String> dpop, Map<String, String> params) {
        Map<String, List<String>> headers = new HashMap<>();
        if (dpop != null) {
            headers.put("dpop", dpop);
        }
        headers.putAll(ATTESTATION_HEADERS);
        return new RefreshTokenRequest(headers, params);
    }
}
