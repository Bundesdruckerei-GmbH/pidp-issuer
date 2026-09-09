/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.domain.AuthorizeResult;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthorizationResult;
import de.bdr.pidp.issuer.authorization.core.domain.ParResult;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenResult;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.TokenResult;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.exception.UnsupportedGrantTypeException;
import de.bdr.pidp.issuer.authorization.core.flows.AuthorizationService;
import de.bdr.pidp.issuer.authorization.core.flows.ParService;
import de.bdr.pidp.issuer.authorization.core.flows.TokenService;
import lombok.RequiredArgsConstructor;
import org.jmolecules.architecture.hexagonal.PrimaryAdapter;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

import static de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException.missingParameter;

@PrimaryAdapter
@RestController
@RequiredArgsConstructor
public class OAuthController {
    private static final String GRANT_TYPE = "grant_type";

    private final ParService parService;
    private final AuthorizationService authorizationService;
    private final TokenService tokenService;
    private final OAuthRequestFactory oAuthRequestFactory;

    @PostMapping(path = Requests.Paths.PAR, consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<JsonNode> par(@RequestHeader MultiValueMap<String, String> allHeaders, @RequestParam MultiValueMap<String, String> allParams) {
        var parRequest = oAuthRequestFactory.createParRequest(allHeaders, allParams);

        ParResult parResult = parService.processPushedAuthRequest(parRequest);

        return OAuthResponseFactory.createParResponse(parResult);
    }

    @GetMapping(path = Requests.Paths.AUTHORIZE)
    public ResponseEntity<String> authorize(@RequestParam MultiValueMap<String, String> allParams) {
        var authRequest = oAuthRequestFactory.createAuthRequest(allParams);

        AuthorizeResult authorizeResult = authorizationService.processAuthRequest(authRequest);

        return OAuthResponseFactory.createAuthorizeResponse(authorizeResult);
    }

    /*
     * The endpoint itself is not specified in OAuth 2.0 or OID4VCI, but the response behaviour must be implemented
     * according to that of the Authorization Endpoint of the Authorization Code Flow in OAuth 2.0.
     */
    @GetMapping(path = Requests.Paths.FINISH_AUTHORIZATION)
    public ResponseEntity<String> finishAuthorization(@RequestParam MultiValueMap<String, String> allParams) {
        var finishAuthRequest = oAuthRequestFactory.createFinishAuthRequest(allParams);

        FinishAuthorizationResult faResult = authorizationService.processFinishAuthRequest(finishAuthRequest);

        return OAuthResponseFactory.createFinishAuthorizationResponse(faResult);
    }

    @PostMapping(path = Requests.Paths.TOKEN, consumes = "application/x-www-form-urlencoded", produces = "application/json")
    public ResponseEntity<JsonNode> invalidGrantType(@RequestParam MultiValueMap<String, String> allParams) {
        var grantTypes = allParams.get(GRANT_TYPE);
        if (grantTypes == null || grantTypes.isEmpty()) {
            throw new InvalidRequestException(missingParameter(GRANT_TYPE));
        }
        var grantType = grantTypes.getFirst();
        if (grantType == null || grantType.isBlank()) {
            throw new InvalidRequestException(missingParameter(GRANT_TYPE));
        } else {
            throw new UnsupportedGrantTypeException("Grant type \"%s\" unsupported".formatted(grantType));
        }
    }

    @PostMapping(path = Requests.Paths.TOKEN, params = "grant_type=authorization_code", consumes = "application/x-www-form-urlencoded", produces = "application/json")
    public ResponseEntity<JsonNode> token(@RequestHeader MultiValueMap<String, String> allHeaders, @RequestParam MultiValueMap<String, String> allParams) {
        var tokenRequest = oAuthRequestFactory.createTokenRequest(allHeaders, allParams);

        TokenResult tokenResult = tokenService.processTokenRequest(tokenRequest);

        return OAuthResponseFactory.createTokenResponse(tokenResult);
    }

    @PostMapping(path = Requests.Paths.TOKEN, params = "grant_type=refresh_token", consumes = "application/x-www-form-urlencoded", produces = "application/json")
    public ResponseEntity<JsonNode> refreshToken(@RequestHeader MultiValueMap<String, String> allHeaders, @RequestParam MultiValueMap<String, String> allParams) {
        var refreshTokenRequest = oAuthRequestFactory.createRefreshTokenRequest(allHeaders, allParams);

        RefreshTokenResult refreshTokenResult = tokenService.processRefreshTokenRequest(refreshTokenRequest);

        return OAuthResponseFactory.createRefreshTokenResponse(refreshTokenResult);
    }
}
