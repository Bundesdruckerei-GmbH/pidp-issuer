/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.steps;

import de.bdr.pidp.issuer.end2end.requests.AuthorizationRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.ChallengeRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.CredentialIssuerMetadataRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.Documentation;
import de.bdr.pidp.issuer.end2end.requests.EidRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.FinishAuthorizationRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.NonceRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.PushedAuthorizationRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.RefreshTokenRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.TokenRequestBuilder;
import de.bdr.pidp.issuer.testdata.TestConfig;
import io.restassured.module.webtestclient.response.WebTestClientResponse;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

import static org.hamcrest.Matchers.startsWith;

public class Steps {
    @Nullable
    private final RestDocumentationContextProvider restDocumentation;

    public Steps(@Nullable RestDocumentationContextProvider restDocumentation) {
        this.restDocumentation = restDocumentation;
    }

    public Steps() {
        this(null);
    }

    public ChallengeResponse doChallenge(@Nullable Documentation documentation) {
        var response = ChallengeRequestBuilder.valid()
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.OK);
        return ChallengeResponse.from(response);
    }

    public ChallengeResponse doChallenge() {
        return doChallenge(null);
    }

    public record ChallengeResponse(String attestationChallenge) {
        static ChallengeResponse from(WebTestClientResponse response) {
            return new ChallengeResponse(response.path("attestation_challenge"));
        }
    }

    public PARResponse doPAR(String attestationChallenge, @Nullable Documentation documentation) {
        var response = PushedAuthorizationRequestBuilder.valid(attestationChallenge)
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.CREATED);
        return PARResponse.from(response);
    }

    public PARResponse doPAR() {
        return doPAR(null, null);
    }

    public record PARResponse(String requestUri) {
        static PARResponse from(WebTestClientResponse response) {
            return new PARResponse(response.path("request_uri"));
        }
    }

    public AuthorizeResponse doAuthorize(String requestUri, @Nullable Documentation documentation) {
        String location = AuthorizationRequestBuilder.valid(requestUri)
                .getRequestUrl(TestConfig.pidiHostnameFromMock());

        var response = new EidRequestBuilder(restDocumentation)
                .withTCTokenUrl(location)
                .withPort(TestConfig.getEidMockPort())
                .withHost(TestConfig.getEidMockHostname())
                .withDocumentation(documentation)
                .doRequest();

        response.then().assertThat()
            .status(HttpStatus.SEE_OTHER)
            .header(HttpHeaders.LOCATION, startsWith(TestConfig.pidiBaseUrl() + "/finish-authorization?"));

        return AuthorizeResponse.from(response);
    }

    public AuthorizeResponse doAuthorize(String requestUri) {
        return doAuthorize(requestUri, null);
    }

    public record AuthorizeResponse(String issuerState) {
        static AuthorizeResponse from(WebTestClientResponse response) {
            var uri = UriComponentsBuilder.fromUriString(response.header(HttpHeaders.LOCATION)).build();
            return new AuthorizeResponse(uri.getQueryParams().getFirst("issuer_state"));
        }
    }

    public FinishAuthorizeResponse doFinishAuthorization(String issuerState, @Nullable Documentation documentation) {
        var response = FinishAuthorizationRequestBuilder.valid(issuerState)
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.FOUND);
        return FinishAuthorizeResponse.from(response);
    }

    public FinishAuthorizeResponse doFinishAuthorization(String issuerState) {
        return doFinishAuthorization(issuerState, null);
    }

    public record FinishAuthorizeResponse(String code, String dpopNonce) {
        static FinishAuthorizeResponse from(WebTestClientResponse response) {
            var code = UriComponentsBuilder.fromUriString(response.header(HttpHeaders.LOCATION)).build().getQueryParams().get("code").getFirst();
            return new FinishAuthorizeResponse(code, response.header("DPoP-Nonce"));
        }
    }

    public TokenResponse doTokenRequest(String authorizationCode, String dpopNonce, @Nullable Documentation documentation) {
        var response = TokenRequestBuilder.valid(dpopNonce)
            .withDocumentation(documentation)
            .withAuthorizationCode(authorizationCode)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.OK);
        return TokenResponse.from(response);
    }

    public TokenResponse doTokenRequest(String authorizationCode, String dpopNonce) {
        return doTokenRequest(authorizationCode, dpopNonce, null);
    }

    public record TokenResponse(String accessToken, String refreshToken, String dpopNonce) {
        static TokenResponse from(WebTestClientResponse response) {
            return new TokenResponse(
                response.path("access_token"),
                response.path("refresh_token"),
                response.header("DPoP-Nonce")
            );
        }
    }

    public NonceResponse doNonceRequest() {
        return doNonceRequest(null);
    }

    public NonceResponse doNonceRequest(@Nullable Documentation documentation) {
        var response = NonceRequestBuilder.valid()
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.OK);
        return NonceResponse.from(response);
    }

    public record NonceResponse(String cNonce) {
        static NonceResponse from(WebTestClientResponse response) {
            return new NonceResponse(response.jsonPath().getString("c_nonce"));
        }
    }

    public RefreshTokenBadRequestResponse doRefreshTokenInitRequest(String refreshToken, String attestationChallenge, @Nullable Documentation documentation) {
        var response = RefreshTokenRequestBuilder.valid(null, attestationChallenge, refreshToken)
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.BAD_REQUEST);
        return RefreshTokenBadRequestResponse.from(response);
    }

    public RefreshTokenBadRequestResponse doRefreshTokenInitRequest(String refreshToken) {
        return doRefreshTokenInitRequest(refreshToken, null, null);
    }

    public record RefreshTokenBadRequestResponse(String dpopNonce, String attestationChallenge) {
        static RefreshTokenBadRequestResponse from(WebTestClientResponse response) {
            return new RefreshTokenBadRequestResponse(response.header("DPoP-Nonce"), response.header("OAuth-Client-Attestation-Challenge"));
        }
    }

    public RefreshTokenResponse doRefreshTokenRequest(String refreshToken, String dpopNonce, String attestationChallenge, @Nullable Documentation documentation) {
        var response = RefreshTokenRequestBuilder.valid(dpopNonce, attestationChallenge, refreshToken)
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.OK);
        return RefreshTokenResponse.from(response);
    }

    public RefreshTokenResponse doRefreshTokenRequest(String refreshToken, String dpopNonce) {
        return doRefreshTokenRequest(refreshToken, dpopNonce, null, null);
    }

    public record RefreshTokenResponse(String accessToken, String dpopNonce) {
        static RefreshTokenResponse from(WebTestClientResponse response) {
            return new RefreshTokenResponse(
                response.path("access_token"),
                response.header("DPoP-Nonce")
            );
        }
    }

    public CredentialIssuerMetadataResponse doCredentialIssuerMetadataRequest(@Nullable Documentation documentation) {
        var response = CredentialIssuerMetadataRequestBuilder.valid()
            .withDocumentation(documentation)
            .doRequest();
        response.then()
            .assertThat()
            .status(HttpStatus.OK);
        return CredentialIssuerMetadataResponse.from(response);
    }

    public CredentialIssuerMetadataResponse doCredentialIssuerMetadataRequest() {
        return doCredentialIssuerMetadataRequest(null);
    }

    public record CredentialIssuerMetadataResponse(Map<String, Object> requestEncryptionJWK) {
        static CredentialIssuerMetadataResponse from(WebTestClientResponse response) {
            return new CredentialIssuerMetadataResponse(
                response.path("credential_request_encryption.jwks.keys[0]")
            );
        }
    }
}
