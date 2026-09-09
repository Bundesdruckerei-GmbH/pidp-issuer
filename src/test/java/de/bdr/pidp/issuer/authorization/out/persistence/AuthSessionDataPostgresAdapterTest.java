/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.out.persistence;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthorizeAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.SessionNotFoundException;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthSessionDataPostgresAdapterTest extends IntegrationTest {

    @Autowired
    private AuthSessionDataPostgresAdapter sessionAdapter;

    @Autowired
    private AuthSessionRepository sessionRepository;

    @Test
    @DisplayName("Verify new session gets initialized and persisted")
    void test001() {
        var session = sessionAdapter.init();
        assertThat(session)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId())
                    .isPositive();
                assertThat(authSession.getNextExpectedRequest())
                    .isEqualTo(Requests.PUSHED_AUTHORIZATION_REQUEST);
                assertThat(sessionRepository.existsById(authSession.getSessionId()))
                    .isTrue();
            });
    }

    @Test
    @DisplayName("Verify session gets load by request_uri")
    void test002() {
        var requestUri = TestUtils.generateRequestUri();
        var session = (AuthSession) sessionAdapter.init();
        session.addGeneratedParProperties(requestUri, Instant.now().plusSeconds(30L));
        sessionAdapter.save(session);

        AuthorizeAuthSession foundSession = sessionAdapter.loadByRequestUri(requestUri);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(session.getSessionId());
                assertThat(authSession.getRequestUri()).isEqualTo(requestUri);
            });
    }

    @Test
    @DisplayName("Verify session gets not found by request_uri and throws exception")
    void test003() {
        var requestUri = TestUtils.generateRequestUri();
        assertThatThrownBy(() -> sessionAdapter.loadByRequestUri(requestUri))
            .isInstanceOf(SessionNotFoundException.class);
    }

    @Test
    @DisplayName("Verify session gets load by issuer state")
    void test004() {
        var issuerState = TestUtils.generateIssuerState();
        var session = (AuthSession) sessionAdapter.init();
        session.addGeneratedAuthorizeProperties(issuerState);
        sessionAdapter.save(session);

        var foundSession = sessionAdapter.loadByIssuerState(issuerState);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(session.getSessionId());
                assertThat(authSession.getIssuerState()).isEqualTo(issuerState);
            });
    }

    @Test
    @DisplayName("Verify session gets not found by issuer state and throws exception")
    void test005() {
        var issuerState = TestUtils.generateIssuerState();
        assertThatThrownBy(() -> sessionAdapter.loadByIssuerState(issuerState))
            .isInstanceOf(SessionNotFoundException.class);
    }

    @Test
    @DisplayName("Verify session gets load by authorization code")
    void test006() {
        var authorizationCode = TestUtils.generateAuthorizationCode();
        var session = (AuthSession) sessionAdapter.init();
        session.addGeneratedFinishAuthorizationProperties(authorizationCode, Instant.now().plusSeconds(30L));
        sessionAdapter.save(session);

        var foundSession = sessionAdapter.loadByAuthorizationCode(authorizationCode);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(session.getSessionId());
                assertThat(authSession.getAuthorizationCode()).isEqualTo(authorizationCode);
            });
    }

    @Test
    @DisplayName("Verify session gets not found by authorization code and throws exception")
    void test007() {
        var authorizationCode = TestUtils.generateAuthorizationCode();
        assertThatThrownBy(() -> sessionAdapter.loadByAuthorizationCode(authorizationCode))
            .isInstanceOf(SessionNotFoundException.class);
    }

    @Test
    @DisplayName("Verify session gets load by access token ID")
    void test008() {
        var accessTokenID = TestUtils.generateAccessToken();
        var session = (AuthSession) sessionAdapter.init();
        session.addGeneratedTokenProperties(new SeedCredential("value", "ref", "sub", Instant.now()), accessTokenID);
        sessionAdapter.save(session);

        var foundSession = sessionAdapter.loadByAccessTokenID(accessTokenID);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(session.getSessionId());
                assertThat(authSession.getAccessTokenID()).isEqualTo(accessTokenID);
            });
    }

    @Test
    @DisplayName("Verify session gets not found by access token ID and throws exception")
    void test009() {
        var accessTokenID = TestUtils.generateAccessToken();
        assertThatThrownBy(() -> sessionAdapter.loadByAccessTokenID(accessTokenID))
            .isInstanceOf(SessionNotFoundException.class);
    }

    @Test
    @DisplayName("Verify session gets load by seed credential ref")
    void test010() {
        var seedCredentialRef = UUID.randomUUID().toString();
        var session = (AuthSession) sessionAdapter.init();
        SeedCredential seedCredential = new SeedCredential("value", seedCredentialRef, "sub", Instant.now());
        session.addGeneratedTokenProperties(seedCredential, null);
        sessionAdapter.save(session);

        var foundSession = sessionAdapter.loadBySeedCredentialRef(seedCredentialRef);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(session.getSessionId());
                assertThat(authSession.getSeedCredentialRef()).isEqualTo(seedCredentialRef);
            });
    }

    @Test
    @DisplayName("Verify session gets not found by access token ID and throws exception")
    void test011() {
        var seedCredentialRef = UUID.randomUUID().toString();
        assertThatThrownBy(() -> sessionAdapter.loadBySeedCredentialRef(seedCredentialRef))
            .isInstanceOf(SessionNotFoundException.class);
    }

    @Test
    @DisplayName("Verify new session gets initialized and persisted by refresh token")
    void test012() throws ParseException {
        var refreshToken = TestRefreshTokenIssuer.buildRefreshToken();
        String refreshTokenID = refreshToken.getJWTClaimsSet().getJWTID();
        var session = (AuthSession) sessionAdapter.initByRefreshToken(refreshToken);
        assertThat(session)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId())
                    .isEqualTo(session.getSessionId());
                assertThat(authSession.getNextExpectedRequest())
                    .isEqualTo(Requests.TOKEN_REQUEST);
                assertThat(authSession.getRefreshTokenID()).isEqualTo(refreshTokenID);
                assertThat(sessionRepository.existsById(authSession.getSessionId()))
                    .isTrue();
            });
    }

    @Test
    @DisplayName("Verify session gets load by refresh token")
    void test013() throws ParseException {
        var refreshToken = TestRefreshTokenIssuer.buildRefreshToken();
        String refreshTokenID = refreshToken.getJWTClaimsSet().getJWTID();
        var initSession = (AuthSession) sessionAdapter.initByRefreshToken(refreshToken);

        var foundSession = sessionAdapter.loadByRefreshToken(refreshToken);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(initSession.getSessionId());
                assertThat(authSession.getNextExpectedRequest()).isEqualTo(Requests.TOKEN_REQUEST);
                assertThat(authSession.getRefreshTokenID()).isEqualTo(refreshTokenID);
            });
    }

    @Test
    @DisplayName("Verify session gets not found by refresh token and throws exception")
    void test014() {
        var refreshToken = TestRefreshTokenIssuer.buildRefreshToken();
        assertThatThrownBy(() -> sessionAdapter.loadByRefreshToken(refreshToken))
            .isInstanceOf(SessionNotFoundException.class);
    }

    @Test
    @DisplayName("Verify session resists all fields")
    void test015() {
        var initSession = (AuthSession) sessionAdapter.init();
        String seedCredentialRef = UUID.randomUUID().toString();
        Instant nowPlus60Seconds = Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MICROS);
        AuthSession originalAuthSession = new AuthSession(
            initSession.getSessionId(),
            TestUtils.generateAccessToken(),
            TestUtils.generateAuthorizationCode(),
            nowPlus60Seconds,
            URI.create("http://bdr.de/pidp/dummy-status-list"),
            10,
            ClientIds.validClientIdForSelfSigned().toString(),
            "CodeChallenge",
            "CodeChallengeMethod",
            RandomUtil.randomString(),
            nowPlus60Seconds,
            "SeedCredentialData",
            seedCredentialRef,
            "SeedCredentialSub",
            nowPlus60Seconds,
            TestUtils.generateIssuerState(),
            TestUtils.generateRequestUri(),
            "RefreshTokenID",
            TestUtils.generateRequestUri(),
            nowPlus60Seconds,
            "Scope",
            "State",
            Requests.CREDENTIAL_REQUEST
        );

        sessionAdapter.save(originalAuthSession);

        var foundSession = sessionAdapter.loadBySeedCredentialRef(seedCredentialRef);
        assertThat(foundSession)
            .isInstanceOfSatisfying(AuthSession.class, authSession -> {
                assertThat(authSession.getSessionId()).isEqualTo(originalAuthSession.getSessionId());
                assertThat(authSession.getAccessTokenID()).isEqualTo(originalAuthSession.getAccessTokenID());
                assertThat(authSession.getAuthorizationCode()).isEqualTo(originalAuthSession.getAuthorizationCode());
                assertThat(authSession.getAuthorizationCodeExpirationTime()).isEqualTo(originalAuthSession.getAuthorizationCodeExpirationTime());
                assertThat(authSession.getClientId()).isEqualTo(originalAuthSession.getClientId());
                assertThat(authSession.getClientAttestationStatusListRefURI()).isEqualTo(originalAuthSession.getClientAttestationStatusListRefURI());
                assertThat(authSession.getClientAttestationStatusListRefIndex()).isEqualTo(originalAuthSession.getClientAttestationStatusListRefIndex());
                assertThat(authSession.getCodeChallenge()).isEqualTo(originalAuthSession.getCodeChallenge());
                assertThat(authSession.getCodeChallengeMethod()).isEqualTo(originalAuthSession.getCodeChallengeMethod());
                assertThat(authSession.getDpopNonce()).isEqualTo(originalAuthSession.getDpopNonce());
                assertThat(authSession.getDpopNonceExpirationTime()).isEqualTo(originalAuthSession.getDpopNonceExpirationTime());
                assertThat(authSession.getSeedCredentialData()).isEqualTo(originalAuthSession.getSeedCredentialData());
                assertThat(authSession.getSeedCredentialRef()).isEqualTo(originalAuthSession.getSeedCredentialRef());
                assertThat(authSession.getSeedCredentialSub()).isEqualTo(originalAuthSession.getSeedCredentialSub());
                assertThat(authSession.getSeedCredentialExpirationTime()).isEqualTo(originalAuthSession.getSeedCredentialExpirationTime());
                assertThat(authSession.getIssuerState()).isEqualTo(originalAuthSession.getIssuerState());
                assertThat(authSession.getRedirectUri()).isEqualTo(originalAuthSession.getRedirectUri());
                assertThat(authSession.getRefreshTokenID()).isEqualTo(originalAuthSession.getRefreshTokenID());
                assertThat(authSession.getRequestUri()).isEqualTo(originalAuthSession.getRequestUri());
                assertThat(authSession.getRequestUriExpirationTime()).isEqualTo(originalAuthSession.getRequestUriExpirationTime());
                assertThat(authSession.getScope()).isEqualTo(originalAuthSession.getScope());
                assertThat(authSession.getState()).isEqualTo(originalAuthSession.getState());
                assertThat(authSession.getNextExpectedRequest()).isEqualTo(originalAuthSession.getNextExpectedRequest());
            });
    }

}
