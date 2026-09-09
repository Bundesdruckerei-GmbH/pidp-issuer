/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.integration;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.out.persistence.AuthSessionEntity;
import de.bdr.pidp.issuer.authorization.out.persistence.AuthSessionRepository;
import de.bdr.pidp.issuer.authorization.port.out.ChallengePortOut;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.issuance.openid4vci.out.persistence.CNonceAdapter;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

class HousekeepingTest extends RestAssuredWebTest {

    private final Instant expired = Instant.now().minus(Duration.ofDays(1)).truncatedTo(ChronoUnit.MICROS);
    private final Instant valid = Instant.now().plus(Duration.ofDays(1)).truncatedTo(ChronoUnit.MICROS);
    private final List<Long> sessionIds = new ArrayList<>();

    @Autowired
    private AuthSessionRepository sessionRepository;

    @Autowired
    private ChallengePortOut challengePortOut;

    @Autowired
    private CNonceAdapter cNonceAdapter;

    @LocalManagementPort
    private int port;

    @AfterEach
    void tearDown() {
        sessionRepository.deleteAllById(sessionIds);
        sessionIds.clear();
    }

    @DisplayName("Cleanup expired session on authorization housekeeping")
    @Test
    void test001() {
        createSession(expired);

        given()
                .when()
                .port(port)
                .contentType(ContentType.JSON)
                .post("/actuator/housekeeping/authorization")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());

        checkSessionEmpty();
    }

    @DisplayName("Skip valid session on authorization housekeeping")
    @Test
    void test002() {
        createSession(valid);

        given()
                .when()
                .port(port)
                .contentType(ContentType.JSON)
                .post("/actuator/housekeeping/authorization")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());

        checkSessionPresent();
    }

    @DisplayName("Cleanup expired challenge on authorization housekeeping")
    @Test
    void test003() {
        var challenge = createChallenge(expired);

        given()
                .when()
                .port(port)
                .contentType(ContentType.JSON)
                .post("/actuator/housekeeping/authorization")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());

        checkChallengeEmpty(challenge);
    }

    @DisplayName("Skip valid challenge on authorization housekeeping")
    @Test
    void test004() {
        var challenge = createChallenge(valid);

        given()
                .when()
                .port(port)
                .contentType(ContentType.JSON)
                .post("/actuator/housekeeping/authorization")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());

        checkChallengePresent(challenge);
    }

    // IssuanceHouseKeeping for cNonce

    @DisplayName("Skip valid cNonce on Issuance housekeeping")
    @Test
    void test005() {
        Nonce cNonce = createCNonce(valid);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/issuance")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkCNoncePresent(cNonce);
    }

    @DisplayName("Cleanup expired cNonce on issuance housekeeping")
    @Test
    void test006() {
        Nonce cNonce = createCNonce(expired);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/issuance")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkCNonceEmpty(cNonce);
    }

    void createSession(Instant expires) {
        var session = new AuthSessionEntity();
        session.setExpires(expires);
        session.setNextExpectedRequest(Requests.AUTHORIZATION_REQUEST);
        var entity = sessionRepository.save(session);
        sessionIds.add(entity.getSessionId());
        checkSessionPresent();
    }

    void checkSessionEmpty() {
        assertThat(sessionRepository.findAllById(sessionIds)).isEmpty();
    }

    void checkSessionPresent() {
        assertThat(sessionRepository.findAllById(sessionIds)).hasSize(1);
    }

    Nonce createChallenge(Instant expiresTime) {
        Nonce nonce = new Nonce(RandomUtil.randomString(), expiresTime);
        challengePortOut.createAndSave(nonce);
        return nonce;
    }

    void checkChallengeEmpty(Nonce challenge) {
        assertThat(challengePortOut.findAndDeleteByChallenge(challenge.nonce())).isEmpty();
    }

    void checkChallengePresent(Nonce challenge) {
        assertThat(challengePortOut.findAndDeleteByChallenge(challenge.nonce())).isPresent()
            .get().isEqualTo(challenge);
    }

    Nonce createCNonce(Instant expiresTime) {
        Nonce nonce = new Nonce(RandomUtil.randomString(), expiresTime);
        cNonceAdapter.createAndSave(nonce);
        return nonce;
    }

    void checkCNonceEmpty(Nonce nonce) {
        assertThat(cNonceAdapter.findAndDeleteByNonce(nonce)).isEmpty();
    }

    void checkCNoncePresent(Nonce nonce) {
        assertThat(cNonceAdapter.findAndDeleteByNonce(nonce)).isPresent()
            .get().isEqualTo(nonce);
    }

}
