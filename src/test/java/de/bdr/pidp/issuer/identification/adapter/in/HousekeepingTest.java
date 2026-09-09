/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.in;

import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.identification.core.model.AuthenticationState;
import de.bdr.pidp.issuer.identification.out.persistence.AuthenticationEntity;
import de.bdr.pidp.issuer.identification.out.persistence.AuthenticationRepository;
import de.bdr.pidp.issuer.identification.out.persistence.EIDResultEntity;
import de.bdr.pidp.issuer.identification.out.persistence.EIDResultRepository;
import de.bdr.pidp.issuer.testdata.TestUtils;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

class HousekeepingTest extends RestAssuredWebTest {

    private final Instant expired = Instant.now().minus(Duration.ofDays(1));
    private final Instant valid = Instant.now().plus(Duration.ofDays(1));
    private final List<Long> authenticationIds = new ArrayList<>();
    private final List<String> externalIds = new ArrayList<>();


    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private EIDResultRepository eidResultRepository;

    @LocalManagementPort
    private int port;

    @AfterEach
    void tearDown() {
        authenticationRepository.deleteAllById(authenticationIds);
        authenticationIds.clear();

        eidResultRepository.deleteAllById(externalIds);
        externalIds.clear();
    }

    @DisplayName("Cleanup expired authentication on identification housekeeping")
    @ParameterizedTest
    @EnumSource(AuthenticationState.class)
    void test001(AuthenticationState state) {
        createExpiredAuthentication(state, expired);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/identification")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkAuthenticationEmpty();
    }

    @DisplayName("Skip valid authentication on identification housekeeping")
    @ParameterizedTest
    @EnumSource(value = AuthenticationState.class, names = {"TERMINATED", "TIMEOUT"}, mode = EnumSource.Mode.EXCLUDE)
    void test002(AuthenticationState state) {
        createExpiredAuthentication(state, valid);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/identification")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkAuthenticationPresent();
    }

    @DisplayName("Cleanup authentication in final state on identification housekeeping")
    @ParameterizedTest
    @EnumSource(value = AuthenticationState.class, names = {"TERMINATED", "TIMEOUT"}, mode = EnumSource.Mode.INCLUDE)
    void test003(AuthenticationState state) {
        createExpiredAuthentication(state, valid);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/identification")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkAuthenticationEmpty();
    }

    @DisplayName("Cleanup expired eID results on identification housekeeping")
    @Test
    void test004() {
        createEIDResult(expired);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/identification")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkEIDResultsEmpty();
    }

    @DisplayName("Skip valid eID results on identification housekeeping")
    @Test
    void test005() {
        createEIDResult(valid);

        given()
            .when()
            .port(port)
            .contentType(ContentType.JSON)
            .post("/actuator/housekeeping/identification")
            .then()
            .assertThat()
            .statusCode(HttpStatus.NO_CONTENT.value());

        checkEIDResultsPresent();
    }

    void createExpiredAuthentication(AuthenticationState state, Instant expires) {
        var auth = new AuthenticationEntity();
        auth.setAuthenticationState(state);
        auth.setSessionId(RandomUtil.randomString());
        auth.setTokenId(RandomUtil.randomString());
        auth.setCreated(Instant.now().minus(Duration.ofDays(14)));
        auth.setValidUntil(expires);
        var entity = authenticationRepository.save(auth);
        authenticationIds.add(entity.getId());
        checkAuthenticationPresent();
    }

    void checkAuthenticationEmpty() {
        assertThat(authenticationRepository.findAllById(authenticationIds)).isEmpty();
    }

    void checkAuthenticationPresent() {
        assertThat(authenticationRepository.findAllById(authenticationIds)).hasSize(1);
    }

    void createEIDResult(Instant expires) {
        var result = new EIDResultEntity();
        result.setExternalId(TestUtils.generateIssuerState());
        result.setSeedCredential("~~serialized~~");
        result.setExpires(expires);

        var entity = eidResultRepository.save(result);
        externalIds.add(entity.getExternalId());
        checkEIDResultsPresent();
    }

    void checkEIDResultsEmpty() {
        assertThat(eidResultRepository.findAllById(externalIds)).isEmpty();
    }

    void checkEIDResultsPresent() {
        assertThat(eidResultRepository.findAllById(externalIds)).hasSize(1);
    }
}
