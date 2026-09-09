/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

class ChallengeControllerITest extends RestAssuredWebTest {

    @LocalServerPort
    private int port;

    @Test
    void shouldFetchChallenge() {
        given()
            .port(port)
        .when()
            .post("/challenge")
        .then()
            .assertThat()
            .statusCode(HttpStatus.OK.value())
            .header(HttpHeaders.CACHE_CONTROL, is("no-store"))
            .body("attestation_challenge", not(emptyString()));
    }
}
