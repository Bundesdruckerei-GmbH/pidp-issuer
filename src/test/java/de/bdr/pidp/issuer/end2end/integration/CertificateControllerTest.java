/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.integration;


import de.bdr.pidp.issuer.testdata.TestConfig;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.nullValue;

class CertificateControllerTest extends RestAssuredWebTest {

    @Test
    void getCertificates() {
        var rootCaCrt = given()
            .baseUri(TestConfig.pidiBaseUrl())
            .when()
            .get("/certificates/root-ca.crt")
            .then()
            .statusCode(HttpStatus.OK.value())
            .contentType(MediaType.TEXT_PLAIN_VALUE)
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())
            .extract().body().asString();
        var accessCrt = given()
            .baseUri(TestConfig.pidiBaseUrl())
            .when()
            .get("/certificates/access.crt")
            .then()
            .statusCode(HttpStatus.OK.value())
            .contentType(MediaType.TEXT_PLAIN_VALUE)
            .header(HttpHeaders.CACHE_CONTROL, nullValue())
            .header(HttpHeaders.PRAGMA, nullValue())
            .extract().body().asString();

        assertThat(rootCaCrt)
            .startsWith("-----BEGIN CERTIFICATE-----")
            .containsPattern("-----END CERTIFICATE-----\\n*$");

        assertThat(accessCrt)
            .startsWith("-----BEGIN CERTIFICATE-----")
            .containsPattern("-----END CERTIFICATE-----\\n*$");
    }
}
