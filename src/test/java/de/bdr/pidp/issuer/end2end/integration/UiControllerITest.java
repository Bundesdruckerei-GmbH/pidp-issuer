/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.integration;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static io.restassured.module.webtestclient.RestAssuredWebTestClient.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;

class UiControllerITest extends RestAssuredWebTest {
    @Autowired
    private AuthorizationConfiguration pidiConfiguration;

    @Test
    @DisplayName("Verify the index page exist")
    void test001() {
        given()
                .when()
                .get("/")
                .then()
                .assertThat()
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
        ;
    }

    @Test
    @DisplayName("Verify the issuance-flow page exist and returned the correct credential_issuer url")
    void test003() {
        given()
                .when()
                .get("/issuance-flow")
                .then()
                .assertThat()
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
                .body(containsString(URLEncoder.encode("\"credential_issuer\":\"" + pidiConfiguration.getBaseUrl() + "\"", StandardCharsets.UTF_8)))
                .body(containsString(URLEncoder.encode("\"credential_configuration_ids\":[\"pid-sd-jwt\"]", StandardCharsets.UTF_8)))
                .body(containsString(URLEncoder.encode("\"credential_configuration_ids\":[\"pid-mso-mdoc\"]", StandardCharsets.UTF_8)))
        ;
    }

    @Test
    @DisplayName("Verify the privacy page exist")
    void test004() {
        given()
                .when()
                .get("/privacy-terms")
                .then()
                .assertThat()

                // disabled for PIDP-4359 Remove privacy terms
                .statusCode(is(404))
                /*
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
                */
        ;
    }

    @Test
    @DisplayName("Verify the releases page exist")
    void test005() {
        given()
                .when()
                .get("/releases")
                .then()
                .assertThat()
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
        ;
    }

    @Test
    @DisplayName("Verify the license page exist")
    void test006() {
        given()
                .when()
                .get("/license")
                .then()
                .assertThat()
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
        ;
    }

    @Test
    @DisplayName("Verify the SD-JWT page exist")
    void test007() {
        given()
                .when()
                .get("/sdjwt")
                .then()
                .assertThat()
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
        ;
    }

    @Test
    @DisplayName("Verify the MSO-MDOC page exist")
    void test008() {
        given()
                .when()
                .get("/msomdoc")
                .then()
                .assertThat()
                .header(HttpHeaders.CACHE_CONTROL, nullValue())
                .header(HttpHeaders.PRAGMA, nullValue())
                .statusCode(is(200))
        ;
    }
}
